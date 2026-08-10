"""
Seeds synthetic session + access_log history so the Isolation Forest has
enough data to train on before real usage accumulates.

Run manually from backend/:
    python -m scripts.seed_synthetic_data

Behavior:
    For every existing user in the `users` table, generates ~40-70 sessions
    spread over the last 90 days with normal, business-hours behavior
    (mostly reads, familiar IPs), plus injects a small share of deliberately
    anomalous sessions per user (off-hours, unfamiliar IP, heavier
    write/delete volume, longer duration) so the model has real variance
    to learn from.

    This is clearly synthetic bootstrap data — there's no schema column to
    flag it as such (keeps the schema matching the proposal's ERD exactly),
    so this script prints the session_id range it creates. Prune those rows
    once enough real session history exists, then retrain.
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal
from app.models.session import UserSession, AccessLog
from app.models.user import User

RESOURCES = ["reports", "billing", "customer_records", "admin_panel", "hr_files", "inventory"]
ACTIONS = ["read", "write", "delete"]
IPS_NORMAL = [f"10.0.0.{i}" for i in range(2, 20)]
IPS_UNUSUAL = [f"185.220.101.{i}" for i in range(1, 10)]  # unfamiliar / exit-node-ish range

SESSIONS_PER_USER = (40, 70)
DAYS_BACK = 90
ANOMALOUS_SESSION_RATE = 0.06  # ~6% of a user's sessions seeded as anomalous


def _random_dt(days_back: int, hour: int) -> datetime:
    day_offset = random.randint(0, days_back)
    minute = random.randint(0, 59)
    base = datetime.utcnow() - timedelta(days=day_offset)
    return base.replace(hour=hour, minute=minute, second=0, microsecond=0)


def make_session(db, user_id: int, anomalous: bool) -> UserSession:
    if anomalous:
        hour = random.choice([1, 2, 3, 4, 22, 23])
        login_time = _random_dt(DAYS_BACK, hour)
        duration = random.uniform(600, 5400)          # long sessions
        ip = random.choice(IPS_UNUSUAL)
        n_events = random.randint(15, 40)
        action_weights = [0.3, 0.4, 0.3]                # heavier write/delete
    else:
        hour = random.choices(
            population=list(range(24)),
            weights=[1 if (h < 7 or h > 19) else 6 for h in range(24)],
        )[0]
        login_time = _random_dt(DAYS_BACK, hour)
        duration = random.uniform(120, 3600)
        ip = random.choice(IPS_NORMAL)
        n_events = random.randint(1, 12)
        action_weights = [0.8, 0.18, 0.02]               # mostly reads

    session = UserSession(
        user_id=user_id,
        login_time=login_time,
        logout_time=login_time + timedelta(seconds=duration),
        session_duration=duration,
        access_location=ip,
    )
    db.add(session)
    db.flush()  # get session_id without a full commit

    for _ in range(n_events):
        resource = random.choice(RESOURCES)
        action = random.choices(ACTIONS, weights=action_weights)[0]
        ts = login_time + timedelta(seconds=random.uniform(0, max(duration, 1)))
        db.add(AccessLog(
            session_id=session.session_id,
            resource_name=resource,
            action_performed=action,
            access_timestamp=ts,
        ))

    return session


def main():
    db = SessionLocal()
    try:
        users = db.query(User).all()
        if not users:
            print("No users found — create at least one user before seeding.")
            return

        first_id, last_id = None, None
        for user in users:
            n_sessions = random.randint(*SESSIONS_PER_USER)
            for _ in range(n_sessions):
                anomalous = random.random() < ANOMALOUS_SESSION_RATE
                s = make_session(db, user.user_id, anomalous)
                if first_id is None:
                    first_id = s.session_id
                last_id = s.session_id

        db.commit()
        print(f"Seeded synthetic sessions for {len(users)} users.")
        print(f"Created session_id range: {first_id}-{last_id}")
        print("Next: python -m scripts.train_isolation_forest")
    finally:
        db.close()


if __name__ == "__main__":
    main()