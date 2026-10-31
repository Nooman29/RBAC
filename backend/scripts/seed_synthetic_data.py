"""
Seeds realistic synthetic session history so the Isolation Forest has enough data to train on before
real usage accumulates.

    python -m scripts.seed_synthetic_data --create-users 8 --synthetic-users-only
    python -m scripts.seed_synthetic_data --reset-synthetic        # DRY RUN: shows what would be removed
    python -m scripts.seed_synthetic_data --reset-synthetic --yes --create-users 8 --synthetic-users-only
    python -m scripts.seed_synthetic_data --remove-synthetic-users --yes

What is generated:
  - Every user gets a routine: a typical start hour, activity level, session length and one or two
    stable IP addresses, so an unfamiliar address is genuinely rare, as it is for real users.
  - Hours and weekdays are LOCAL business time (settings.BUSINESS_TIMEZONE, Africa/Nairobi by
    default); sessions are stored in UTC like real logins, so a 09:00 start is saved as 06:00 UTC.
  - Normal sessions follow that routine on weekdays, touch the live system's resources (dashboard,
    user, role) and are mostly reads.
  - About 6% of sessions are "unusual": the routine plus a random mix of 1-3 unusual traits (night
    login, brand-new address, much higher volume, much longer, destructive actions, many resources,
    weekend). They are generic; they do not copy the attack simulator's scenarios.

There is no database column that marks synthetic data. Synthetic sessions are recognisable by their IP
ranges (10.77.* and 185.220.*; the earlier version of this script used 10.0.0.* and 185.220.101.*), and
demo users by the username prefix 'synth_'. Use --reset-synthetic to remove synthetic sessions.
"""

from __future__ import annotations

import argparse
import random
import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import or_

from app.core.business_time import local_now, to_utc
from app.core.constants import DEPARTMENTS
from app.core.security import hash_password
from app.db.database import SessionLocal
from app.models.anomaly import AnomalyAlert
from app.models.notification import Notification
from app.models.session import AccessLog, UserSession
from app.models.user import User
from app.services import live_detection_service

RESOURCES = ["dashboard", "user", "role"]
NORMAL_RESOURCE_WEIGHTS = [0.70, 0.20, 0.10]
ACTIONS = ["read", "write", "delete"]
NORMAL_ACTION_WEIGHTS = [0.80, 0.17, 0.03]

NORMAL_IP_PREFIX = "10.77"
UNUSUAL_IP_PREFIX = "185.220"
OLD_SYNTHETIC_IP_PATTERNS = ["10.0.0.%", "185.220.101.%"]
NEW_SYNTHETIC_IP_PATTERNS = [f"{NORMAL_IP_PREFIX}.%", f"{UNUSUAL_IP_PREFIX}.%"]
SYNTH_USER_PREFIX = "synth_"

SESSIONS_PER_USER = (40, 70)
DAYS_BACK = 90
ANOMALOUS_SESSION_RATE = 0.06
NORMAL_WEEKEND_RATE = 0.05
TRAITS = ["night", "new_ip", "volume", "long", "destructive", "wide", "weekend"]


# ---------------------------------------------------------------- generation

def random_day(weekend: bool) -> datetime:
    """A recent LOCAL calendar day (midnight), weekend or weekday as asked."""
    while True:
        base = local_now() - timedelta(days=random.randint(1, DAYS_BACK))
        if (base.weekday() >= 5) == weekend:
            return base.replace(hour=0, minute=0, second=0, microsecond=0)


def make_profile() -> dict:
    ips = {
        f"{NORMAL_IP_PREFIX}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        for _ in range(random.choice([1, 1, 2]))
    }
    return {
        "typical_hour": random.randint(8, 11),
        "typical_events": random.randint(3, 9),
        "typical_duration": random.uniform(600, 2400),
        "ips": sorted(ips),
    }


def normal_params(profile: dict) -> dict:
    if random.random() < 0.03:
        hour = random.choice([5, 6, 20, 21])           # an occasional early or late start
    else:
        hour = min(19, max(7, profile["typical_hour"] + random.randint(-1, 5)))
    ips = profile["ips"]
    ip = ips[0] if (len(ips) == 1 or random.random() < 0.85) else ips[1]
    return {
        "weekend": random.random() < NORMAL_WEEKEND_RATE,
        "hour": hour,
        "duration": profile["typical_duration"] * random.uniform(0.7, 1.3),
        "events": max(1, round(random.gauss(profile["typical_events"], 1.5))),
        "ip": ip,
        "action_weights": NORMAL_ACTION_WEIGHTS,
        "resource_weights": NORMAL_RESOURCE_WEIGHTS,
    }


def unseen_ip(used: set) -> str:
    while True:
        ip = f"{UNUSUAL_IP_PREFIX}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        if ip not in used:
            used.add(ip)
            return ip


def apply_trait(p: dict, trait: str, used_unusual_ips: set) -> dict:
    """Makes session parameters unusual in one way (one of TRAITS)."""
    if trait == "night":
        p["hour"] = random.choice([0, 1, 2, 3, 4, 22, 23])
    elif trait == "new_ip":
        p["ip"] = unseen_ip(used_unusual_ips)
    elif trait == "volume":
        p["events"] = int(max(p["events"], 6) * random.uniform(3, 6))
    elif trait == "long":
        p["duration"] *= random.uniform(2, 4)
    elif trait == "destructive":
        p["action_weights"] = [0.3, 0.4, 0.3]
    elif trait == "wide":
        p["resource_weights"] = [1 / 3, 1 / 3, 1 / 3]
    elif trait == "weekend":
        p["weekend"] = True
    return p


def anomalous_params(profile: dict, used_unusual_ips: set) -> dict:
    p = normal_params(profile)
    for trait in random.sample(TRAITS, k=random.choice([1, 2, 2, 3])):
        apply_trait(p, trait, used_unusual_ips)
    return p


def add_session(db, user_id: int, p: dict) -> UserSession:
    login = to_utc(random_day(p["weekend"]).replace(
        hour=p["hour"], minute=random.randint(0, 59), second=random.randint(0, 59)
    ))
    duration = max(60.0, float(p["duration"]))
    session = UserSession(
        user_id=user_id,
        login_time=login,
        logout_time=login + timedelta(seconds=duration),
        session_duration=duration,
        access_location=p["ip"],
        terminated=False,
    )
    db.add(session)
    db.flush()
    for _ in range(p["events"]):
        db.add(AccessLog(
            session_id=session.session_id,
            resource_name=random.choices(RESOURCES, weights=p["resource_weights"])[0],
            action_performed=random.choices(ACTIONS, weights=p["action_weights"])[0],
            access_timestamp=login + timedelta(seconds=random.uniform(0, duration)),
        ))
    return session


# ---------------------------------------------------------------- cleanup helpers

def delete_sessions(db, session_ids) -> None:
    for i in range(0, len(session_ids), 500):
        chunk = session_ids[i:i + 500]
        live_detection_service.delete_for_sessions(db, chunk)
        alert_ids = [a for (a,) in db.query(AnomalyAlert.alert_id).filter(AnomalyAlert.session_id.in_(chunk)).all()]
        if alert_ids:
            db.query(Notification).filter(Notification.alert_id.in_(alert_ids)).delete(synchronize_session=False)
            db.query(AnomalyAlert).filter(AnomalyAlert.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        db.query(AccessLog).filter(AccessLog.session_id.in_(chunk)).delete(synchronize_session=False)
        db.query(UserSession).filter(UserSession.session_id.in_(chunk)).delete(synchronize_session=False)
        db.commit()


def synthetic_session_ids(db):
    patterns = OLD_SYNTHETIC_IP_PATTERNS + NEW_SYNTHETIC_IP_PATTERNS
    return [
        sid for (sid,) in db.query(UserSession.session_id)
        .filter(
            UserSession.simulated_scenario.is_(None),
            or_(*[UserSession.access_location.like(p) for p in patterns]),
        )
        .all()
    ]


def synthetic_users(db):
    # autoescape: '_' is a wildcard in SQL LIKE, so without it 'synth_' would also match e.g. 'synthia'
    return db.query(User).filter(User.username.startswith(SYNTH_USER_PREFIX, autoescape=True)).all()


def create_demo_users(db, how_many: int):
    created, index = [], 1
    while len(created) < how_many:
        username = f"{SYNTH_USER_PREFIX}{index:02d}"
        index += 1
        if db.query(User).filter(User.username == username).first():
            continue
        user = User(
            username=username,
            email=f"{username}@example.com",
            department=random.choice(DEPARTMENTS),
            password=hash_password(secrets.token_urlsafe(24)),   # nobody knows it: these accounts cannot sign in
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        created.append(user)
    return created


# ---------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-users", type=int, default=0, help="create this many demo users (synth_01, ...)")
    parser.add_argument("--synthetic-users-only", action="store_true",
                        help="only seed the 'synth_' demo users, leaving real accounts' history untouched")
    parser.add_argument("--force", action="store_true",
                        help=f"seed users even if they already have {SESSIONS_PER_USER[0]}+ sessions")
    parser.add_argument("--reset-synthetic", action="store_true",
                        help="remove earlier synthetic sessions (dry run unless --yes is given)")
    parser.add_argument("--remove-synthetic-users", action="store_true",
                        help="delete the 'synth_' demo users and all their data (needs --yes)")
    parser.add_argument("--yes", action="store_true", help="confirm deletions")
    parser.add_argument("--seed", type=int, default=None, help="random seed, for repeatable data")
    args = parser.parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    db = SessionLocal()
    try:
        if args.remove_synthetic_users:
            users = synthetic_users(db)
            print(f"{len(users)} demo user(s): {', '.join(u.username for u in users) or '-'}")
            if not args.yes:
                print("Dry run. Add --yes to delete them and all their sessions.")
                return
            for user in users:
                ids = [s for (s,) in db.query(UserSession.session_id).filter(UserSession.user_id == user.user_id).all()]
                delete_sessions(db, ids)
                db.query(Notification).filter(Notification.user_id == user.user_id).delete(synchronize_session=False)
                db.delete(user)
                db.commit()
            print("Removed.")
            return

        if args.reset_synthetic:
            ids = synthetic_session_ids(db)
            print("Synthetic sessions found, by address range:")
            for pattern in OLD_SYNTHETIC_IP_PATTERNS + NEW_SYNTHETIC_IP_PATTERNS:
                count = db.query(UserSession).filter(
                    UserSession.simulated_scenario.is_(None), UserSession.access_location.like(pattern)
                ).count()
                print(f"  {pattern:<16} {count}")
            print(f"  total            {len(ids)}")
            if not args.yes:
                print("Dry run. Check that none of these addresses belong to real users, then add --yes.")
                return
            delete_sessions(db, ids)
            print(f"Deleted {len(ids)} synthetic session(s).")

        if args.create_users:
            created = create_demo_users(db, args.create_users)
            print(f"Created demo users: {', '.join(u.username for u in created)}")

        users = synthetic_users(db) if args.synthetic_users_only else db.query(User).all()
        if not users:
            print("No users to seed. Create users first, or use --create-users N.")
            return

        seeded_users, total, unusual = 0, 0, 0
        for user in users:
            existing = db.query(UserSession).filter(
                UserSession.user_id == user.user_id, UserSession.simulated_scenario.is_(None)
            ).count()
            if existing >= SESSIONS_PER_USER[0] and not args.force:
                continue
            profile = make_profile()
            used_unusual_ips: set = set()
            for _ in range(random.randint(*SESSIONS_PER_USER)):
                is_unusual = random.random() < ANOMALOUS_SESSION_RATE
                params = anomalous_params(profile, used_unusual_ips) if is_unusual else normal_params(profile)
                add_session(db, user.user_id, params)
                total += 1
                unusual += int(is_unusual)
            db.commit()
            seeded_users += 1

        print(f"Seeded {total} sessions for {seeded_users} user(s) ({unusual} deliberately unusual).")
        print("Next: python -m scripts.train_isolation_forest   (then restart the backend)")
    finally:
        db.close()


if __name__ == "__main__":
    main()
    