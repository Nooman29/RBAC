"""
Prepares accounts for demonstrating live (mid-session) detection in the browser.

    docker compose exec backend python -m scripts.setup_live_demo --email-base you@gmail.com
    docker compose exec backend python -m scripts.setup_live_demo --email-base you@gmail.com --password "Demo#2026"
    docker compose exec backend python -m scripts.setup_live_demo --remove --yes

Every run removes the earlier 'live_' accounts (with all their sessions and alerts) and creates them
again, so each rehearsal starts from the same state. Real accounts are never touched.

Sign-in is the password and then the one-time code, emailed to a plus-address of --email-base
(you+live_staff@gmail.com), so all codes reach your own inbox.

Accounts and what each one demonstrates (see docs/LIVE_DETECTION_DEMO.md):
  live_admin      Administrator   the presenter's dashboard: watches the In progress panel
  live_staff      Standard User   R1: types /users three times (pages the menu hides)
  live_operator   Administrator   R4 + R2 + R5: has a confirmed threat for "many writes" and a quiet
                                  read-only routine, then deletes the five live_victim accounts
  live_night      Standard User   R3: has only ever worked night shifts (22:00-01:00 local)
  live_victim_1-5 Standard User   throwaway accounts for live_operator to delete

History is placed in local business time (settings.BUSINESS_TIMEZONE) at the address the browser
signs in from (--ip; by default the address of the most recent real sign-in), so the only unusual
thing during the demo is what the presenter does.
"""

import argparse
import getpass
import random
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.business_time import local_now, to_utc
from app.core.security import hash_password
from app.db.database import SessionLocal
from app.models.anomaly import AnomalyAlert
from app.models.biometric import BiometricEnrollment
from app.models.live_alert import DeniedAttempt, LiveAlert
from app.models.notification import Notification
from app.models.otp import OTPCode
from app.models.role import Role
from app.models.session import AccessLog, UserSession
from app.models.user import User
from scripts.seed_synthetic_data import NEW_SYNTHETIC_IP_PATTERNS, delete_sessions

PREFIX = "live_"
ACCOUNTS = [
    {"username": "live_admin", "role": "Administrator", "department": "IT"},
    {"username": "live_staff", "role": "Standard User", "department": "Finance"},
    {"username": "live_operator", "role": "Administrator", "department": "Operations"},
    {"username": "live_night", "role": "Standard User", "department": "Operations"},
] + [{"username": f"live_victim_{i}", "role": "Standard User", "department": "HR"} for i in range(1, 6)]


def plus_address(base: str, tag: str) -> str:
    local, _, domain = base.partition("@")
    return f"{local}+{tag}@{domain}"


def live_users(db):
    return db.query(User).filter(User.username.startswith(PREFIX, autoescape=True)).all()


def remove(db) -> int:
    users = live_users(db)
    ids = [u.user_id for u in users]
    for user in users:
        sessions = [s for (s,) in db.query(UserSession.session_id).filter(UserSession.user_id == user.user_id).all()]
        delete_sessions(db, sessions)
    if ids:
        db.query(DeniedAttempt).filter(DeniedAttempt.user_id.in_(ids)).delete(synchronize_session=False)
        db.query(LiveAlert).filter(LiveAlert.resolved_by.in_(ids)).update({"resolved_by": None}, synchronize_session=False)
        db.query(AnomalyAlert).filter(AnomalyAlert.reviewed_by.in_(ids)).update({"reviewed_by": None}, synchronize_session=False)
        db.query(Notification).filter(Notification.user_id.in_(ids)).delete(synchronize_session=False)
        db.query(OTPCode).filter(OTPCode.user_id.in_(ids)).delete(synchronize_session=False)
        db.query(BiometricEnrollment).filter(BiometricEnrollment.user_id.in_(ids)).delete(synchronize_session=False)
    for user in users:
        db.delete(user)
    db.commit()
    return len(users)


def default_ip(db) -> str:
    """Address of the most recent real sign-in (what the backend will record for the demo browser)."""
    query = db.query(UserSession.access_location).filter(
        UserSession.simulated_scenario.is_(None), UserSession.access_location.isnot(None)
    )
    for pattern in NEW_SYNTHETIC_IP_PATTERNS:
        query = query.filter(~UserSession.access_location.like(pattern))
    row = query.order_by(UserSession.login_time.desc()).first()
    return row[0] if row else "127.0.0.1"


def add_history(db, user, days_ago, hour, minutes, ip, actions, resource="dashboard"):
    """A closed session at a LOCAL clock time, with one access log per action."""
    login = to_utc((local_now() - timedelta(days=days_ago)).replace(
        hour=hour, minute=random.randint(0, 20), second=0, microsecond=0))
    session = UserSession(
        user_id=user.user_id, login_time=login, logout_time=login + timedelta(minutes=minutes),
        session_duration=minutes * 60.0, access_location=ip,
    )
    db.add(session)
    db.flush()
    for i, action in enumerate(actions):
        db.add(AccessLog(session_id=session.session_id, resource_name=resource, action_performed=action,
                         access_timestamp=login + timedelta(minutes=i * minutes / max(1, len(actions)))))
    return session


def weekdays_back(count):
    """The last `count` weekdays before today (days-ago offsets), oldest last."""
    today = local_now()
    offsets, d = [], 1
    while len(offsets) < count:
        if (today - timedelta(days=d)).weekday() < 5:
            offsets.append(d)
        d += 1
    return offsets


def create(db, email_base, password, ip) -> dict:
    roles = {r.role_name: r for r in db.query(Role).all()}
    missing = {a["role"] for a in ACCOUNTS} - set(roles)
    if missing:
        raise SystemExit(f"Roles missing ({', '.join(sorted(missing))}). Run: python -m scripts.seed_roles_and_permissions")

    users = {}
    for spec in ACCOUNTS:
        user = User(
            username=spec["username"],
            email=plus_address(email_base, spec["username"]),
            password=hash_password(password),
            department=spec["department"],
            password_set=True,
            biometric_choice_made=True,      # straight to password + emailed code
            is_biometric_enrolled=False,
        )
        user.roles.append(roles[spec["role"]])
        db.add(user)
        users[spec["username"]] = user
    db.commit()

    # live_operator: a quiet, read-only routine across the working day (8 sessions of ~4 reads,
    # 08:00-17:00 local, so a daytime demo is never an "unusual hour") ...
    for days_ago, hour in zip(weekdays_back(8), [8, 9, 10, 11, 13, 14, 15, 16]):
        add_history(db, users["live_operator"], days_ago, hour=hour, minutes=random.randint(15, 25), ip=ip,
                    actions=["read"] * random.randint(3, 5))
    # ... and one earlier session an administrator confirmed as a threat: a burst of writes.
    threat = add_history(db, users["live_operator"], days_ago=weekdays_back(10)[-1], hour=10, minutes=20, ip=ip,
                         actions=["write"] * 8 + ["read"] * 2, resource="user")
    db.add(AnomalyAlert(
        session_id=threat.session_id, anomaly_score=0.62, is_anomaly=True, detection_reason="ml_model",
        pattern_signature="highwrite", review_verdict="confirmed_threat", reviewed=True,
        reviewed_by=users["live_admin"].user_id,
        notes="Demo precedent: bulk changes to user accounts, confirmed as a threat.",
    ))

    # live_night: night shifts only (22:00 local, three hours each).
    for days_ago in weekdays_back(6):
        add_history(db, users["live_night"], days_ago, hour=22, minutes=180, ip=ip,
                    actions=["read"] * random.randint(3, 6))

    db.commit()
    return users


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--email-base", help="your email; codes go to plus-addresses of it")
    parser.add_argument("--password", help="password for every live_ account (prompted if omitted)")
    parser.add_argument("--ip", help="address the demo browser signs in from (default: latest real sign-in)")
    parser.add_argument("--remove", action="store_true", help="only remove the live_ accounts")
    parser.add_argument("--yes", action="store_true", help="confirm --remove")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    random.seed(args.seed)

    db = SessionLocal()
    try:
        if args.remove:
            if not args.yes:
                print(f"Would remove: {', '.join(u.username for u in live_users(db)) or '-'}. Add --yes.")
                return
            print(f"Removed {remove(db)} live_ account(s).")
            return

        if not args.email_base or "@" not in args.email_base:
            raise SystemExit("--email-base you@example.com is required (sign-in codes are emailed).")
        password = args.password or getpass.getpass("Password for the live_ accounts: ")
        ip = args.ip or default_ip(db)

        removed = remove(db)
        if removed:
            print(f"Removed {removed} earlier live_ account(s).")
        create(db, args.email_base, password, ip)
        print(f"Created {len(ACCOUNTS)} live_ accounts. History recorded at address {ip}.")
        print()
        print("  live_admin      watch Alerts > In progress")
        print("  live_staff      R1: type /users in the address bar three times")
        print("  live_operator   R4 on the first delete, R2 after five deletes (live_victim_1-5), R5 after ~10 actions")
        print("  live_night      R3: sign in during the day and open any page")
        print()
        print("Full script: docs/LIVE_DETECTION_DEMO.md")
    finally:
        db.close()


if __name__ == "__main__":
    main()
