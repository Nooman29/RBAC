"""
Creates demo users for the Digital School Feeding System demo.

    docker compose exec backend python -m scripts.create_demo_users --email-base you@gmail.com

Each demo user's email is a plus-address of --email-base (you+demo_teacher@gmail.com), so the one-time
codes sent at sign-in reach your own inbox (this works with Gmail and most providers that support
plus-addressing). The accounts are fully activated: no setup email and no Face ID enrolment, so signing in
is the password and then the emailed code.

Safe to re-run (existing users are skipped). Remove them again with:  --remove --yes
"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.security import hash_password
from app.db.database import SessionLocal
from app.models.biometric import BiometricEnrollment
from app.models.guardian import GuardianLink
from app.models.notification import Notification
from app.models.otp import OTPCode
from app.models.role import Role
from app.models.session import UserSession
from app.models.user import User
from scripts.seed_synthetic_data import delete_sessions

PREFIX = "demo_"
DEMO_USERS = [
    {"username": "demo_teacher", "role": "Teacher", "school_id": "SCH-1"},
    {"username": "demo_teacher_b", "role": "Teacher", "school_id": "SCH-2"},
    {"username": "demo_parent", "role": "Parent/Guardian", "students": ["STU-1001"]},
    {"username": "demo_finance", "role": "Finance Officer"},
]


def plus_address(base: str, tag: str) -> str:
    local, _, domain = base.partition("@")
    return f"{local}+{tag}@{domain}"


def demo_users(db):
    return db.query(User).filter(User.username.startswith(PREFIX, autoescape=True)).all()


def remove(db, confirmed: bool) -> None:
    users = demo_users(db)
    print(f"{len(users)} demo user(s): {', '.join(u.username for u in users) or '-'}")
    if not confirmed:
        print("Dry run. Add --yes to delete them and all their sessions.")
        return
    for user in users:
        ids = [s for (s,) in db.query(UserSession.session_id).filter(UserSession.user_id == user.user_id).all()]
        delete_sessions(db, ids)
        db.query(Notification).filter(Notification.user_id == user.user_id).delete(synchronize_session=False)
        db.query(OTPCode).filter(OTPCode.user_id == user.user_id).delete(synchronize_session=False)
        db.query(BiometricEnrollment).filter(BiometricEnrollment.user_id == user.user_id).delete(synchronize_session=False)
        db.delete(user)   # guardian links and interface events go with it (database cascade)
        db.commit()
    print("Removed.")


def create(db, email_base: str, password: str) -> None:
    for spec in DEMO_USERS:
        if db.query(User).filter(User.username == spec["username"]).first():
            print(f"{spec['username']}: already exists, skipped")
            continue
        role = db.query(Role).filter(Role.role_name == spec["role"]).first()
        if role is None:
            sys.exit(f"Role '{spec['role']}' not found. Run: python -m scripts.seed_roles_and_permissions")
        user = User(
            username=spec["username"],
            email=plus_address(email_base, spec["username"]),
            password=hash_password(password),
            password_set=True,
            is_biometric_enrolled=False,
            biometric_choice_made=True,     # skip first-time setup; sign-in uses the emailed code
            school_id=spec.get("school_id"),
        )
        user.roles = [role]
        db.add(user)
        db.commit()
        db.refresh(user)
        for student_id in spec.get("students", []):
            db.add(GuardianLink(guardian_user_id=user.user_id, external_student_id=student_id))
        db.commit()
        extra = f", school {spec['school_id']}" if spec.get("school_id") else ""
        extra += f", linked to {', '.join(spec['students'])}" if spec.get("students") else ""
        print(f"{spec['username']}: created ({spec['role']}{extra}) -> {user.email}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--email-base", help="your real address, e.g. you@gmail.com (codes arrive here)")
    parser.add_argument("--password", default=None, help="omit to be prompted (recommended)")
    parser.add_argument("--remove", action="store_true", help="delete the demo users (dry run unless --yes)")
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        if args.remove:
            remove(db, args.yes)
            return
        if not args.email_base or "@" not in args.email_base:
            sys.exit("Give --email-base with your real email address, e.g. --email-base you@gmail.com")
        password = args.password or getpass.getpass("Password for the demo users (min 8 characters): ")
        if len(password) < 8:
            sys.exit("Password must be at least 8 characters.")
        create(db, args.email_base, password)
    finally:
        db.close()


if __name__ == "__main__":
    main()