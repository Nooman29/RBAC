"""
Create the first Administrator account (needed on a fresh install, where no users exist).

    python -m scripts.seed_roles_and_permissions     # roles must exist first
    python -m scripts.create_admin --username admin --email you@example.com

The password is prompted for. On first login the account goes through the normal
first-time setup (Face ID enrolment or email-code fallback).
Refuses to create a user that already exists, so it is safe to re-run.
"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.constants import DEPARTMENTS
from app.core.security import hash_password
from app.db.database import SessionLocal
from app.models.role import Role
from app.models.user import User


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--department", default="IT", help=f"one of: {', '.join(DEPARTMENTS)}")
    parser.add_argument("--password", default=None, help="omit to be prompted (recommended)")
    args = parser.parse_args()

    if args.department not in DEPARTMENTS:
        sys.exit(f"Department must be one of: {', '.join(DEPARTMENTS)}")

    password = args.password
    if password is None:
        password = getpass.getpass("Password (min 8 characters): ")
        if password != getpass.getpass("Confirm password: "):
            sys.exit("Passwords do not match.")
    if len(password) < 8:
        sys.exit("Password must be at least 8 characters.")

    db = SessionLocal()
    try:
        role = db.query(Role).filter(Role.role_name == "Administrator").first()
        if role is None:
            sys.exit("Administrator role not found. Run: python -m scripts.seed_roles_and_permissions")

        if db.query(User).filter((User.username == args.username) | (User.email == args.email)).first():
            sys.exit("A user with that username or email already exists.")

        user = User(
            username=args.username,
            email=args.email,
            department=args.department,
            password=hash_password(password),
            password_set=True,
            is_biometric_enrolled=False,
            biometric_choice_made=False,   # forces first-time setup at first login
        )
        user.roles = [role]
        db.add(user)
        db.commit()
        print(f"Administrator '{args.username}' created. Log in, then choose Face ID or email-code verification.")
    finally:
        db.close()


if __name__ == "__main__":
    main()