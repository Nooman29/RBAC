"""
Seeds the three proposal-defined roles (Administrator, Manager, Standard User)
with least-privilege permission sets, and assigns Administrator to a chosen
user (or the first user found).

Run manually from backend/:
    python -m scripts.seed_roles_and_permissions
    python -m scripts.seed_roles_and_permissions --admin-user-id 1

Idempotent: safe to re-run; only inserts what's missing, never duplicates.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal
from app.models.role import Role, Permission
from app.models.user import User

# resource_name -> list of action_types this role may perform.
# An empty dict (Standard User) means: no administrative capability at all.
ROLE_POLICIES = {
    "Administrator": {
        "dashboard": ["read", "write"],
        "role": ["read", "write"],
        "user": ["read", "write"],
    },
    "Manager": {
        "dashboard": ["read"],   # can monitor sessions/alerts, cannot review/manage
        "user": ["read"],        # can view the team, cannot create/modify
    },
    "Standard User": {},
}

ROLE_DESCRIPTIONS = {
    "Administrator": "Full administrative access: dashboard, role management, user management.",
    "Manager": "Read-only visibility into dashboard and users. Cannot manage roles or permissions.",
    "Standard User": "No administrative access. Principle-of-least-privilege baseline role.",
}


def get_or_create_role(db, name: str) -> Role:
    role = db.query(Role).filter(Role.role_name == name).first()
    if role:
        return role
    role = Role(role_name=name, description=ROLE_DESCRIPTIONS[name])
    db.add(role)
    db.commit()
    db.refresh(role)
    print(f"Created role: {name}")
    return role


def get_or_create_permission(db, resource_name: str, action_type: str) -> Permission:
    perm = (
        db.query(Permission)
        .filter(Permission.resource_name == resource_name, Permission.action_type == action_type)
        .first()
    )
    if perm:
        return perm
    perm = Permission(resource_name=resource_name, action_type=action_type)
    db.add(perm)
    db.commit()
    db.refresh(perm)
    print(f"Created permission: {resource_name}:{action_type}")
    return perm


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-user-id", type=int, default=None,
                         help="user_id to assign Administrator to (defaults to the first user)")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        roles = {}
        for role_name, policy in ROLE_POLICIES.items():
            role = get_or_create_role(db, role_name)
            roles[role_name] = role

            for resource_name, actions in policy.items():
                for action_type in actions:
                    perm = get_or_create_permission(db, resource_name, action_type)
                    if perm not in role.permissions:
                        role.permissions.append(perm)
                        print(f"Granted {resource_name}:{action_type} -> {role_name}")
            db.commit()

        admin_role = roles["Administrator"]
        user = (
            db.query(User).filter(User.user_id == args.admin_user_id).first()
            if args.admin_user_id is not None
            else db.query(User).first()
        )

        if user:
            if admin_role not in user.roles:
                user.roles.append(admin_role)
                db.commit()
                print(f"Assigned Administrator role to user_id={user.user_id} ({user.username})")
            else:
                print(f"user_id={user.user_id} already has Administrator role")
        else:
            print("No users found — create one first, then re-run with --admin-user-id.")

        print("\nRole -> permission map:")
        for role_name, role in roles.items():
            perms = ", ".join(f"{p.resource_name}:{p.action_type}" for p in role.permissions) or "(none)"
            print(f"  {role_name}: {perms}")
    finally:
        db.close()


if __name__ == "__main__":
    main()