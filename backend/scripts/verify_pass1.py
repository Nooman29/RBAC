"""
Verifies DSFS Pass 1. Prints PASS/FAIL per check; exit code 1 on any failure.
Leaves the database unchanged (temporary users are rolled back).

    python -m scripts.verify_pass1

Note: check 1 compares the original roles to their ORIGINAL permissions. If you
manually edited those roles' permissions through the UI, it will report that.
"""

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal, engine
from app.db.migrations import apply_dsfs_pass1_schema
from app.models.role import Role
from app.models.user import User
from app.models.guardian import GuardianLink
from app.core.constants import RESOURCES
from app.core.dsfs_catalog import ACTIONS, ROLE_SCOPES, DSFS_ROLE_POLICIES
from app.services.rbac_service import AccessContext, check_access

ORIGINAL_CORE = ("dashboard", "role", "user")
EXPECTED_ADMIN_CORE = {(r, a) for r in ORIGINAL_CORE for a in ("read", "write")}
EXPECTED_MANAGER = {("dashboard", "read"), ("user", "read")}
EXPECTED_STANDARD = {("dashboard", "read")}

failures = []


def check(name, condition, detail=""):
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not condition) else ""))
    if not condition:
        failures.append(name)


def perms_of(role):
    return {(p.resource_name, p.action_type) for p in role.permissions}


def make_user(db, role, **fields):
    tag = uuid.uuid4().hex[:8]
    user = User(username=f"verify_{tag}", password="x", email=f"verify_{tag}@example.invalid", **fields)
    user.roles = [role]
    db.add(user)
    db.flush()
    return user


def decide(db, user, resource, action, **ctx):
    return check_access(db, user, resource, action, AccessContext(**ctx))


def main():
    # 0. Migration is idempotent. Runs BEFORE any session opens: ALTER TABLE
    #    needs exclusive locks and would block behind an open transaction.
    try:
        apply_dsfs_pass1_schema(engine)
        apply_dsfs_pass1_schema(engine)
        check("migration runs twice without error", True)
    except Exception as exc:  # noqa: BLE001
        check("migration runs twice without error", False, repr(exc))

    db = SessionLocal()
    try:
        roles = {r.role_name: r for r in db.query(Role).all()}

        # 1. Original roles unchanged
        for name in ("Administrator", "Manager", "Standard User"):
            check(f"original role exists: {name}", name in roles)
        if all(n in roles for n in ("Administrator", "Manager", "Standard User")):
            admin_perms = perms_of(roles["Administrator"])
            admin_core = {p for p in admin_perms if p[0] in ORIGINAL_CORE}
            check("Administrator core permissions unchanged", admin_core == EXPECTED_ADMIN_CORE,
                  str(sorted(admin_core ^ EXPECTED_ADMIN_CORE)))
            check("Manager permissions unchanged", perms_of(roles["Manager"]) == EXPECTED_MANAGER,
                  str(sorted(perms_of(roles["Manager"]) ^ EXPECTED_MANAGER)))
            check("Standard User permissions unchanged", perms_of(roles["Standard User"]) == EXPECTED_STANDARD,
                  str(sorted(perms_of(roles["Standard User"]) ^ EXPECTED_STANDARD)))

            # 3. Administrator holds every action on every new resource
            new_resources = [r for r in RESOURCES if r not in ORIGINAL_CORE]
            expected_new = {(r, a) for r in new_resources for a in ACTIONS}
            admin_new = {p for p in admin_perms if p[0] not in ORIGINAL_CORE}
            check("Administrator has all actions on new resources", admin_new == expected_new,
                  str(sorted(admin_new ^ expected_new)))

        # 2. DSFS roles + scopes
        for name, policy in DSFS_ROLE_POLICIES.items():
            expected = {(r, a) for r, acts in policy.items() for a in acts}
            role = roles.get(name)
            check(f"DSFS role permissions match catalog: {name}",
                  role is not None and perms_of(role) == expected,
                  "missing role" if role is None else str(sorted(perms_of(role) ^ expected)))
        for name, scope in ROLE_SCOPES.items():
            role = roles.get(name)
            check(f"role scope correct: {name} = {scope}", role is not None and role.scope == scope,
                  "missing role" if role is None else f"got {role.scope}")

        if not all(n in roles for n in ROLE_SCOPES):
            print("\nSeed has not been run; skipping access-evaluation checks.")
        else:
            # 4. Scope-aware evaluation (temporary users, rolled back at the end)
            teacher = make_user(db, roles["Teacher"], school_id="SCH-1")
            d = decide(db, teacher, "attendance", "write", school_id="SCH-1")
            check("school scope: own school allowed", d.allowed, d.reason)
            d = decide(db, teacher, "attendance", "write", school_id="SCH-2")
            check("school scope: other school denied (school_mismatch)", (not d.allowed) and d.reason == "school_mismatch", d.reason)
            d = decide(db, teacher, "attendance", "write")
            check("school scope: no context denied (context_required)", (not d.allowed) and d.reason == "context_required", d.reason)
            d = decide(db, teacher, "payment", "read", school_id="SCH-1")
            check("missing permission denied (missing_permission)", (not d.allowed) and d.reason == "missing_permission", d.reason)

            parent = make_user(db, roles["Parent/Guardian"])
            db.add(GuardianLink(guardian_user_id=parent.user_id, external_student_id="STU-1"))
            db.flush()
            d = decide(db, parent, "attendance", "read", student_id="STU-1")
            check("own scope: linked student allowed", d.allowed, d.reason)
            d = decide(db, parent, "attendance", "read", student_id="STU-2")
            check("own scope: unlinked student denied (not_owner)", (not d.allowed) and d.reason == "not_owner", d.reason)
            d = decide(db, parent, "attendance", "read")
            check("own scope: no context denied (context_required)", (not d.allowed) and d.reason == "context_required", d.reason)

            supplier = make_user(db, roles["Supplier"], organization_id="ORG-1")
            d = decide(db, supplier, "supply", "read", organization_id="ORG-1")
            check("organization scope: own org allowed", d.allowed, d.reason)
            d = decide(db, supplier, "supply", "read", organization_id="ORG-2")
            check("organization scope: other org denied", (not d.allowed) and d.reason == "organization_mismatch", d.reason)

            finance = make_user(db, roles["Finance Officer"])
            d = decide(db, finance, "payment", "approve")
            check("global scope: allowed without context", d.allowed, d.reason)

            admin_user = make_user(db, roles["Administrator"])
            d = decide(db, admin_user, "role", "write")
            check("Administrator (global) allowed without context", d.allowed, d.reason)

            manager = make_user(db, roles["Manager"], department="IT")
            d = decide(db, manager, "dashboard", "read", department="IT")
            check("Manager (department scope): own department allowed", d.allowed, d.reason)
            d = decide(db, manager, "dashboard", "read", department="HR")
            check("Manager (department scope): other department denied", (not d.allowed) and d.reason == "department_mismatch", d.reason)

            standard = make_user(db, roles["Standard User"])
            d = decide(db, standard, "dashboard", "read", owner_id=standard.user_id)
            check("Standard User (own scope): own record allowed", d.allowed, d.reason)
            d = decide(db, standard, "dashboard", "read", owner_id=standard.user_id + 99999)
            check("Standard User (own scope): other's record denied", (not d.allowed) and d.reason == "not_owner", d.reason)
    finally:
        db.rollback()   # discard every temporary user/link
        db.close()

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED:")
        for name in failures:
            print(f"  - {name}")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()