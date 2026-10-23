"""
Row-level visibility for the RBAC dashboard (sessions, alerts, audit log, users).

Visibility comes from each role's `scope` column, not from its name, so every role
(the three original ones and the DSFS roles) is treated the same way:

    global       -> everything
    school       -> users with the same school_id
    department   -> users in the same department
    organization -> users with the same organization_id (suppliers)
    own          -> only the user's own records

A user with several roles gets the widest scope among them. Deny by default: a
school/organization scope without a school_id/organization_id on the user falls
back to "own".

Older databases (and test databases) may still have the column default "own" on
the original roles. For roles listed in the DSFS catalog, a stored "own" is
replaced by the catalog's documented scope, so Administrator always sees
everything and Manager always sees their department.
"""
from typing import Optional

from app.core.dsfs_catalog import ROLE_SCOPES
from app.models.user import User

SCOPE_ORDER = ["global", "school", "department", "organization", "own"]  # widest first

SCOPE_LABELS = {
    "global": "All records across the programme",
    "school": "Records belonging to your school",
    "department": "Records belonging to your department",
    "organization": "Records belonging to your organisation",
    "own": "Only your own records",
}


def role_scope(role) -> str:
    scope = getattr(role, "scope", None) or "own"
    if scope == "own":
        scope = ROLE_SCOPES.get(getattr(role, "role_name", None), "own")
    return scope if scope in SCOPE_ORDER else "own"


def effective_scope(user) -> str:
    scopes = [role_scope(r) for r in (getattr(user, "roles", None) or [])]
    if not scopes:
        return "own"
    return min(scopes, key=SCOPE_ORDER.index)


def visibility_scope(user) -> dict:
    scope = effective_scope(user)
    if scope == "global":
        return {"level": "all"}
    if scope == "school" and getattr(user, "school_id", None):
        return {"level": "school", "school_id": user.school_id}
    if scope == "department":
        return {"level": "department", "department": user.department}
    if scope == "organization" and getattr(user, "organization_id", None):
        return {"level": "organization", "organization_id": user.organization_id}
    return {"level": "self", "user_id": user.user_id}


def apply_visibility(query, scope: dict):
    """Applies the scope to any query already joined against the User table."""
    level = scope["level"]
    if level == "all":
        return query
    if level == "school":
        return query.filter(User.school_id == scope["school_id"])
    if level == "department":
        return query.filter(User.department == scope["department"])
    if level == "organization":
        return query.filter(User.organization_id == scope["organization_id"])
    return query.filter(User.user_id == scope["user_id"])


def in_scope(user: Optional[User], scope: dict) -> bool:
    level = scope["level"]
    if level == "all":
        return True
    if user is None:
        return False
    if level == "school":
        return user.school_id == scope["school_id"]
    if level == "department":
        return user.department == scope["department"]
    if level == "organization":
        return user.organization_id == scope["organization_id"]
    return user.user_id == scope["user_id"]


def out_of_scope_message(kind: str, scope: dict) -> str:
    level = scope["level"]
    if level == "school":
        return f"This {kind} belongs to a different school."
    if level == "department":
        return f"This {kind} belongs to a different department."
    if level == "organization":
        return f"This {kind} belongs to a different organisation."
    return f"This {kind} does not belong to your account."
