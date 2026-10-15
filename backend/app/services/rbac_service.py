from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session
from app.models.user import User
from app.models.role import Role
from app.models.guardian import GuardianLink


def assign_role(db: Session, user: User, role: Role) -> User:
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
        db.refresh(user)
    return user


def remove_role(db: Session, user: User, role: Role) -> User:
    if role in user.roles:
        user.roles.remove(role)
        db.commit()
        db.refresh(user)
    return user


def user_has_permission(user: User, resource_name: str, action_type: str) -> bool:
    for role in user.roles:
        for perm in role.permissions:
            if perm.resource_name == resource_name and perm.action_type == action_type:
                return True
    return False


# ---------------------------------------------------------------------------
# Scope-aware access evaluation (DSFS). Used by the integration API; existing
# routes keep using user_has_permission / require_permission unchanged.
# ---------------------------------------------------------------------------

@dataclass
class AccessContext:
    """Facts about the record being accessed, supplied by the calling module."""
    school_id: Optional[str] = None
    department: Optional[str] = None
    organization_id: Optional[str] = None
    owner_id: Optional[int] = None      # the user_id that owns the record
    student_id: Optional[str] = None    # external student identifier


@dataclass
class AccessDecision:
    allowed: bool
    reason: str


def _same(a, b) -> bool:
    return a is not None and b is not None and str(a) == str(b)


def _role_grants(role: Role, resource_name: str, action_type: str) -> bool:
    return any(
        p.resource_name == resource_name and p.action_type == action_type
        for p in role.permissions
    )


def _scope_satisfied(db: Session, user: User, scope: str, ctx: AccessContext):
    """Return (ok, reason). Deny by default."""
    if scope == "global":
        return True, "allowed"

    if scope == "school":
        if ctx.school_id is None:
            return False, "context_required"
        if not user.school_id:
            return False, "user_has_no_school"
        return (True, "allowed") if _same(ctx.school_id, user.school_id) else (False, "school_mismatch")

    if scope == "department":
        if ctx.department is None:
            return False, "context_required"
        return (True, "allowed") if _same(ctx.department, user.department) else (False, "department_mismatch")

    if scope == "organization":
        if ctx.organization_id is None:
            return False, "context_required"
        if not user.organization_id:
            return False, "user_has_no_organization"
        return (
            (True, "allowed")
            if _same(ctx.organization_id, user.organization_id)
            else (False, "organization_mismatch")
        )

    if scope == "own":
        if ctx.owner_id is None and ctx.student_id is None:
            return False, "context_required"
        if _same(ctx.owner_id, user.user_id):
            return True, "allowed"
        if ctx.student_id is not None:
            linked = (
                db.query(GuardianLink.id)
                .filter(
                    GuardianLink.guardian_user_id == user.user_id,
                    GuardianLink.external_student_id == str(ctx.student_id),
                )
                .first()
            )
            if linked:
                return True, "allowed"
        return False, "not_owner"

    return False, "unknown_scope"


def check_access(
    db: Session,
    user: User,
    resource_name: str,
    action_type: str,
    context: Optional[AccessContext] = None,
) -> AccessDecision:
    """
    Allow if ANY of the user's roles both grants the permission and has its
    scope satisfied by the context. Deny by default.
    """
    ctx = context or AccessContext()
    has_permission = False
    denial_reason = "missing_permission"

    for role in user.roles:
        if not _role_grants(role, resource_name, action_type):
            continue
        has_permission = True
        ok, reason = _scope_satisfied(db, user, role.scope, ctx)
        if ok:
            return AccessDecision(True, "allowed")
        denial_reason = reason

    return AccessDecision(False, denial_reason if has_permission else "missing_permission")