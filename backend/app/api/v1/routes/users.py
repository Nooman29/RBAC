import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.deps import require_scope
from app.api.v1.errors import api_error
from app.api.v1.schemas import (
    GuardianLinkIn,
    GuardianLinkOut,
    SetRoleV1,
    UserCreateV1,
    UserCreatedV1,
    UserOutV1,
    UserPage,
    UserUpdateV1,
)
from app.core.constants import DEPARTMENTS
from app.core.security import hash_password
from app.db.database import get_db
from app.models.guardian import GuardianLink
from app.models.role import Role
from app.models.user import User
from app.services import welcome_email_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])

ADMIN_ROLE_NAME = "Administrator"
SETUP_TOKEN_EXPIRE_HOURS = 48


def _get_user(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise api_error(404, "user_not_found", "User not found.")
    return user


def _check_department(department: str) -> None:
    if department != "Unassigned" and department not in DEPARTMENTS:
        raise api_error(
            422, "invalid_department",
            f"Department must be 'Unassigned' or one of: {', '.join(DEPARTMENTS)}.",
        )


def _check_scope_fields(role: Role, school_id: Optional[str], organization_id: Optional[str]) -> None:
    if role.scope == "school" and not school_id:
        raise api_error(422, "school_id_required", f"Role '{role.role_name}' is school-scoped; school_id is required.")
    if role.scope == "organization" and not organization_id:
        raise api_error(
            422, "organization_id_required",
            f"Role '{role.role_name}' is organisation-scoped; organization_id is required.",
        )


def _refuse_admin_role(role: Role) -> None:
    if role.role_name == ADMIN_ROLE_NAME:
        raise api_error(
            403, "forbidden_role",
            "Service clients cannot assign the Administrator role. Use the administrator dashboard.",
        )


@router.get("", response_model=UserPage, summary="List users")
def list_users(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    school_id: Optional[str] = None,
    role_name: Optional[str] = None,
    department: Optional[str] = None,
    _client=Depends(require_scope("users:read")),
    db: Session = Depends(get_db),
):
    query = db.query(User)
    if school_id:
        query = query.filter(User.school_id == school_id)
    if department:
        query = query.filter(User.department == department)
    if role_name:
        query = query.join(User.roles).filter(Role.role_name == role_name)
    total = query.count()
    items = query.order_by(User.user_id).offset(offset).limit(limit).all()
    return UserPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/{user_id}", response_model=UserOutV1, summary="One user")
def get_user(user_id: int, _client=Depends(require_scope("users:read")), db: Session = Depends(get_db)):
    return _get_user(db, user_id)


@router.post(
    "", response_model=UserCreatedV1, status_code=201,
    summary="Create a user (they receive an email to set their password)",
)
def create_user(
    payload: UserCreateV1,
    _client=Depends(require_scope("users:write")),
    db: Session = Depends(get_db),
):
    role = db.query(Role).filter(Role.role_id == payload.role_id).first()
    if role is None:
        raise api_error(404, "role_not_found", "Role not found.")
    _refuse_admin_role(role)
    _check_scope_fields(role, payload.school_id, payload.organization_id)
    _check_department(payload.department)

    if db.query(User).filter(User.username == payload.username).first():
        raise api_error(409, "username_taken", "Username already exists.")
    if db.query(User).filter(User.email == payload.email).first():
        raise api_error(409, "email_taken", "Email already in use.")

    setup_token = secrets.token_urlsafe(32)
    user = User(
        username=payload.username,
        email=payload.email,
        department=payload.department,
        school_id=payload.school_id,
        organization_id=payload.organization_id,
        password=hash_password(secrets.token_urlsafe(32)),   # placeholder until they set their own
        password_set=False,
        password_setup_token=setup_token,
        password_setup_expires=(
            datetime.now(timezone.utc) + timedelta(hours=SETUP_TOKEN_EXPIRE_HOURS)
        ).replace(tzinfo=None),
        biometric_choice_made=False,
    )
    user.roles = [role]
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise api_error(409, "conflict", "Username or email already in use.")
    db.refresh(user)

    sent = welcome_email_service.send_welcome_email(user, setup_token)
    if not sent:
        logger.warning("Welcome email failed for user_id=%s (created via API v1).", user.user_id)

    base = UserOutV1.model_validate(user)
    return UserCreatedV1(**base.model_dump(), setup_email_sent=bool(sent))


@router.patch("/{user_id}", response_model=UserOutV1, summary="Update department, school or organisation")
def update_user(
    user_id: int,
    payload: UserUpdateV1,
    _client=Depends(require_scope("users:write")),
    db: Session = Depends(get_db),
):
    user = _get_user(db, user_id)
    if any(r.role_name == ADMIN_ROLE_NAME for r in user.roles):
        raise api_error(403, "forbidden_role", "Administrator accounts cannot be modified through the API.")

    fields = payload.model_fields_set
    if "department" in fields and payload.department is not None:
        _check_department(payload.department)
        user.department = payload.department
    if "school_id" in fields:
        user.school_id = payload.school_id or None
    if "organization_id" in fields:
        user.organization_id = payload.organization_id or None

    try:
        for role in user.roles:
            _check_scope_fields(role, user.school_id, user.organization_id)
    except Exception:
        db.rollback()
        raise

    db.commit()
    db.refresh(user)
    return user


@router.put("/{user_id}/role", response_model=UserOutV1, summary="Set the user's role (single-role model)")
def set_user_role(
    user_id: int,
    payload: SetRoleV1,
    _client=Depends(require_scope("users:write")),
    db: Session = Depends(get_db),
):
    user = _get_user(db, user_id)
    if any(r.role_name == ADMIN_ROLE_NAME for r in user.roles):
        raise api_error(403, "forbidden_role", "Administrator accounts cannot be modified through the API.")

    role = db.query(Role).filter(Role.role_id == payload.role_id).first()
    if role is None:
        raise api_error(404, "role_not_found", "Role not found.")
    _refuse_admin_role(role)
    _check_scope_fields(role, user.school_id, user.organization_id)

    user.roles = [role]
    db.commit()
    db.refresh(user)
    return user


# ---- guardian links (Parent/Guardian -> external student ids) ---------------

@router.get("/{user_id}/guardian-links", response_model=List[GuardianLinkOut], summary="Students linked to a guardian")
def list_guardian_links(
    user_id: int, _client=Depends(require_scope("users:read")), db: Session = Depends(get_db)
):
    _get_user(db, user_id)
    return (
        db.query(GuardianLink)
        .filter(GuardianLink.guardian_user_id == user_id)
        .order_by(GuardianLink.id)
        .all()
    )


@router.post(
    "/{user_id}/guardian-links", response_model=GuardianLinkOut, status_code=201,
    summary="Link a guardian to an external student id",
)
def add_guardian_link(
    user_id: int,
    payload: GuardianLinkIn,
    _client=Depends(require_scope("users:write")),
    db: Session = Depends(get_db),
):
    _get_user(db, user_id)
    existing = (
        db.query(GuardianLink.id)
        .filter(
            GuardianLink.guardian_user_id == user_id,
            GuardianLink.external_student_id == payload.external_student_id,
        )
        .first()
    )
    if existing:
        raise api_error(409, "link_exists", "This guardian is already linked to that student.")
    link = GuardianLink(guardian_user_id=user_id, external_student_id=payload.external_student_id)
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


@router.delete("/{user_id}/guardian-links/{link_id}", summary="Remove a guardian link")
def remove_guardian_link(
    user_id: int,
    link_id: int,
    _client=Depends(require_scope("users:write")),
    db: Session = Depends(get_db),
):
    link = (
        db.query(GuardianLink)
        .filter(GuardianLink.id == link_id, GuardianLink.guardian_user_id == user_id)
        .first()
    )
    if link is None:
        raise api_error(404, "link_not_found", "Guardian link not found.")
    db.delete(link)
    db.commit()
    return {"detail": "Guardian link removed."}