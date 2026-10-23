from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

import secrets
from datetime import datetime, timedelta, timezone
from app.services import welcome_email_service

from app.db.database import get_db
from app.core.security import hash_password
from app.core.visibility import visibility_scope, apply_visibility, in_scope, out_of_scope_message
from app.models.user import User
from app.models.role import Role
from app.core.rbac import require_permission
from app.services import rbac_service
from app.models.session import UserSession, AccessLog
from app.models.anomaly import AnomalyAlert
from app.models.notification import Notification
from app.models.otp import OTPCode
from app.models.biometric import BiometricEnrollment
from app.core.constants import DEPARTMENTS
from app.schemas.user import UserCreate, UserOut, UpdateDepartmentRequest, SetRoleRequest

router = APIRouter(prefix="/api/users", tags=["users"])

# Used only for the lock-out guards below (never remove or delete the last Administrator).
# Who can SEE which users is decided by role scope, in app/core/visibility.py.
ADMIN_ROLE_NAME = "Administrator"

SETUP_TOKEN_EXPIRE_HOURS = 48


def _count_administrators(db: Session, exclude_user_id: int = None) -> int:
    query = db.query(User).join(User.roles).filter(Role.role_name == ADMIN_ROLE_NAME)
    if exclude_user_id is not None:
        query = query.filter(User.user_id != exclude_user_id)
    return query.distinct().count()


def _is_administrator(user: User) -> bool:
    return any(r.role_name == ADMIN_ROLE_NAME for r in user.roles)


@router.put("/{user_id}/role", response_model=UserOut)
def set_user_role(
    user_id: int,
    payload: SetRoleRequest,
    current_user: User = Depends(require_permission("user", "write")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_role = db.query(Role).filter(Role.role_id == payload.role_id).first()
    if not new_role:
        raise HTTPException(status_code=404, detail="Role not found")

    currently_admin = _is_administrator(user)
    becoming_admin = new_role.role_name == ADMIN_ROLE_NAME

    if currently_admin and not becoming_admin:
        if user.user_id == current_user.user_id:
            raise HTTPException(
                status_code=400,
                detail="You cannot remove your own Administrator role while logged in.",
            )
        if _count_administrators(db, exclude_user_id=user.user_id) == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot remove the last remaining Administrator role — this would lock everyone out.",
            )

    user.roles = [new_role]  # single-role model: replaces whatever they had
    db.commit()
    db.refresh(user)
    return user


@router.get("/", response_model=List[UserOut])
def list_users(
    current_user: User = Depends(require_permission("user", "read")),
    db: Session = Depends(get_db),
):
    # global -> everyone, school -> same school, department -> same department,
    # organization -> same supplier organisation, own -> just themselves
    scope = visibility_scope(current_user)
    return apply_visibility(db.query(User), scope).all()


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    current_user: User = Depends(require_permission("user", "read")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    scope = visibility_scope(current_user)
    if not in_scope(user, scope):
        raise HTTPException(status_code=403, detail=out_of_scope_message("user", scope))
    return user


@router.post("/", response_model=UserOut, dependencies=[Depends(require_permission("user", "write"))])
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    if payload.department not in DEPARTMENTS:
        raise HTTPException(status_code=400, detail=f"Department must be one of: {', '.join(DEPARTMENTS)}")

    if not payload.role_ids:
        raise HTTPException(status_code=400, detail="A user must be assigned at least one role.")

    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already in use")

    setup_token = secrets.token_urlsafe(32)
    placeholder_password = hash_password(secrets.token_urlsafe(32))

    user = User(
        username=payload.username,
        email=payload.email,
        department=payload.department,
        password=placeholder_password,
        password_set=False,
        password_setup_token=setup_token,
        password_setup_expires=datetime.now(timezone.utc) + timedelta(hours=SETUP_TOKEN_EXPIRE_HOURS),
        biometric_choice_made=False,
    )
    if payload.role_ids:
        user.roles = db.query(Role).filter(Role.role_id.in_(payload.role_ids)).all()

    db.add(user)
    db.commit()
    db.refresh(user)

    sent = welcome_email_service.send_welcome_email(user, setup_token)
    if not sent:
        import logging
        logging.getLogger(__name__).warning(
            "Welcome email failed to send for user_id=%s — share the setup link manually.", user.user_id
        )

    return user


@router.patch(
    "/{user_id}/department",
    response_model=UserOut,
    dependencies=[Depends(require_permission("user", "write"))],
)
def update_department(user_id: int, payload: UpdateDepartmentRequest, db: Session = Depends(get_db)):
    if payload.department not in DEPARTMENTS:
        raise HTTPException(status_code=400, detail=f"Department must be one of: {', '.join(DEPARTMENTS)}")
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.department = payload.department
    db.commit()
    db.refresh(user)
    return user


@router.post(
    "/{user_id}/resend-setup-email",
    dependencies=[Depends(require_permission("user", "write"))],
)
def resend_setup_email(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.password_set:
        raise HTTPException(status_code=400, detail="User has already completed account setup.")

    setup_token = secrets.token_urlsafe(32)
    user.password_setup_token = setup_token
    user.password_setup_expires = datetime.now(timezone.utc) + timedelta(hours=SETUP_TOKEN_EXPIRE_HOURS)
    db.commit()

    sent = welcome_email_service.send_welcome_email(user, setup_token)
    if not sent:
        raise HTTPException(status_code=500, detail="Failed to send setup email.")
    return {"detail": "Setup email resent."}


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(require_permission("user", "write")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.user_id == current_user.user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account while logged in.",
        )

    if _is_administrator(user) and _count_administrators(db, exclude_user_id=user.user_id) == 0:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete the last remaining Administrator — this would lock everyone out.",
        )

    try:
        session_ids = [
            s.session_id for s in db.query(UserSession.session_id).filter(UserSession.user_id == user.user_id).all()
        ]

        if session_ids:
            alert_ids = [
                a.alert_id for a in db.query(AnomalyAlert.alert_id).filter(AnomalyAlert.session_id.in_(session_ids)).all()
            ]
            if alert_ids:
                # Notifications from OTHER admins may point at these alerts — clean those up too,
                # not just this user's own notifications, or the alert delete below will fail.
                db.query(Notification).filter(Notification.alert_id.in_(alert_ids)).delete(synchronize_session=False)
                db.query(AnomalyAlert).filter(AnomalyAlert.alert_id.in_(alert_ids)).delete(synchronize_session=False)

            db.query(AccessLog).filter(AccessLog.session_id.in_(session_ids)).delete(synchronize_session=False)
            db.query(UserSession).filter(UserSession.session_id.in_(session_ids)).delete(synchronize_session=False)

        # If this user reviewed alerts belonging to OTHER users' sessions, don't leave a dangling FK
        db.query(AnomalyAlert).filter(AnomalyAlert.reviewed_by == user.user_id).update(
            {"reviewed_by": None}, synchronize_session=False
        )

        db.query(Notification).filter(Notification.user_id == user.user_id).delete(synchronize_session=False)
        db.query(OTPCode).filter(OTPCode.user_id == user.user_id).delete(synchronize_session=False)
        db.query(BiometricEnrollment).filter(BiometricEnrollment.user_id == user.user_id).delete(synchronize_session=False)

        db.delete(user)
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete user due to related data. Check server logs.")

    return {"detail": f"User '{user.username}' deleted"}


@router.post(
    "/{user_id}/roles/{role_id}",
    response_model=UserOut,
    dependencies=[Depends(require_permission("user", "write"))],
)
def assign_role_to_user(user_id: int, role_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    return rbac_service.assign_role(db, user, role)


@router.delete(
    "/{user_id}/roles/{role_id}",
    response_model=UserOut,
)
def remove_role_from_user(
    user_id: int,
    role_id: int,
    current_user: User = Depends(require_permission("user", "write")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.role_name == ADMIN_ROLE_NAME:
        if user.user_id == current_user.user_id:
            raise HTTPException(
                status_code=400,
                detail="You cannot remove your own Administrator role while logged in.",
            )
        if _count_administrators(db, exclude_user_id=user.user_id) == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot remove the last remaining Administrator role — this would lock everyone out.",
            )

    return rbac_service.remove_role(db, user, role)