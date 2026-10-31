import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.models.user import User
from app.models.session import UserSession
from app.core.rate_limit import client_ip
from app.schemas.user import (
    ForgotPasswordRequest,
    MyPermissionsOut,
    PermissionPair,
    ResetPasswordRequest,
    Token,
    UserOut,
)
from app.core.security import (
    verify_password,
    hash_password,
    create_access_token,
    create_pending_token,
    decode_pending_token,
)
from app.core.rbac import get_current_user_and_session
from app.core.constants import RESOURCES
from app.core.dsfs_catalog import ACTIONS, risk_tier_for_roles
from app.core.visibility import SCOPE_LABELS, effective_scope
from app.services import biometric_service, otp_service, password_reset_service, session_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


class PendingTokenResponse(BaseModel):
    status: str
    pending_token: str
    has_face_option: bool = False


class VerifyFaceRequest(BaseModel):
    pending_token: str
    image_base64: str


class VerifyOtpRequest(BaseModel):
    pending_token: str


class RequestOtpRequest(BaseModel):
    pending_token: str


class EnrollFaceRequest(BaseModel):
    image_base64: str


class SetupPasswordRequest(BaseModel):
    token: str
    new_password: str


class CompleteBiometricSetupRequest(BaseModel):
    pending_token: str
    image_base64: str


class SkipBiometricSetupRequest(BaseModel):
    pending_token: str


class ResourceAccess(BaseModel):
    resource_name: str
    actions: List[str]


class MyAccessOut(BaseModel):
    username: str
    role_names: List[str]
    scope: str
    scope_label: str
    school_id: Optional[str] = None
    organization_id: Optional[str] = None
    department: Optional[str] = None
    risk_tier: str
    dashboard_access: bool
    resources: List[ResourceAccess]


def _all_permission_pairs(user: User) -> list:
    """Union of permissions over ALL the user's roles (not just the first one)."""
    seen, pairs = set(), []
    for role in user.roles:
        for p in role.permissions:
            key = (p.resource_name, p.action_type)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return pairs


def _issue_full_login(db: Session, request: Request, user: User) -> Token:
    """Shared final step: create session + issue real access token."""
    session = session_service.create_session(db, user_id=user.user_id, access_location=client_ip(request))
    token = create_access_token({"sub": str(user.user_id), "sid": session.session_id})
    return Token(access_token=token)


@router.post("/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.password_set:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account setup incomplete. Check your email for a setup link, or contact an administrator.",
        )

    if not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # A password alone never opens first-time setup (it could enrol someone else's face, or skip
    # straight in). Users who have not chosen yet verify the emailed code first; verify-otp then
    # sends them to setup. The setup-password link already proves the email, so it goes direct.
    pending_token = create_pending_token(user.user_id, scope="pending_2fa")
    return PendingTokenResponse(
        status="2fa_required", pending_token=pending_token, has_face_option=user.is_biometric_enrolled
    )


@router.post("/setup-password")
def setup_password(payload: SetupPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.password_setup_token == payload.token).first()
    if not user or user.password_setup_expires is None:
        raise HTTPException(status_code=400, detail="Invalid or expired setup link. Contact an administrator for a new one.")

    expires = user.password_setup_expires
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        raise HTTPException(status_code=400, detail="Invalid or expired setup link. Contact an administrator for a new one.")

    user.password = hash_password(payload.new_password)
    user.password_set = True
    user.password_setup_token = None
    user.password_setup_expires = None
    db.commit()

    pending_token = create_pending_token(user.user_id, scope="first_time_setup")
    return {"status": "password_set", "pending_token": pending_token}


@router.post("/complete-biometric-setup", response_model=Token)
def complete_biometric_setup(payload: CompleteBiometricSetupRequest, request: Request, db: Session = Depends(get_db)):
    user_id_str = decode_pending_token(payload.pending_token, expected_scope="first_time_setup")
    if user_id_str is None:
        raise HTTPException(status_code=401, detail="Invalid or expired setup session. Please log in again.")
    user_id = int(user_id_str)
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    success, message = biometric_service.enroll_face(db, user.user_id, payload.image_base64)
    if not success:
        raise HTTPException(status_code=400, detail=message)

    user.is_biometric_enrolled = True
    user.biometric_choice_made = True
    db.commit()

    return _issue_full_login(db, request, user)


@router.post("/skip-biometric-setup", response_model=Token)
def skip_biometric_setup(payload: SkipBiometricSetupRequest, request: Request, db: Session = Depends(get_db)):
    user_id_str = decode_pending_token(payload.pending_token, expected_scope="first_time_setup")
    if user_id_str is None:
        raise HTTPException(status_code=401, detail="Invalid or expired setup session. Please log in again.")
    user_id = int(user_id_str)
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.biometric_choice_made = True
    db.commit()

    return _issue_full_login(db, request, user)


@router.post("/request-otp")
def request_otp(payload: RequestOtpRequest, request: Request, db: Session = Depends(get_db)):
    user_id_str = decode_pending_token(payload.pending_token)
    if user_id_str is None:
        raise HTTPException(status_code=401, detail="Invalid or expired pending token")

    user_id = int(user_id_str)
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    sent = otp_service.generate_and_send_otp(db, user_id, user.email)
    if not sent:
        raise HTTPException(status_code=500, detail="Failed to send OTP email")
    return {"status": "otp_sent"}


@router.post("/verify-face", response_model=Token)
def verify_face(payload: VerifyFaceRequest, request: Request, db: Session = Depends(get_db)):
    user_id_str = decode_pending_token(payload.pending_token)
    if user_id_str is None:
        raise HTTPException(status_code=401, detail="Invalid or expired pending token")
    user_id = int(user_id_str)

    if not biometric_service.verify_face(db, user_id, payload.image_base64):
        raise HTTPException(status_code=401, detail="Face verification failed")

    user = db.query(User).filter(User.user_id == user_id).first()
    return _issue_full_login(db, request, user)


@router.post("/verify-otp")
def verify_otp_route(payload: VerifyOtpRequest, request: Request, db: Session = Depends(get_db), code: str = ""):
    """Returns an access token, or, for a user who has not chosen Face ID yet, a first-time
    setup token (status "first_time_setup_required") now that the email is verified."""
    user_id_str = decode_pending_token(payload.pending_token)
    if user_id_str is None:
        raise HTTPException(status_code=401, detail="Invalid or expired pending token")
    user_id = int(user_id_str)

    if not otp_service.verify_otp(db, user_id, code):
        raise HTTPException(status_code=401, detail="Incorrect or expired OTP")

    user = db.query(User).filter(User.user_id == user_id).first()
    if not user.biometric_choice_made:
        return PendingTokenResponse(
            status="first_time_setup_required",
            pending_token=create_pending_token(user.user_id, scope="first_time_setup"),
            has_face_option=False,
        )
    return _issue_full_login(db, request, user)


@router.post("/enroll-face")
def enroll_face_route(
    payload: EnrollFaceRequest,
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    user, _session_id = current
    success, message = biometric_service.enroll_face(db, user.user_id, payload.image_base64)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    user.is_biometric_enrolled = True
    db.commit()
    return {"status": "enrolled"}


@router.get("/me", response_model=UserOut)
def get_me(current=Depends(get_current_user_and_session), db: Session = Depends(get_db)):
    user, _ = current
    return user

@router.get("/my-permissions", response_model=MyPermissionsOut)
def get_my_permissions(current=Depends(get_current_user_and_session)):
    user, _ = current
    role_names = [r.role_name for r in user.roles]
    return MyPermissionsOut(
        username=user.username,
        role_name=", ".join(role_names) if role_names else None,
        department=user.department,
        permissions=[PermissionPair(resource_name=r, action_type=a) for r, a in _all_permission_pairs(user)],
    )


@router.get("/my-access", response_model=MyAccessOut)
def get_my_access(current=Depends(get_current_user_and_session)):
    """What the signed-in user may do, per module, and at which scope. Feeds the My Access page."""
    user, _ = current
    pairs = _all_permission_pairs(user)

    by_resource: dict = {}
    for resource, action in pairs:
        by_resource.setdefault(resource, set()).add(action)

    order = {name: i for i, name in enumerate(RESOURCES)}
    resources = [
        ResourceAccess(resource_name=r, actions=[a for a in ACTIONS if a in acts] + sorted(acts - set(ACTIONS)))
        for r, acts in sorted(by_resource.items(), key=lambda kv: order.get(kv[0], len(order)))
    ]

    scope = effective_scope(user)
    return MyAccessOut(
        username=user.username,
        role_names=[r.role_name for r in user.roles],
        scope=scope,
        scope_label=SCOPE_LABELS.get(scope, scope),
        school_id=user.school_id,
        organization_id=user.organization_id,
        department=user.department,
        risk_tier=risk_tier_for_roles([r.role_name for r in user.roles]),
        dashboard_access=("dashboard", "read") in set(pairs),
        resources=resources,
    )


@router.post("/logout")
def logout(current=Depends(get_current_user_and_session), db: Session = Depends(get_db)):
    _, session_id = current
    session = session_service.close_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"detail": "Logged out", "session_duration": session.session_duration}

RESET_TOKEN_EXPIRE_HOURS = 1


@router.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    # Always return the same response whether or not the email exists —
    # never reveal which emails are registered to an anonymous requester.
    if user and user.password_set:
        reset_token = secrets.token_urlsafe(32)
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=RESET_TOKEN_EXPIRE_HOURS)
        db.commit()
        password_reset_service.send_reset_email(user, reset_token)

    return {"detail": "If an account exists with that email, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.password_reset_token == payload.token).first()
    if not user or user.password_reset_expires is None:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link. Request a new one.")

    expires = user.password_reset_expires
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        raise HTTPException(status_code=400, detail="Invalid or expired reset link. Request a new one.")

    user.password = hash_password(payload.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    db.commit()

    # Whoever knew the old password may still be signed in: end every open session.
    open_sessions = (
        db.query(UserSession)
        .filter(UserSession.user_id == user.user_id, UserSession.logout_time.is_(None))
        .all()
    )
    for open_session in open_sessions:
        session_service.close_session(db, open_session.session_id)

    return {"detail": "Password reset successfully. You can now log in."}
