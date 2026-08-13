from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.models.user import User
from app.schemas.user import Token
from app.core.security import (
    verify_password,
    create_access_token,
    create_pending_token,
    decode_pending_token,
)
from app.core.rbac import get_current_user_and_session
from app.services import session_service, biometric_service, otp_service
from app.schemas.user import UserOut

router = APIRouter(prefix="/api/auth", tags=["auth"])


class PendingTokenResponse(BaseModel):
    status: str
    pending_token: str


class VerifyFaceRequest(BaseModel):
    pending_token: str
    image_base64: str


class VerifyOtpRequest(BaseModel):
    pending_token: str


class RequestOtpRequest(BaseModel):
    pending_token: str


class EnrollFaceRequest(BaseModel):
    image_base64: str


def _issue_full_login(db: Session, request: Request, user: User) -> Token:
    """Shared final step: create session + issue real access token."""
    client_host = request.client.host if request.client else "unknown"
    session = session_service.create_session(db, user_id=user.user_id, access_location=client_host)
    token = create_access_token({"sub": str(user.user_id), "sid": session.session_id})
    return Token(access_token=token)

@router.get("/me", response_model=UserOut)
def get_me(current=Depends(get_current_user_and_session)):
    user, _ = current
    return user


@router.post("/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.is_biometric_enrolled:
        pending_token = create_pending_token(user.user_id)
        return PendingTokenResponse(status="2fa_required", pending_token=pending_token)

    # No biometric enrolled yet — fall back to direct login (e.g. first-time users)
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


@router.post("/verify-otp", response_model=Token)
def verify_otp_route(payload: VerifyOtpRequest, request: Request, db: Session = Depends(get_db), code: str = ""):
    user_id_str = decode_pending_token(payload.pending_token)
    if user_id_str is None:
        raise HTTPException(status_code=401, detail="Invalid or expired pending token")
    user_id = int(user_id_str)

    if not otp_service.verify_otp(db, user_id, code):
        raise HTTPException(status_code=401, detail="Incorrect or expired OTP")

    user = db.query(User).filter(User.user_id == user_id).first()
    return _issue_full_login(db, request, user)


@router.post("/enroll-face")
def enroll_face_route(
    payload: EnrollFaceRequest,
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    user, _session_id = current
    success = biometric_service.enroll_face(db, user.user_id, payload.image_base64)
    if not success:
        raise HTTPException(status_code=400, detail="No face detected in image")
    user.is_biometric_enrolled = True
    db.commit()
    return {"status": "enrolled"}


@router.post("/logout")
def logout(current=Depends(get_current_user_and_session), db: Session = Depends(get_db)):
    _, session_id = current
    session = session_service.close_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"detail": "Logged out", "session_duration": session.session_duration}