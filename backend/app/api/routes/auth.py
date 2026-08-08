from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.schemas.user import Token
from app.core.security import verify_password, create_access_token
from app.core.rbac import get_current_user_and_session
from app.services import session_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    client_host = request.client.host if request.client else "unknown"
    session = session_service.create_session(db, user_id=user.user_id, access_location=client_host)

    token = create_access_token({"sub": str(user.user_id), "sid": session.session_id})
    return Token(access_token=token)


@router.post("/logout")
def logout(current=Depends(get_current_user_and_session), db: Session = Depends(get_db)):
    _, session_id = current
    session = session_service.close_session(db, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"detail": "Logged out", "session_duration": session.session_duration}