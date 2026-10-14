from dataclasses import dataclass
from typing import Optional

from jose import JWTError
from jose.exceptions import ExpiredSignatureError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.models.session import UserSession
from app.models.user import User


@dataclass
class TokenCheck:
    active: bool
    reason: str
    user: Optional[User] = None
    session: Optional[UserSession] = None
    expires_at: Optional[int] = None


def validate_access_token(db: Session, token: str) -> TokenCheck:
    """
    Stricter than get_current_user_and_session: a logged-out or terminated session
    is inactive, and short-lived pending-2FA tokens are rejected.
    """
    try:
        payload = decode_access_token(token)
    except ExpiredSignatureError:
        return TokenCheck(False, "token_expired")
    except JWTError:
        return TokenCheck(False, "invalid_token")

    if "scope" in payload or payload.get("sid") is None or payload.get("sub") is None:
        return TokenCheck(False, "invalid_token")

    try:
        user_id = int(payload["sub"])
        session_id = int(payload["sid"])
    except (TypeError, ValueError):
        return TokenCheck(False, "invalid_token")

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        return TokenCheck(False, "user_not_found")

    session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if session is None or session.user_id != user.user_id:
        return TokenCheck(False, "session_not_found")
    if session.terminated:
        return TokenCheck(False, "session_terminated")
    if session.logout_time is not None:
        return TokenCheck(False, "session_ended")

    return TokenCheck(True, "active", user=user, session=session, expires_at=payload.get("exp"))