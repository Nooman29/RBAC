from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import decode_access_token
from app.models.user import User
from app.services import session_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user_and_session(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        session_id = payload.get("sid")
        if user_id is None or session_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception

    user = db.query(User).filter(User.user_id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user, int(session_id)


def get_current_user(current=Depends(get_current_user_and_session)) -> User:
    user, _ = current
    return user


def require_permission(resource_name: str, action_type: str):
    def dependency(current=Depends(get_current_user_and_session), db: Session = Depends(get_db)) -> User:
        from app.services.rbac_service import user_has_permission
        user, session_id = current

        if not user_has_permission(user, resource_name, action_type):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {action_type} on {resource_name}",
            )

        session_service.log_access(db, session_id=session_id, resource_name=resource_name, action_type=action_type)
        return user

    return dependency