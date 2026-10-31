from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.components import component_for
from app.core.security import decode_access_token
from app.models.user import User
from app.models.session import UserSession
from app.services import session_service, live_detection_service

bearer_scheme = HTTPBearer()


def get_current_user_and_session(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = credentials.credentials
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

    session = db.query(UserSession).filter(UserSession.session_id == int(session_id)).first()
    if session is None or session.user_id != user.user_id:
        raise credentials_exception
    if session.terminated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been terminated by an administrator",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if session.logout_time is not None:
        # Logged out (or closed as stale): the session was already scored, and live detection
        # ignores closed sessions, so a token kept after logout must not keep working.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has ended. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user, int(session_id)


def get_current_user(current=Depends(get_current_user_and_session)) -> User:
    user, _ = current
    return user


def require_permission(resource_name: str, action_type: str, audit: bool = True):
    """
    audit=False still enforces the permission but writes no access log and runs no live
    checks. Only for background polling (e.g. the live alerts panel): access logs are the
    anomaly model's activity counts, and polling is not user activity.
    """
    def dependency(
        current=Depends(get_current_user_and_session),
        db: Session = Depends(get_db),
        request: Request = None,
    ) -> User:
        from app.services.rbac_service import user_has_permission
        user, session_id = current

        # FastAPI always injects the request. It is optional only so the guard can still be
        # called directly (as unit tests do), in which case it logs exactly what it always did.
        audit_details = {}
        if request is not None:
            audit_details = {
                "component": component_for(request.url.path),
                "endpoint": f"{request.method} {request.url.path}"[:200],
            }

        if not user_has_permission(user, resource_name, action_type):
            # Refused requests are not access logs (the model never sees them), but live
            # detection counts them to spot probing.
            live_detection_service.on_denied(
                db, session_id, resource_name, action_type,
                endpoint=audit_details.get("endpoint"), reason="permission",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {action_type} on {resource_name}",
            )

        if not audit:
            return user

        log = session_service.log_access(
            db,
            session_id=session_id,
            resource_name=resource_name,
            action_type=action_type,
            **audit_details,
        )
        if request is not None and getattr(log, "log_id", None) is not None:
            # Lets the route add a description of what it changed (session_service.annotate_access).
            request.state.access_log_id = log.log_id
        live_detection_service.on_access(db, session_id)
        return user

    return dependency