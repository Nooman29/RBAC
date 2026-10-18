import logging
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from app.models.session import UserSession, AccessLog
from app.services import anomaly_service

logger = logging.getLogger(__name__)


def create_session(db: Session, user_id: int, access_location: str = "unknown") -> UserSession:
    session = UserSession(user_id=user_id, access_location=access_location)
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def close_session(db: Session, session_id: int) -> Optional[UserSession]:
    session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if not session:
        return None
    session.logout_time = datetime.utcnow()
    session.session_duration = (session.logout_time - session.login_time).total_seconds()
    db.commit()
    db.refresh(session)

    # Score for anomalies now that the session is closed (duration + full
    # access log are only meaningful once it's ended). No-op until
    # scripts/train_isolation_forest.py has produced model artifacts, so
    # this can never block the logout flow.
    try:
        anomaly_service.score_session(db, session.session_id)
    except Exception:
        logger.exception("Anomaly scoring failed for session_id=%s", session.session_id)

    return session


def log_access(
    db: Session,
    session_id: int,
    resource_name: str,
    action_type: str,
    component: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> AccessLog:
    log = AccessLog(
        session_id=session_id,
        resource_name=resource_name,
        action_performed=action_type,
        component=component,
        endpoint=endpoint,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log