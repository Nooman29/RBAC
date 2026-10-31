import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import func
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


def close_stale_sessions(db: Session, max_minutes: int) -> list:
    """
    Ends sessions left open longer than max_minutes (the access-token lifetime, so their token has
    expired: the user closed the browser without signing out) and scores them.

    The session ends at its LAST RECORDED ACTIVITY (latest access log), not at login + max_minutes:
    otherwise every abandoned session gets the same made-up duration, which distorts the model's
    session_duration_sec feature and its z-score. A session with no recorded activity lasted 0 s.
    """
    now = datetime.utcnow()
    stale = (
        db.query(UserSession)
        .filter(UserSession.logout_time.is_(None), UserSession.login_time < now - timedelta(minutes=max_minutes))
        .all()
    )
    if not stale:
        return []

    for s in stale:
        last_activity = (
            db.query(func.max(AccessLog.access_timestamp)).filter(AccessLog.session_id == s.session_id).scalar()
        )
        token_expiry = s.login_time + timedelta(minutes=max_minutes)
        end = min(max(last_activity or s.login_time, s.login_time), token_expiry)
        s.logout_time = end
        s.session_duration = (end - s.login_time).total_seconds()
    db.commit()

    for s in stale:
        try:
            anomaly_service.score_session(db, s.session_id)
        except Exception:
            logger.exception("Anomaly scoring failed for auto-closed stale session_id=%s", s.session_id)
    return stale


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


def annotate_access(db: Session, request, details: str) -> None:
    """
    Adds a plain-language description to the audit row require_permission wrote for this request
    (for example "Revoked write on user from Manager"). No-op when the request was not audited.
    """
    log_id = getattr(getattr(request, "state", None), "access_log_id", None) if request is not None else None
    if log_id is None:
        return
    log = db.query(AccessLog).filter(AccessLog.log_id == log_id).first()
    if log is not None:
        log.details = details[:300]
        db.commit()