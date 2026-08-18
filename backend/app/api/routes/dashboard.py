import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List

import csv
import io
from typing import Optional
from fastapi.responses import StreamingResponse
from app.models.session import AccessLog

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.rbac import require_permission
from app.core.config import settings
from app.models.session import UserSession
from app.models.user import User
from app.models.role import Role
from app.models.anomaly import AnomalyAlert
from app.services import anomaly_service
from app.schemas.dashboard import (
    DashboardSummary,
    AnomalyAlertSummary,
    AnomalyAlertDetail,
    AlertReviewUpdate,
    SessionOut,
    TerminateSessionResult,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _department_scope(current_user: User) -> str | None:
    role_names = {r.role_name for r in current_user.roles}
    if "Administrator" in role_names:
        return None
    return current_user.department


def _assert_alert_in_scope(alert: AnomalyAlert, dept: str | None):
    if dept is None:
        return
    session = alert.session
    user = session.user if session else None
    if user is None or user.department != dept:
        raise HTTPException(status_code=403, detail="This alert belongs to a different department.")


def _assert_session_in_scope(session: UserSession, dept: str | None):
    if dept is None:
        return
    user = session.user
    if user is None or user.department != dept:
        raise HTTPException(status_code=403, detail="This session belongs to a different department.")


def _auto_close_stale_sessions(db: Session):
    """
    Sessions whose access token has expired but was never explicitly logged
    out (tab closed, browser crashed, etc.) stay 'active' in the DB forever
    otherwise. Close them lazily whenever sessions are queried, and score
    them like any other closed session.
    """
    cutoff_minutes = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    threshold = datetime.utcnow() - timedelta(minutes=cutoff_minutes)

    stale = (
        db.query(UserSession)
        .filter(UserSession.logout_time.is_(None), UserSession.login_time < threshold)
        .all()
    )
    if not stale:
        return

    for s in stale:
        s.logout_time = s.login_time + timedelta(minutes=cutoff_minutes)
        s.session_duration = (s.logout_time - s.login_time).total_seconds()
    db.commit()

    for s in stale:
        try:
            anomaly_service.score_session(db, s.session_id)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Anomaly scoring failed for auto-closed stale session_id=%s", s.session_id
            )


@router.get("/summary", response_model=DashboardSummary)
def get_summary(
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    _auto_close_stale_sessions(db)
    dept = _department_scope(current_user)

    session_q = db.query(UserSession).join(User, UserSession.user_id == User.user_id)
    if dept:
        session_q = session_q.filter(User.department == dept)
    active_sessions = session_q.filter(UserSession.logout_time.is_(None)).count()

    user_q = db.query(User)
    if dept:
        user_q = user_q.filter(User.department == dept)
    total_users = user_q.count()

    roles_configured = db.query(Role).count()

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    alert_q = (
        db.query(AnomalyAlert)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
    )
    if dept:
        alert_q = alert_q.filter(User.department == dept)
    alerts_today = alert_q.filter(
        AnomalyAlert.is_anomaly.is_(True), AnomalyAlert.alert_timestamp >= today_start
    ).count()

    return DashboardSummary(
        active_sessions=active_sessions,
        total_users=total_users,
        roles_configured=roles_configured,
        alerts_today=alerts_today,
    )


@router.get("/alerts", response_model=List[AnomalyAlertSummary])
def list_alerts(
    only_anomalous: bool = Query(True),
    include_reviewed: bool = Query(True),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    dept = _department_scope(current_user)

    query = db.query(AnomalyAlert)
    if only_anomalous:
        query = query.filter(AnomalyAlert.is_anomaly.is_(True))
    if not include_reviewed:
        query = query.filter(AnomalyAlert.reviewed.is_(False))

    alerts = query.order_by(AnomalyAlert.alert_timestamp.desc()).all()

    results = []
    for alert in alerts:
        session = alert.session
        user = session.user if session else None
        if dept and (user is None or user.department != dept):
            continue
        results.append(
            AnomalyAlertSummary(
                alert_id=alert.alert_id,
                session_id=alert.session_id,
                user_id=user.user_id if user else -1,
                username=user.username if user else "unknown",
                department=user.department if user else None,
                anomaly_score=alert.anomaly_score,
                is_anomaly=alert.is_anomaly,
                alert_timestamp=alert.alert_timestamp,
                reviewed=alert.reviewed,
            )
        )
    return results


def _build_alert_detail(alert: AnomalyAlert) -> AnomalyAlertDetail:
    session = alert.session
    user = session.user if session else None
    features = json.loads(alert.features_json) if alert.features_json else {}
    shap_contributions = json.loads(alert.shap_values_json) if alert.shap_values_json else []

    return AnomalyAlertDetail(
        alert_id=alert.alert_id,
        session_id=alert.session_id,
        user_id=user.user_id if user else -1,
        username=user.username if user else "unknown",
        department=user.department if user else None,
        anomaly_score=alert.anomaly_score,
        is_anomaly=alert.is_anomaly,
        alert_timestamp=alert.alert_timestamp,
        reviewed=alert.reviewed,
        reviewed_by=alert.reviewed_by,
        notes=alert.notes,
        features=features,
        shap_contributions=shap_contributions,
        role_names=[r.role_name for r in user.roles] if user else [],
        login_time=session.login_time if session else alert.alert_timestamp,
        session_duration=session.session_duration if session else None,
        access_location=session.access_location if session else None,
        session_terminated=session.terminated if session else False,
    )


@router.get("/alerts/{alert_id}", response_model=AnomalyAlertDetail)
def get_alert_detail(
    alert_id: int,
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    _assert_alert_in_scope(alert, _department_scope(current_user))
    return _build_alert_detail(alert)


@router.patch("/alerts/{alert_id}", response_model=AnomalyAlertDetail)
def update_alert(
    alert_id: int,
    payload: AlertReviewUpdate,
    current_user=Depends(require_permission("dashboard", "write")),
    db: Session = Depends(get_db),
):
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    _assert_alert_in_scope(alert, _department_scope(current_user))

    if payload.reviewed is not None:
        alert.reviewed = payload.reviewed
        if payload.reviewed:
            alert.reviewed_by = current_user.user_id
    if payload.notes is not None:
        alert.notes = payload.notes

    db.commit()
    db.refresh(alert)
    return _build_alert_detail(alert)


@router.post("/sessions/{session_id}/terminate", response_model=TerminateSessionResult)
def terminate_session(
    session_id: int,
    current_user: User = Depends(require_permission("dashboard", "write")),
    db: Session = Depends(get_db),
):
    session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    _assert_session_in_scope(session, _department_scope(current_user))

    was_active = session.logout_time is None
    session.terminated = True
    if was_active:
        session.logout_time = datetime.utcnow()
        session.session_duration = (session.logout_time - session.login_time).total_seconds()

    db.commit()
    db.refresh(session)

    if was_active:
        try:
            anomaly_service.score_session(db, session.session_id)
        except Exception:
            import logging
            logging.getLogger(__name__).exception(
                "Anomaly scoring failed for forcibly-terminated session_id=%s", session.session_id
            )

    return TerminateSessionResult(
        session_id=session.session_id,
        terminated=True,
        logout_time=session.logout_time,
        session_duration=session.session_duration,
    )


@router.get("/sessions", response_model=List[SessionOut])
def list_sessions(
    active_only: bool = Query(False),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    _auto_close_stale_sessions(db)
    dept = _department_scope(current_user)

    query = db.query(UserSession).join(User, UserSession.user_id == User.user_id)
    if dept:
        query = query.filter(User.department == dept)
    if active_only:
        query = query.filter(UserSession.logout_time.is_(None))
    sessions = query.order_by(UserSession.login_time.desc()).limit(100).all()

    return [
        SessionOut(
            session_id=s.session_id,
            user_id=s.user_id,
            username=s.user.username if s.user else "unknown",
            department=s.user.department if s.user else None,
            login_time=s.login_time,
            logout_time=s.logout_time,
            session_duration=s.session_duration,
            access_location=s.access_location,
            is_active=s.logout_time is None,
            terminated=s.terminated,
        )
        for s in sessions
    ]


@router.get("/charts/alerts-over-time")
def alerts_over_time(
    days: int = Query(14, ge=1, le=90),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    dept = _department_scope(current_user)
    start = (datetime.utcnow() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    query = (
        db.query(AnomalyAlert)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
        .filter(AnomalyAlert.is_anomaly.is_(True), AnomalyAlert.alert_timestamp >= start)
    )
    if dept:
        query = query.filter(User.department == dept)

    counts = defaultdict(int)
    for a in query.all():
        counts[a.alert_timestamp.date().isoformat()] += 1

    return [
        {"date": (start + timedelta(days=i)).date().isoformat(),
         "alerts": counts.get((start + timedelta(days=i)).date().isoformat(), 0)}
        for i in range(days)
    ]


@router.get("/charts/session-activity")
def session_activity(
    days: int = Query(14, ge=1, le=90),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    dept = _department_scope(current_user)
    start = (datetime.utcnow() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    query = db.query(UserSession).join(User, UserSession.user_id == User.user_id).filter(
        UserSession.login_time >= start
    )
    if dept:
        query = query.filter(User.department == dept)

    counts = defaultdict(int)
    for s in query.all():
        counts[s.login_time.date().isoformat()] += 1

    return [
        {"date": (start + timedelta(days=i)).date().isoformat(),
         "sessions": counts.get((start + timedelta(days=i)).date().isoformat(), 0)}
        for i in range(days)
    ]


@router.get("/audit-log/export")
def export_audit_log(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_id: Optional[int] = Query(None),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    dept = _department_scope(current_user)

    query = (
        db.query(AccessLog)
        .join(UserSession, AccessLog.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
    )
    if dept:
        query = query.filter(User.department == dept)
    if start_date:
        query = query.filter(AccessLog.access_timestamp >= start_date)
    if end_date:
        query = query.filter(AccessLog.access_timestamp <= end_date)
    if user_id:
        query = query.filter(UserSession.user_id == user_id)

    logs = query.order_by(AccessLog.access_timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["log_id", "timestamp", "username", "department", "session_id", "resource_name", "action_performed"])
    for log in logs:
        session = log.session
        user = session.user if session else None
        writer.writerow([
            log.log_id,
            log.access_timestamp.isoformat(),
            user.username if user else "unknown",
            user.department if user else "unknown",
            log.session_id,
            log.resource_name,
            log.action_performed,
        ])

    filename = f"audit_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )