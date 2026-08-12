import json
from datetime import datetime
from typing import List

import csv
import io
from typing import Optional
from fastapi.responses import StreamingResponse
from app.models.session import AccessLog

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from datetime import timedelta
from collections import defaultdict

from app.db.database import get_db
from app.core.rbac import require_permission
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


@router.get(
    "/summary",
    response_model=DashboardSummary,
    dependencies=[Depends(require_permission("dashboard", "read"))],
)
def get_summary(db: Session = Depends(get_db)):
    active_sessions = db.query(UserSession).filter(UserSession.logout_time.is_(None)).count()
    total_users = db.query(User).count()
    roles_configured = db.query(Role).count()

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    alerts_today = (
        db.query(AnomalyAlert)
        .filter(AnomalyAlert.is_anomaly.is_(True), AnomalyAlert.alert_timestamp >= today_start)
        .count()
    )
    return DashboardSummary(
        active_sessions=active_sessions,
        total_users=total_users,
        roles_configured=roles_configured,
        alerts_today=alerts_today,
    )
@router.get(
    "/charts/alerts-over-time",
    dependencies=[Depends(require_permission("dashboard", "read"))],
)
def alerts_over_time(days: int = Query(14, ge=1, le=90), db: Session = Depends(get_db)):
    start = (datetime.utcnow() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    alerts = (
        db.query(AnomalyAlert)
        .filter(AnomalyAlert.is_anomaly.is_(True), AnomalyAlert.alert_timestamp >= start)
        .all()
    )
    counts = defaultdict(int)
    for a in alerts:
        counts[a.alert_timestamp.date().isoformat()] += 1

    return [
        {"date": (start + timedelta(days=i)).date().isoformat(),
         "alerts": counts.get((start + timedelta(days=i)).date().isoformat(), 0)}
        for i in range(days)
    ]


@router.get(
    "/charts/session-activity",
    dependencies=[Depends(require_permission("dashboard", "read"))],
)
def session_activity(days: int = Query(14, ge=1, le=90), db: Session = Depends(get_db)):
    start = (datetime.utcnow() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    sessions = db.query(UserSession).filter(UserSession.login_time >= start).all()
    counts = defaultdict(int)
    for s in sessions:
        counts[s.login_time.date().isoformat()] += 1

    return [
        {"date": (start + timedelta(days=i)).date().isoformat(),
         "sessions": counts.get((start + timedelta(days=i)).date().isoformat(), 0)}
        for i in range(days)
    ]


@router.get(
    "/alerts",
    response_model=List[AnomalyAlertSummary],
    dependencies=[Depends(require_permission("dashboard", "read"))],
)
def list_alerts(
    only_anomalous: bool = Query(True),
    include_reviewed: bool = Query(True),
    db: Session = Depends(get_db),
):
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
        results.append(
            AnomalyAlertSummary(
                alert_id=alert.alert_id,
                session_id=alert.session_id,
                user_id=user.user_id if user else -1,
                username=user.username if user else "unknown",
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


@router.get(
    "/alerts/{alert_id}",
    response_model=AnomalyAlertDetail,
    dependencies=[Depends(require_permission("dashboard", "read"))],
)
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
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

    if payload.reviewed is not None:
        alert.reviewed = payload.reviewed
        if payload.reviewed:
            alert.reviewed_by = current_user.user_id
    if payload.notes is not None:
        alert.notes = payload.notes

    db.commit()
    db.refresh(alert)
    return _build_alert_detail(alert)


@router.post(
    "/sessions/{session_id}/terminate",
    response_model=TerminateSessionResult,
    dependencies=[Depends(require_permission("dashboard", "write"))],
)
def terminate_session(session_id: int, db: Session = Depends(get_db)):
    session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    was_active = session.logout_time is None
    session.terminated = True
    if was_active:
        session.logout_time = datetime.utcnow()
        session.session_duration = (session.logout_time - session.login_time).total_seconds()

    db.commit()
    db.refresh(session)

    # If terminating an active session just closed it for the first time,
    # this is a genuine close event — score it like any other logout.
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


@router.get(
    "/sessions",
    response_model=List[SessionOut],
    dependencies=[Depends(require_permission("dashboard", "read"))],
)
def list_sessions(active_only: bool = Query(False), db: Session = Depends(get_db)):
    query = db.query(UserSession)
    if active_only:
        query = query.filter(UserSession.logout_time.is_(None))
    sessions = query.order_by(UserSession.login_time.desc()).limit(100).all()

    return [
        SessionOut(
            session_id=s.session_id,
            user_id=s.user_id,
            username=s.user.username if s.user else "unknown",
            login_time=s.login_time,
            logout_time=s.logout_time,
            session_duration=s.session_duration,
            access_location=s.access_location,
            is_active=s.logout_time is None,
            terminated=s.terminated,
        )
        for s in sessions
    ]

@router.get(
    "/audit-log/export",
    dependencies=[Depends(require_permission("dashboard", "read"))],
)
def export_audit_log(
    start_date: Optional[datetime] = Query(None, description="ISO date, e.g. 2026-08-01"),
    end_date: Optional[datetime] = Query(None, description="ISO date, e.g. 2026-08-31"),
    user_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    query = (
        db.query(AccessLog)
        .join(UserSession, AccessLog.session_id == UserSession.session_id)
    )
    if start_date:
        query = query.filter(AccessLog.access_timestamp >= start_date)
    if end_date:
        query = query.filter(AccessLog.access_timestamp <= end_date)
    if user_id:
        query = query.filter(UserSession.user_id == user_id)

    logs = query.order_by(AccessLog.access_timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["log_id", "timestamp", "username", "session_id", "resource_name", "action_performed"])
    for log in logs:
        session = log.session
        user = session.user if session else None
        writer.writerow([
            log.log_id,
            log.access_timestamp.isoformat(),
            user.username if user else "unknown",
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