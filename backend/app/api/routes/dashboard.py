import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Optional

import csv
import io
from fastapi.responses import StreamingResponse
from app.models.session import AccessLog

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.rbac import require_permission
from app.core.config import settings
from app.core.constants import REVIEW_VERDICTS
from app.models.session import UserSession
from app.models.user import User
from app.models.role import Role
from app.models.anomaly import AnomalyAlert
from app.services import anomaly_service, attack_simulation_service
from app.schemas.dashboard import (
    DashboardSummary,
    AnomalyAlertSummary,
    AnomalyAlertDetail,
    AlertReviewUpdate,
    SessionOut,
    TerminateSessionResult,
    ScenarioOut,
    SimulateAttackRequest,
    SimulateAttackResult,
    DetectionOutcomeSummary,
    AuditLogEntryOut,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

OVERDUE_HOURS = 24


def _visibility_scope(current_user: User) -> dict:
    """
    Three-tier visibility for all dashboard-family data:
      - Administrator -> sees everything: {"level": "all"}
      - Manager       -> sees their own department only:
                         {"level": "department", "department": <dept>}
      - Everyone else (Standard User) -> sees only their own activity:
                         {"level": "self", "user_id": <id>}
    """
    role_names = {r.role_name for r in current_user.roles}
    if "Administrator" in role_names:
        return {"level": "all"}
    if "Manager" in role_names:
        return {"level": "department", "department": current_user.department}
    return {"level": "self", "user_id": current_user.user_id}


def _apply_visibility(query, scope: dict):
    """Applies the scope to any query already joined against the User table."""
    if scope["level"] == "all":
        return query
    if scope["level"] == "department":
        return query.filter(User.department == scope["department"])
    return query.filter(User.user_id == scope["user_id"])


def _in_scope(user: Optional[User], scope: dict) -> bool:
    if scope["level"] == "all":
        return True
    if user is None:
        return False
    if scope["level"] == "department":
        return user.department == scope["department"]
    return user.user_id == scope["user_id"]


def _assert_alert_in_scope(alert: AnomalyAlert, scope: dict):
    session = alert.session
    user = session.user if session else None
    if not _in_scope(user, scope):
        if scope["level"] == "department":
            raise HTTPException(status_code=403, detail="This alert belongs to a different department.")
        raise HTTPException(status_code=403, detail="This alert does not belong to your account.")


def _assert_session_in_scope(session: UserSession, scope: dict):
    user = session.user
    if not _in_scope(user, scope):
        if scope["level"] == "department":
            raise HTTPException(status_code=403, detail="This session belongs to a different department.")
        raise HTTPException(status_code=403, detail="This session does not belong to your account.")


def _is_overdue(alert: AnomalyAlert) -> bool:
    if not alert.is_anomaly or alert.review_verdict is not None:
        return False
    return (datetime.utcnow() - alert.alert_timestamp) > timedelta(hours=OVERDUE_HOURS)


def _auto_close_stale_sessions(db: Session):
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
    scope = _visibility_scope(current_user)

    session_q = db.query(UserSession).join(User, UserSession.user_id == User.user_id)
    session_q = _apply_visibility(session_q, scope)
    active_sessions = session_q.filter(UserSession.logout_time.is_(None)).count()

    user_q = db.query(User)
    user_q = _apply_visibility(user_q, scope)
    total_users = user_q.count()

    roles_configured = db.query(Role).count()

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    alert_q = (
        db.query(AnomalyAlert)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
    )
    alert_q = _apply_visibility(alert_q, scope)
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
    scope = _visibility_scope(current_user)

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
        if not _in_scope(user, scope):
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
                detection_reason=alert.detection_reason,
                review_verdict=alert.review_verdict,
                is_overdue=_is_overdue(alert),
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
        detection_reason=alert.detection_reason,
        review_verdict=alert.review_verdict,
        is_overdue=_is_overdue(alert),
        alert_timestamp=alert.alert_timestamp,
        reviewed=alert.reviewed,
        reviewed_by=alert.reviewed_by,
        notes=alert.notes,
        pattern_signature=alert.pattern_signature,
        features=features,
        shap_contributions=shap_contributions,
        role_names=[r.role_name for r in user.roles] if user else [],
        login_time=session.login_time if session else alert.alert_timestamp,
        session_duration=session.session_duration if session else None,
        access_location=session.access_location if session else None,
        session_terminated=session.terminated if session else False,
        session_active=(session.logout_time is None and not session.terminated) if session else False,
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
    _assert_alert_in_scope(alert, _visibility_scope(current_user))
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
    _assert_alert_in_scope(alert, _visibility_scope(current_user))

    # A verdict can be recorded on ANY scored session, flagged or not. A "confirmed_threat"
    # on a session the model let through is how a missed detection is reported; the detector
    # learns the pattern and the session leaves the user's baseline.
    if payload.review_verdict is not None:
        if payload.review_verdict not in REVIEW_VERDICTS:
            raise HTTPException(status_code=400, detail=f"review_verdict must be one of: {', '.join(REVIEW_VERDICTS)}")
        alert.review_verdict = payload.review_verdict
        alert.reviewed = True
        alert.reviewed_by = current_user.user_id
    elif payload.reviewed is not None:
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
    _assert_session_in_scope(session, _visibility_scope(current_user))

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
    scope = _visibility_scope(current_user)

    query = db.query(UserSession).join(User, UserSession.user_id == User.user_id)
    query = _apply_visibility(query, scope)
    if active_only:
        query = query.filter(UserSession.logout_time.is_(None))
    sessions = query.order_by(UserSession.login_time.desc()).limit(100).all()

    session_ids = [s.session_id for s in sessions]
    alerts_by_session = {}
    if session_ids:
        alerts_by_session = {
            a.session_id: a
            for a in db.query(AnomalyAlert).filter(AnomalyAlert.session_id.in_(session_ids)).all()
        }

    results = []
    for s in sessions:
        alert = alerts_by_session.get(s.session_id)
        results.append(
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
                simulated=s.simulated_scenario is not None,
                alert_id=alert.alert_id if alert else None,
                is_anomaly=alert.is_anomaly if alert else None,
                anomaly_score=alert.anomaly_score if alert else None,
                review_verdict=alert.review_verdict if alert else None,
            )
        )
    return results


@router.get("/charts/alerts-over-time")
def alerts_over_time(
    days: int = Query(14, ge=1, le=90),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)
    start = (datetime.utcnow() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    query = (
        db.query(AnomalyAlert)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
        .filter(AnomalyAlert.is_anomaly.is_(True), AnomalyAlert.alert_timestamp >= start)
    )
    query = _apply_visibility(query, scope)

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
    scope = _visibility_scope(current_user)
    start = (datetime.utcnow() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    query = db.query(UserSession).join(User, UserSession.user_id == User.user_id).filter(
        UserSession.login_time >= start
    )
    query = _apply_visibility(query, scope)

    counts = defaultdict(int)
    for s in query.all():
        counts[s.login_time.date().isoformat()] += 1

    return [
        {"date": (start + timedelta(days=i)).date().isoformat(),
         "sessions": counts.get((start + timedelta(days=i)).date().isoformat(), 0)}
        for i in range(days)
    ]


@router.get("/simulate-attack/scenarios", response_model=List[ScenarioOut])
def get_scenarios(
    current_user: User = Depends(require_permission("dashboard", "write")),
):
    return attack_simulation_service.list_scenarios()


@router.post("/simulate-attack", response_model=SimulateAttackResult)
def simulate_attack(
    payload: SimulateAttackRequest,
    current_user: User = Depends(require_permission("dashboard", "write")),
    db: Session = Depends(get_db),
):
    try:
        result = attack_simulation_service.run_scenario(db, payload.user_id, payload.scenario)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return result


@router.delete("/simulate-attack/reset/{user_id}")
def reset_simulated_data_route(
    user_id: int,
    current_user: User = Depends(require_permission("dashboard", "write")),
    db: Session = Depends(get_db),
):
    deleted = attack_simulation_service.reset_simulated_data(db, user_id)
    return {"deleted_sessions": deleted}


@router.delete("/simulate-attack/full-reset/{user_id}")
def full_reset_user_route(
    user_id: int,
    current_user: User = Depends(require_permission("dashboard", "write")),
    db: Session = Depends(get_db),
):
    deleted = attack_simulation_service.full_reset_user_history(db, user_id)
    return {"deleted_sessions": deleted}


@router.get("/detection-outcomes", response_model=DetectionOutcomeSummary)
def get_detection_outcomes(
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)

    query = (
        db.query(AnomalyAlert)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
        .filter(AnomalyAlert.is_anomaly.is_(True))
    )
    query = _apply_visibility(query, scope)

    alerts = query.all()

    confirmed = sum(1 for a in alerts if a.review_verdict == "confirmed_threat")
    false_positive = sum(1 for a in alerts if a.review_verdict == "false_positive")
    authorized = sum(1 for a in alerts if a.review_verdict == "authorized_exception")
    unreviewed = sum(1 for a in alerts if a.review_verdict is None)
    overdue = sum(1 for a in alerts if _is_overdue(a))

    # Threats the detector let through, reported by an administrator afterwards.
    missed_query = (
        db.query(AnomalyAlert)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
        .filter(AnomalyAlert.is_anomaly.is_(False), AnomalyAlert.review_verdict == "confirmed_threat")
    )
    missed = _apply_visibility(missed_query, scope).count()

    return DetectionOutcomeSummary(
        confirmed_threat=confirmed,
        false_positive=false_positive,
        authorized_exception=authorized,
        unreviewed=unreviewed,
        unreviewed_overdue=overdue,
        total_flagged=len(alerts),
        missed_threat=missed,
    )


@router.get("/audit-log/preview", response_model=List[AuditLogEntryOut])
def preview_audit_log(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_ids: Optional[List[int]] = Query(None),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)

    query = (
        db.query(AccessLog)
        .join(UserSession, AccessLog.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
    )
    query = _apply_visibility(query, scope)
    if start_date:
        query = query.filter(AccessLog.access_timestamp >= start_date)
    if end_date:
        query = query.filter(AccessLog.access_timestamp <= end_date)
    if user_ids:
        query = query.filter(UserSession.user_id.in_(user_ids))

    logs = query.order_by(AccessLog.access_timestamp.desc()).limit(500).all()

    return [
        AuditLogEntryOut(
            log_id=log.log_id,
            timestamp=log.access_timestamp,
            username=log.session.user.username if log.session and log.session.user else "unknown",
            department=log.session.user.department if log.session and log.session.user else None,
            session_id=log.session_id,
            resource_name=log.resource_name,
            action_performed=log.action_performed,
        )
        for log in logs
    ]


@router.get("/audit-log/export")
def export_audit_log(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_ids: Optional[List[int]] = Query(None),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)

    query = (
        db.query(AccessLog)
        .join(UserSession, AccessLog.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
    )
    query = _apply_visibility(query, scope)
    if start_date:
        query = query.filter(AccessLog.access_timestamp >= start_date)
    if end_date:
        query = query.filter(AccessLog.access_timestamp <= end_date)
    if user_ids:
        query = query.filter(UserSession.user_id.in_(user_ids))

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