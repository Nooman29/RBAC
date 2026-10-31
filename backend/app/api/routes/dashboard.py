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
from app.core.rbac import require_permission, get_current_user_and_session
from app.core.config import settings
from app.core.business_time import local_now, to_local, to_utc
from app.core.visibility import (
    visibility_scope as _visibility_scope,
    apply_visibility as _apply_visibility,
    in_scope as _in_scope,
    out_of_scope_message,
)
from app.core.constants import REVIEW_VERDICTS
from app.models.session import UserSession
from app.models.user import User
from app.models.role import Role
from app.models.anomaly import AnomalyAlert
from app.models.live_alert import LiveAlert, LiveSessionScore
from app.services import anomaly_service, attack_simulation_service, live_detection_service, session_service
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
    LiveAlertOut,
    LiveScoreOut,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

OVERDUE_HOURS = 24


# Visibility (who sees which sessions, alerts and audit entries) comes from each role's
# scope column -- global / school / department / organization / own -- not from role
# names. See app/core/visibility.py. Administrator (global), Manager (department) and
# Standard User (own) behave exactly as before; the DSFS roles now get their own scopes.


def _refuse_out_of_scope(db: Session, current, kind: str, scope: dict, action: str, endpoint: str):
    # A record outside the caller's scope: refused, and counted by live detection (R1).
    _, session_id = current
    live_detection_service.on_denied(db, session_id, "dashboard", action, endpoint=endpoint, reason="visibility")
    raise HTTPException(status_code=403, detail=out_of_scope_message(kind, scope))


def _assert_alert_in_scope(alert: AnomalyAlert, scope: dict, db: Session, current, action: str, endpoint: str):
    session = alert.session
    user = session.user if session else None
    if not _in_scope(user, scope):
        _refuse_out_of_scope(db, current, "alert", scope, action, endpoint)


def _assert_session_in_scope(session: UserSession, scope: dict, db: Session, current, action: str, endpoint: str):
    user = session.user
    if not _in_scope(user, scope):
        _refuse_out_of_scope(db, current, "session", scope, action, endpoint)


def _build_live_alert_out(alert: LiveAlert) -> LiveAlertOut:
    session = alert.session
    user = session.user if session else None
    return LiveAlertOut(
        live_alert_id=alert.id,
        session_id=alert.session_id,
        user_id=alert.user_id,
        username=user.username if user else "unknown",
        department=user.department if user else None,
        rule=alert.rule,
        severity=alert.severity,
        status=alert.status,
        summary=alert.summary,
        hit_count=alert.hit_count,
        is_learning=alert.is_learning,
        first_seen_at=alert.first_seen_at,
        last_seen_at=alert.last_seen_at,
        evidence=json.loads(alert.evidence_json) if alert.evidence_json else [],
        session_active=(session.logout_time is None and not session.terminated) if session else False,
        session_terminated=session.terminated if session else False,
        resolved_by=alert.resolved_by,
        resolved_at=alert.resolved_at,
    )


def _build_live_score_out(score: LiveSessionScore) -> LiveScoreOut:
    return LiveScoreOut(
        scored_at=score.scored_at,
        anomaly_score=score.anomaly_score,
        peak_score=score.peak_score,
        threshold_used=score.threshold_used,
        risk_tier=score.risk_tier,
        is_learning=score.is_learning,
        n_events=score.n_events,
        elapsed_sec=score.elapsed_sec,
        flagged=score.anomaly_score >= score.threshold_used,
        shap_contributions=json.loads(score.shap_values_json) if score.shap_values_json else [],
    )


def _is_overdue(alert: AnomalyAlert) -> bool:
    if not alert.is_anomaly or alert.review_verdict is not None:
        return False
    return (datetime.utcnow() - alert.alert_timestamp) > timedelta(hours=OVERDUE_HOURS)


def _auto_close_stale_sessions(db: Session):
    session_service.close_stale_sessions(db, settings.ACCESS_TOKEN_EXPIRE_MINUTES)


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

    # "Today" starts at local midnight, converted to UTC because alerts are stored in UTC.
    today_start = to_utc(local_now().replace(hour=0, minute=0, second=0, microsecond=0))
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


def _build_alert_detail(alert: AnomalyAlert, db: Session) -> AnomalyAlertDetail:
    session = alert.session
    user = session.user if session else None
    features = json.loads(alert.features_json) if alert.features_json else {}
    shap_contributions = json.loads(alert.shap_values_json) if alert.shap_values_json else []
    live_alerts = (
        db.query(LiveAlert)
        .filter(LiveAlert.session_id == alert.session_id)
        .order_by(LiveAlert.first_seen_at)
        .all()
    )
    live_score = db.query(LiveSessionScore).filter(LiveSessionScore.session_id == alert.session_id).first()

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
        threshold_used=alert.threshold_used,
        risk_tier=alert.risk_tier,
        is_learning=alert.is_learning,
        prior_sessions=alert.prior_sessions,
        live_alerts=[_build_live_alert_out(a) for a in live_alerts],
        live_score=_build_live_score_out(live_score) if live_score else None,
    )


@router.get("/alerts/{alert_id}", response_model=AnomalyAlertDetail)
def get_alert_detail(
    alert_id: int,
    current_user: User = Depends(require_permission("dashboard", "read")),
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    _assert_alert_in_scope(alert, _visibility_scope(current_user), db, current,
                           "read", f"GET /api/dashboard/alerts/{alert_id}")
    return _build_alert_detail(alert, db)


@router.patch("/alerts/{alert_id}", response_model=AnomalyAlertDetail)
def update_alert(
    alert_id: int,
    payload: AlertReviewUpdate,
    current_user=Depends(require_permission("dashboard", "write")),
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    _assert_alert_in_scope(alert, _visibility_scope(current_user), db, current,
                           "write", f"PATCH /api/dashboard/alerts/{alert_id}")

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
    return _build_alert_detail(alert, db)


@router.post("/sessions/{session_id}/terminate", response_model=TerminateSessionResult)
def terminate_session(
    session_id: int,
    current_user: User = Depends(require_permission("dashboard", "write")),
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    _assert_session_in_scope(session, _visibility_scope(current_user), db, current,
                             "write", f"POST /api/dashboard/sessions/{session_id}/terminate")

    was_active = session.logout_time is None
    session.terminated = True
    if was_active:
        session.logout_time = datetime.utcnow()
        session.session_duration = (session.logout_time - session.login_time).total_seconds()
    live_detection_service.resolve_for_terminated_session(db, session.session_id, current_user.user_id)

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
    live_rules_by_session = defaultdict(list)
    if session_ids:
        alerts_by_session = {
            a.session_id: a
            for a in db.query(AnomalyAlert).filter(AnomalyAlert.session_id.in_(session_ids)).all()
        }
        open_live = (
            db.query(LiveAlert.session_id, LiveAlert.rule)
            .filter(LiveAlert.session_id.in_(session_ids), LiveAlert.status == "open")
            .all()
        )
        for sid, rule in open_live:
            live_rules_by_session[sid].append(rule)

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
                live_rules=sorted(live_rules_by_session.get(s.session_id, [])),
            )
        )
    return results


# Live (mid-session) detection: early warnings while a session is still active.
# See app/services/live_detection_service.py.

@router.get("/live-alerts", response_model=List[LiveAlertOut])
def list_live_alerts(
    status: str = Query("open", pattern="^(open|all)$"),
    # audit=False: the panel polls this every few seconds, and polling must not count as the
    # administrator's own activity in the anomaly model's features.
    current_user: User = Depends(require_permission("dashboard", "read", audit=False)),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)
    query = (
        db.query(LiveAlert)
        .join(UserSession, LiveAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
    )
    query = _apply_visibility(query, scope)
    if status == "open":
        query = query.filter(LiveAlert.status == "open")
    alerts = query.order_by(LiveAlert.last_seen_at.desc()).limit(200).all()
    return [_build_live_alert_out(a) for a in alerts]


@router.post("/live-alerts/{live_alert_id}/dismiss", response_model=LiveAlertOut)
def dismiss_live_alert(
    live_alert_id: int,
    current_user: User = Depends(require_permission("dashboard", "write")),
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    alert = db.query(LiveAlert).filter(LiveAlert.id == live_alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Live alert not found")
    user = alert.session.user if alert.session else None
    scope = _visibility_scope(current_user)
    if not _in_scope(user, scope):
        _refuse_out_of_scope(db, current, "alert", scope, "write",
                             f"POST /api/dashboard/live-alerts/{live_alert_id}/dismiss")

    if alert.status == "open":
        alert.status = "dismissed"
        alert.resolved_by = current_user.user_id
        alert.resolved_at = datetime.utcnow()
        db.commit()
        db.refresh(alert)
    return _build_live_alert_out(alert)


@router.get("/charts/alerts-over-time")
def alerts_over_time(
    days: int = Query(14, ge=1, le=90),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)
    # Days are local calendar days; the filter compares with stored UTC times.
    start = (local_now() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    query = (
        db.query(AnomalyAlert)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .join(User, UserSession.user_id == User.user_id)
        .filter(AnomalyAlert.is_anomaly.is_(True), AnomalyAlert.alert_timestamp >= to_utc(start))
    )
    query = _apply_visibility(query, scope)

    counts = defaultdict(int)
    for a in query.all():
        counts[to_local(a.alert_timestamp).date().isoformat()] += 1

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
    # Days are local calendar days; the filter compares with stored UTC times.
    start = (local_now() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    query = db.query(UserSession).join(User, UserSession.user_id == User.user_id).filter(
        UserSession.login_time >= to_utc(start)
    )
    query = _apply_visibility(query, scope)

    counts = defaultdict(int)
    for s in query.all():
        counts[to_local(s.login_time).date().isoformat()] += 1

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