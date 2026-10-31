"""
Live (mid-session) detection: checks that run on each activity event while a session is
still active, so an administrator can terminate it in time.

Three layers:
  1. Rules (R1-R4) catch known warning signs on the event that shows them.
  2. The Isolation Forest scores the session so far (R5, provisional), at most once per
     model_interval_sec after a warm-up, to catch unusual combinations no single rule names.
  3. The end-of-session score (anomaly_service.score_session) stays the official verdict,
     and administrator verdicts on it feed back into R4.

Rules:
  R1 out_of_scope            a module reports a write/approve/export the user had no permission
                             for (immediate), or several refused requests in a short window
  R2 destructive_burst       many deletes/exports in a short window (stricter for high-risk roles)
  R3 unusual_hour            activity at an hour this user is never active; users in their
                             learning period fall back to the model's own off-hours rule
  R4 confirmed_threat_pattern the session so far trips every indicator of a pattern an
                             administrator confirmed as a threat for this user
  R5 model_provisional       the live model score of the session so far is above the tier threshold

R4 is safe mid-session because every signature indicator is either fixed at login (off-hours,
weekend, new IP) or grows with activity (write/delete/volume/variety counts): an indicator set
now is still set at logout. Duration is not part of the signature.

Nothing here writes access_logs or anomaly_alerts, so the model's features, baselines and
retraining are unchanged. Live alerts are one row per (session, rule); repeat hits update it,
and recipients are notified only when it is first raised. Every public entry point catches its
own errors: live detection can never fail the request that triggered it.

Times are stored and compared as naive UTC; clock hours (R3) are read in the programme's local
time zone (app.core.business_time), the same way the model's features read them.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Iterable, Optional

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from app.core.business_time import to_local, tz_label
from app.core.dsfs_catalog import LIVE_DETECTION
from app.ml.feature_engineering import (
    FEATURE_COLUMNS,
    MIN_HISTORY_FOR_ZSCORE,
    _offhours,
    build_session_feature_vector,
    counts_as_normal_behaviour,
)
from app.models.anomaly import AnomalyAlert
from app.models.live_alert import DeniedAttempt, LiveAlert, LiveSessionScore
from app.models import service_client  # noqa: F401  (module_events has a foreign key to service_clients)
from app.models.module_event import ModuleEvent
from app.models.notification import Notification
from app.models.session import AccessLog, UserSession
from app.services import anomaly_service, notification_service

logger = logging.getLogger(__name__)

RULE_OUT_OF_SCOPE = "out_of_scope"
RULE_BURST = "destructive_burst"
RULE_UNUSUAL_HOUR = "unusual_hour"
RULE_CONFIRMED_PATTERN = "confirmed_threat_pattern"
RULE_MODEL = "model_provisional"

RULE_LABELS = {
    RULE_OUT_OF_SCOPE: "Action outside the user's access",
    RULE_BURST: "Burst of deletions/exports",
    RULE_UNUSUAL_HOUR: "Unusual hour for this user",
    RULE_CONFIRMED_PATTERN: "Repeat of a confirmed threat pattern",
    RULE_MODEL: "Model (provisional)",
}

STATUS_OPEN = "open"
STATUS_DISMISSED = "dismissed"
STATUS_TERMINATED = "terminated"

SEVERITY_ORDER = ["low", "medium", "high"]
MAX_EVIDENCE = 20                                  # evidence entries kept per live alert
UNPERMITTED_ACTIONS = {"write", "approve", "export"}  # module actions that change or take data


# --- entry points (called from the request path) ------------------------------------------------

def on_access(db: DBSession, session_id: int, now: Optional[datetime] = None) -> None:
    """An allowed, audited request was just logged for this session."""
    try:
        session = _open_session(db, session_id)
        if session is not None:
            _run_activity_checks(db, session, now or datetime.utcnow())
    except Exception:
        db.rollback()
        logger.exception("Live detection failed for session_id=%s", session_id)


def on_denied(
    db: DBSession,
    session_id: int,
    resource_name: str,
    action_type: str,
    endpoint: Optional[str] = None,
    reason: str = "permission",
    now: Optional[datetime] = None,
) -> None:
    """A request in this session was refused (missing permission or record out of scope)."""
    try:
        session = _open_session(db, session_id)
        if session is None:
            return
        now = now or datetime.utcnow()
        _record_denied(db, session, resource_name, action_type, endpoint, reason, now)
        _check_denied_attempts(db, session, now)
    except Exception:
        db.rollback()
        logger.exception("Live detection (denied request) failed for session_id=%s", session_id)


def on_module_events(
    db: DBSession, session_id: int, events: Iterable[ModuleEvent], now: Optional[datetime] = None
) -> None:
    """A DSFS module reported activity for this session (already committed)."""
    try:
        session = _open_session(db, session_id)
        if session is None:
            return
        now = now or datetime.utcnow()
        for event in events:
            if event.permitted:
                continue
            if event.action_type in UNPERMITTED_ACTIONS:
                _raise_alert(
                    db, session, RULE_OUT_OF_SCOPE, "high",
                    f"Module reported '{event.action_type}' on {event.resource_name} without permission",
                    {"at": _iso(now), "resource": event.resource_name, "action": event.action_type,
                     "entity_ref": event.entity_ref, "source": "module"},
                    now,
                )
            else:
                _record_denied(db, session, event.resource_name, event.action_type,
                               "POST /api/v1/events", "module", now)
                _check_denied_attempts(db, session, now)
        _run_activity_checks(db, session, now)
    except Exception:
        db.rollback()
        logger.exception("Live detection (module events) failed for session_id=%s", session_id)


# --- housekeeping used by routes -----------------------------------------------------------------

def resolve_for_terminated_session(
    db: DBSession, session_id: int, admin_id: int, now: Optional[datetime] = None
) -> None:
    """Marks the session's open live alerts as handled by termination. The caller commits."""
    db.query(LiveAlert).filter(
        LiveAlert.session_id == session_id, LiveAlert.status == STATUS_OPEN
    ).update(
        {"status": STATUS_TERMINATED, "resolved_by": admin_id, "resolved_at": now or datetime.utcnow()},
        synchronize_session=False,
    )


def delete_for_sessions(db: DBSession, session_ids: list) -> None:
    """Removes live-detection rows for sessions about to be deleted. The caller commits."""
    if not session_ids:
        return
    live_ids = [a.id for a in db.query(LiveAlert.id).filter(LiveAlert.session_id.in_(session_ids)).all()]
    if live_ids:
        db.query(Notification).filter(Notification.live_alert_id.in_(live_ids)).delete(synchronize_session=False)
        db.query(LiveAlert).filter(LiveAlert.id.in_(live_ids)).delete(synchronize_session=False)
    db.query(LiveSessionScore).filter(LiveSessionScore.session_id.in_(session_ids)).delete(synchronize_session=False)
    db.query(DeniedAttempt).filter(DeniedAttempt.session_id.in_(session_ids)).delete(synchronize_session=False)


# --- shared helpers ------------------------------------------------------------------------------

def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat()


def _open_session(db: DBSession, session_id: int) -> Optional[UserSession]:
    session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if session is None or session.logout_time is not None or session.terminated:
        return None
    if session.simulated_scenario is not None:
        return None
    return session


def _raise_alert(
    db: DBSession,
    session: UserSession,
    rule: str,
    severity: str,
    summary: str,
    evidence: dict,
    now: datetime,
    is_learning: Optional[bool] = None,
) -> LiveAlert:
    """Creates the (session, rule) live alert and notifies, or records a repeat hit on it."""
    alert = (
        db.query(LiveAlert)
        .filter(LiveAlert.session_id == session.session_id, LiveAlert.rule == rule)
        .first()
    )
    if alert is None:
        alert = LiveAlert(
            session_id=session.session_id,
            user_id=session.user_id,
            rule=rule,
            severity=severity,
            status=STATUS_OPEN,
            summary=summary[:300],
            evidence_json=json.dumps([evidence]),
            hit_count=1,
            is_learning=is_learning,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(alert)
        try:
            db.commit()
        except IntegrityError:
            # A concurrent request raised the same rule first: count this as a repeat hit.
            db.rollback()
            alert = (
                db.query(LiveAlert)
                .filter(LiveAlert.session_id == session.session_id, LiveAlert.rule == rule)
                .one()
            )
        else:
            db.refresh(alert)
            logger.info("Live alert raised: rule=%s session_id=%s user_id=%s", rule, session.session_id, session.user_id)
            try:
                notification_service.notify_live_alert(db, alert, RULE_LABELS.get(rule, rule))
            except Exception:
                db.rollback()
                logger.exception("Failed to notify for live_alert_id=%s", alert.id)
            return alert

    # Repeat hit: a dismissed alert stays dismissed; nobody is notified again.
    alert.hit_count += 1
    alert.last_seen_at = now
    alert.summary = summary[:300]
    if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(alert.severity):
        alert.severity = severity
    if is_learning is not None:
        alert.is_learning = is_learning
    items = json.loads(alert.evidence_json) if alert.evidence_json else []
    items.append(evidence)
    alert.evidence_json = json.dumps(items[-MAX_EVIDENCE:])
    db.commit()
    return alert


def _run_activity_checks(db: DBSession, session: UserSession, now: datetime) -> None:
    tier = anomaly_service._user_risk_tier(session)
    elapsed = max(0.0, (now - session.login_time).total_seconds())
    cache = {}

    def features() -> dict:
        # Built at most once per event and shared by R4 and R5.
        if "features" not in cache:
            cache["features"] = build_session_feature_vector(db, session, live_duration_sec=elapsed)
        return cache["features"]

    checks = (
        (RULE_BURST, lambda: _check_burst(db, session, tier, now)),
        (RULE_UNUSUAL_HOUR, lambda: _check_unusual_hour(db, session, now)),
        (RULE_CONFIRMED_PATTERN, lambda: _check_confirmed_pattern(db, session, features, now)),
        (RULE_MODEL, lambda: _check_model(db, session, features, elapsed, now)),
    )
    for rule, check in checks:
        # One failing check never stops the others.
        try:
            check()
        except Exception:
            db.rollback()
            logger.exception("Live check %s failed for session_id=%s", rule, session.session_id)


# --- R1 out_of_scope -----------------------------------------------------------------------------

def _record_denied(db, session, resource_name, action_type, endpoint, reason, now) -> None:
    db.add(
        DeniedAttempt(
            session_id=session.session_id,
            user_id=session.user_id,
            resource_name=resource_name[:100],
            action_type=action_type[:20],
            endpoint=endpoint[:200] if endpoint else None,
            reason=reason,
            created_at=now,
        )
    )
    db.commit()


def _check_denied_attempts(db: DBSession, session: UserSession, now: datetime) -> None:
    limit = LIVE_DETECTION["denied_attempts"]
    window = LIVE_DETECTION["denied_window_sec"]
    rows = (
        db.query(DeniedAttempt)
        .filter(
            DeniedAttempt.session_id == session.session_id,
            DeniedAttempt.created_at >= now - timedelta(seconds=window),
            DeniedAttempt.created_at <= now,
        )
        .order_by(DeniedAttempt.created_at)
        .all()
    )
    if len(rows) < limit:
        return
    _raise_alert(
        db, session, RULE_OUT_OF_SCOPE, "medium",
        f"{len(rows)} refused requests in {window // 60} min",
        {"at": _iso(now), "count": len(rows),
         "recent": [f"{r.action_type} {r.resource_name} ({r.reason})" for r in rows[-5:]]},
        now,
    )


# --- R2 destructive_burst ------------------------------------------------------------------------

def _check_burst(db: DBSession, session: UserSession, tier: str, now: datetime) -> None:
    window = LIVE_DETECTION["burst_window_sec"]
    limit = LIVE_DETECTION["burst_count"].get(tier, LIVE_DETECTION["burst_count"]["standard"])
    since = now - timedelta(seconds=window)

    logs = db.query(AccessLog).filter(
        AccessLog.session_id == session.session_id,
        AccessLog.access_timestamp >= since,
        AccessLog.access_timestamp <= now,
    )
    # No route is guarded by a "delete" permission (DELETE /api/users/{id} needs user:write),
    # so deletions are recognised by the HTTP method recorded on the audit row.
    deletes = logs.filter(
        or_(AccessLog.endpoint.like("DELETE %"), AccessLog.action_performed == "delete")
    ).count()
    # Module exports are mapped to "read" in access_logs; the raw action is in module_events.
    exports = logs.filter(AccessLog.endpoint.like("%/export")).count()
    exports += db.query(ModuleEvent).filter(
        ModuleEvent.session_id == session.session_id,
        ModuleEvent.action_type == "export",
        ModuleEvent.created_at >= since,
        ModuleEvent.created_at <= now,
    ).count()

    if deletes + exports < limit:
        return
    _raise_alert(
        db, session, RULE_BURST, "high",
        f"{deletes} deletion(s) and {exports} export(s) in {window // 60} min (limit {limit}, {tier} tier)",
        {"at": _iso(now), "deletes": deletes, "exports": exports, "limit": limit, "risk_tier": tier},
        now,
    )


# --- R3 unusual_hour -----------------------------------------------------------------------------

def _clean_prior_sessions(db: DBSession, session: UserSession):
    """
    The user's earlier closed, non-simulated sessions that count as normal behaviour
    (feature_engineering.counts_as_normal_behaviour, the same rule as the z-score baseline), so
    a flagged-unreviewed or confirmed-threat session never makes its hours look "usual".
    """
    return (
        db.query(UserSession.login_time, UserSession.logout_time)
        .outerjoin(AnomalyAlert, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.user_id == session.user_id,
            UserSession.session_id != session.session_id,
            UserSession.session_duration.isnot(None),
            UserSession.simulated_scenario.is_(None),
            UserSession.login_time < session.login_time,
            counts_as_normal_behaviour(),
        )
        .all()
    )


def _active_hours(rows) -> set:
    """Every LOCAL clock hour covered by at least one of the sessions (login to logout)."""
    hours = set()
    for login_time, logout_time in rows:
        end = to_local(logout_time or login_time)
        t = to_local(login_time).replace(minute=0, second=0, microsecond=0)
        steps = 0
        while t <= end and steps < 24:
            hours.add(t.hour)
            t += timedelta(hours=1)
            steps += 1
    return hours


def _check_unusual_hour(db: DBSession, session: UserSession, now: datetime) -> None:
    hour = to_local(now).hour
    zone = tz_label()
    rows = _clean_prior_sessions(db, session)
    n_prior = len(rows)

    if n_prior >= MIN_HISTORY_FOR_ZSCORE:
        margin = LIVE_DETECTION["unusual_hour_margin"]
        usual = {(h + d) % 24 for h in _active_hours(rows) for d in range(-margin, margin + 1)}
        if hour in usual:
            return
        is_learning = False
        summary = f"Active at {hour:02d}:00 {zone}, outside this user's usual hours"
        evidence = {"at": _iso(now), "hour": hour, "usual_hours": sorted(usual), "prior_sessions": n_prior}
    else:
        # Learning period: no personal pattern yet, so use the same off-hours rule as the model.
        # Nothing is relaxed; the alert says the personal baseline was not ready.
        if not _offhours(hour):
            return
        is_learning = True
        summary = f"Active at {hour:02d}:00 {zone}, outside business hours (learning period)"
        evidence = {"at": _iso(now), "hour": hour, "prior_sessions": n_prior}

    _raise_alert(db, session, RULE_UNUSUAL_HOUR, "low", summary, evidence, now, is_learning=is_learning)


# --- R4 confirmed_threat_pattern -----------------------------------------------------------------

def _confirmed_precedents(db: DBSession, session: UserSession) -> list:
    rows = (
        db.query(AnomalyAlert.pattern_signature)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.user_id == session.user_id,
            AnomalyAlert.session_id != session.session_id,
            AnomalyAlert.review_verdict == anomaly_service.CONFIRMED_THREAT,
            AnomalyAlert.pattern_signature.isnot(None),
        )
        .all()
    )
    precedents = [anomaly_service._signature_flags(signature) for (signature,) in rows]
    return [flags for flags in precedents if flags]


def _check_confirmed_pattern(db: DBSession, session: UserSession, features, now: datetime) -> None:
    precedents = _confirmed_precedents(db, session)
    if not precedents:
        return  # cheap exit: no feature building for users without confirmed threats
    current = anomaly_service._signature_flags(anomaly_service._compute_pattern_signature(features()))
    matches = [flags for flags in precedents if flags <= current]
    if not matches:
        return
    matched = sorted(max(matches, key=len))
    _raise_alert(
        db, session, RULE_CONFIRMED_PATTERN, "high",
        f"Repeats a pattern confirmed as a threat: {', '.join(matched)}",
        {"at": _iso(now), "matched": "|".join(matched), "current": "|".join(sorted(current))},
        now,
    )


# --- R5 model_provisional ------------------------------------------------------------------------

def _check_model(db: DBSession, session: UserSession, features, elapsed: float, now: datetime) -> None:
    n_events = db.query(AccessLog).filter(AccessLog.session_id == session.session_id).count()
    # Warm-up: a session's first minutes look unusual simply because they are short.
    if n_events < LIVE_DETECTION["model_min_events"] and elapsed < LIVE_DETECTION["model_min_elapsed_sec"]:
        return

    previous = db.query(LiveSessionScore).filter(LiveSessionScore.session_id == session.session_id).first()
    if previous is not None and (now - previous.scored_at).total_seconds() < LIVE_DETECTION["model_interval_sec"]:
        return

    if not anomaly_service._load_artifacts():
        return

    # The same model, scaler, tier threshold and SHAP explainer as end-of-session scoring.
    feature_values = features()
    scaled = anomaly_service._scaler.transform([[feature_values[col] for col in FEATURE_COLUMNS]])
    score = float(-anomaly_service._model.score_samples(scaled)[0])
    risk_tier = anomaly_service._user_risk_tier(session)
    threshold = anomaly_service._threshold_for_tier(risk_tier)
    is_learning = anomaly_service._count_prior_sessions(db, session) < MIN_HISTORY_FOR_ZSCORE
    contributions = anomaly_service._compute_shap_contributions(scaled)

    if previous is None:
        previous = LiveSessionScore(session_id=session.session_id, peak_score=score)
        db.add(previous)
    previous.scored_at = now
    previous.anomaly_score = score
    previous.peak_score = max(previous.peak_score, score)
    previous.threshold_used = threshold
    previous.risk_tier = risk_tier
    previous.is_learning = is_learning
    previous.n_events = n_events
    previous.elapsed_sec = elapsed
    previous.shap_values_json = json.dumps(contributions) if contributions is not None else None
    db.commit()

    if score < threshold:
        return
    _raise_alert(
        db, session, RULE_MODEL, "high",
        f"Model score {score:.3f} is above the {risk_tier}-tier threshold {threshold:.3f} after "
        f"{n_events} action(s) in {int(elapsed // 60)} min (provisional)",
        {"at": _iso(now), "score": score, "threshold": threshold, "risk_tier": risk_tier,
         "n_events": n_events, "elapsed_sec": elapsed,
         "top_features": (contributions or [])[:3]},
        now,
        is_learning=is_learning,
    )
