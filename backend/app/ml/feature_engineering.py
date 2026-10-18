"""
Feature engineering for the live Isolation Forest anomaly scorer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.models.session import UserSession, AccessLog

from sqlalchemy import and_, or_
from app.models.anomaly import AnomalyAlert

RAW_FEATURE_COLUMNS = [
    "login_hour",
    "is_offhours",
    "is_weekend",
    "session_duration_sec",
    "n_access_events",
    "distinct_resources",
    "distinct_actions",
    "n_read",
    "n_write",
    "n_delete",
    "new_ip",
]

ZSCORE_SOURCE_COLUMNS = [
    "session_duration_sec",
    "n_access_events",
    "distinct_resources",
    "n_write",
    "n_delete",
]

FEATURE_COLUMNS = RAW_FEATURE_COLUMNS + [f"{c}_zscore" for c in ZSCORE_SOURCE_COLUMNS]

# --- z-score hardening -------------------------------------------------------------------------
# A personal z-score only means something once a user has a history to compare against, and a very
# uniform history must not turn a one-unit difference into a z-score in the millions.
MIN_HISTORY_FOR_ZSCORE = 5      # normal sessions needed before personal z-scores are used
RELATIVE_STD_FLOOR = 0.10       # standard deviation is never below 10% of the user's average
Z_CLIP = 10.0                   # z-scores are clamped to [-Z_CLIP, +Z_CLIP]
MIN_STD = {                     # absolute floor per feature (in the feature's own units)
    "session_duration_sec": 60.0,
    "n_access_events": 1.0,
    "distinct_resources": 0.5,
    "n_write": 0.5,
    "n_delete": 0.5,
}


def _offhours(hour: int) -> int:
    return int(hour < 7 or hour > 19)


def _zscore(value: float, mean: float, std: float, floor: float) -> float:
    scale = max(std, RELATIVE_STD_FLOOR * abs(mean), floor)
    z = (value - mean) / scale
    return max(-Z_CLIP, min(Z_CLIP, z))


def build_raw_session_features(db: DBSession, session: UserSession) -> dict:
    login_time: datetime = session.login_time
    hour = login_time.hour
    weekday = login_time.weekday()

    logs = (
        db.query(AccessLog)
        .filter(AccessLog.session_id == session.session_id)
        .all()
    )

    resources = {l.resource_name for l in logs}
    actions = {l.action_performed for l in logs}
    n_read = sum(1 for l in logs if l.action_performed == "read")
    n_write = sum(1 for l in logs if l.action_performed == "write")
    n_delete = sum(1 for l in logs if l.action_performed == "delete")

    prior_locations = {
        loc
        for (loc,) in db.query(UserSession.access_location)
        .filter(
            UserSession.user_id == session.user_id,
            UserSession.session_id != session.session_id,
            UserSession.login_time < session.login_time,
        )
        .all()
        if loc
    }
    new_ip = int(bool(session.access_location) and session.access_location not in prior_locations)

    duration = session.session_duration if session.session_duration is not None else 0.0

    return {
        "login_hour": hour,
        "is_offhours": _offhours(hour),
        "is_weekend": int(weekday >= 5),
        "session_duration_sec": duration,
        "n_access_events": len(logs),
        "distinct_resources": len(resources),
        "distinct_actions": len(actions),
        "n_read": n_read,
        "n_write": n_write,
        "n_delete": n_delete,
        "new_ip": new_ip,
    }


def build_user_history_stats(
    db: DBSession,
    user_id: int,
    exclude_session_id: Optional[int] = None,
    include_simulated: bool = False,
) -> dict:
    """
    Mean/std of each ZSCORE_SOURCE_COLUMNS raw feature across this user's
    OTHER closed sessions, plus n_sessions (how many sessions that is).

    Simulated attack sessions never count toward a baseline (include_simulated
    is kept only for older callers and defaults to False).

    A session counts toward "normal" behavior only if:
      - it was never scored, or
      - it was scored normal AND an administrator has not confirmed it as a threat, or
      - an administrator cleared it as a false positive or authorized exception.
    A flagged session that is unreviewed, and ANY session confirmed as a threat
    (including one the model let through), never counts. This keeps an attack, however
    it was discovered, from teaching the model to treat it as normal.
    """
    query = (
        db.query(UserSession)
        .outerjoin(AnomalyAlert, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.user_id == user_id,
            UserSession.session_duration.isnot(None),
        )
    )
    if not include_simulated:
        query = query.filter(UserSession.simulated_scenario.is_(None))
    if exclude_session_id is not None:
        query = query.filter(UserSession.session_id != exclude_session_id)

    query = query.filter(
        or_(
            AnomalyAlert.alert_id.is_(None),
            and_(
                AnomalyAlert.is_anomaly.is_(False),
                or_(
                    AnomalyAlert.review_verdict.is_(None),
                    AnomalyAlert.review_verdict != "confirmed_threat",
                ),
            ),
            AnomalyAlert.review_verdict.in_(["false_positive", "authorized_exception"]),
        )
    )

    other_sessions = query.all()

    if not other_sessions:
        stats = {f"{c}_mean": 0.0 for c in ZSCORE_SOURCE_COLUMNS}
        stats.update({f"{c}_std": 0.0 for c in ZSCORE_SOURCE_COLUMNS})
        stats["n_sessions"] = 0
        return stats

    raw_rows = [build_raw_session_features(db, s) for s in other_sessions]

    stats = {"n_sessions": len(other_sessions)}
    for col in ZSCORE_SOURCE_COLUMNS:
        values = [r[col] for r in raw_rows]
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        std = variance ** 0.5
        stats[f"{col}_mean"] = mean
        stats[f"{col}_std"] = std

    return stats


def build_session_feature_vector(
    db: DBSession, session: UserSession, include_simulated_in_baseline: bool = False
) -> dict:
    """
    Full feature dict for one session, keyed exactly by FEATURE_COLUMNS.

    Personal z-scores are neutral (0.0) until the user has MIN_HISTORY_FOR_ZSCORE normal sessions,
    use a floored standard deviation, and are clamped to +/- Z_CLIP.
    """
    raw = build_raw_session_features(db, session)
    stats = build_user_history_stats(
        db, session.user_id, exclude_session_id=session.session_id,
        include_simulated=include_simulated_in_baseline,
    )
    enough_history = stats["n_sessions"] >= MIN_HISTORY_FOR_ZSCORE

    features = dict(raw)
    for col in ZSCORE_SOURCE_COLUMNS:
        if enough_history:
            features[f"{col}_zscore"] = _zscore(
                raw[col], stats[f"{col}_mean"], stats[f"{col}_std"], MIN_STD[col]
            )
        else:
            features[f"{col}_zscore"] = 0.0

    return {col: features[col] for col in FEATURE_COLUMNS}