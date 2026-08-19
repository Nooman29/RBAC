"""
Feature engineering for the live Isolation Forest anomaly scorer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.models.session import UserSession, AccessLog

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


def _offhours(hour: int) -> int:
    return int(hour < 7 or hour > 19)


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
    OTHER closed sessions.

    include_simulated=False (default, production behavior): simulated attack
    sessions are excluded, so a user's baseline always reflects genuine
    historical behavior only.

    include_simulated=True: used ONLY by the attack-simulation demo tool's
    "naive" mode, to intentionally reproduce a baseline that gets polluted by
    repeated simulated sessions — used to demonstrate why the exclusion above
    is necessary. Never used in the normal scoring path.
    """
    query = db.query(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.session_duration.isnot(None),
    )
    if not include_simulated:
        query = query.filter(UserSession.simulated_scenario.is_(None))
    if exclude_session_id is not None:
        query = query.filter(UserSession.session_id != exclude_session_id)

    other_sessions = query.all()

    if not other_sessions:
        stats = {f"{c}_mean": 0.0 for c in ZSCORE_SOURCE_COLUMNS}
        stats.update({f"{c}_std": 0.0 for c in ZSCORE_SOURCE_COLUMNS})
        return stats

    raw_rows = [build_raw_session_features(db, s) for s in other_sessions]

    stats = {}
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
    include_simulated_in_baseline is only ever True when called from the
    attack-simulation demo tool's "naive" mode.
    """
    raw = build_raw_session_features(db, session)
    stats = build_user_history_stats(
        db, session.user_id, exclude_session_id=session.session_id,
        include_simulated=include_simulated_in_baseline,
    )

    features = dict(raw)
    for col in ZSCORE_SOURCE_COLUMNS:
        mean = stats[f"{col}_mean"]
        std = stats[f"{col}_std"]
        features[f"{col}_zscore"] = (raw[col] - mean) / (std + 1e-6)

    return {col: features[col] for col in FEATURE_COLUMNS}