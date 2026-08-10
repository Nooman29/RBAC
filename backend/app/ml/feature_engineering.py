"""
Feature engineering for the live Isolation Forest anomaly scorer.

Grain: one row per SESSION (not per user-day, unlike the CERT offline
notebook). The live schema only gives us session-level and access-log-level
data, and session volume per user will be far lower than CERT's daily logs,
so per-session is the natural, honest grain here.

This module is imported by BOTH:
    - scripts/train_isolation_forest.py   (offline training)
    - app/services/anomaly_service.py     (live scoring)
so training and inference are guaranteed to build features identically.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.models.session import UserSession, AccessLog

# Raw per-session features, computed directly from one session + its access logs
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

# Subset of raw features we ALSO express as a per-user z-score — i.e. how far
# this session deviates from THAT user's own historical average. This is what
# catches "this user is behaving unlike themselves", as opposed to just
# "this user does more stuff than other users" (which would unfairly flag
# naturally high-activity roles, e.g. admins — same issue the CERT notebook
# called out in Pipeline v2).
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
    """Raw (non-zscore) features for a single, already-closed session."""
    login_time: datetime = session.login_time
    hour = login_time.hour
    weekday = login_time.weekday()  # 5, 6 = Sat, Sun

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

    # Has this user ever logged in from this IP before this session?
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
    db: DBSession, user_id: int, exclude_session_id: Optional[int] = None
) -> dict:
    """
    Mean/std of each ZSCORE_SOURCE_COLUMNS raw feature across this user's
    OTHER closed sessions (leave-one-out for the session being scored or
    trained on). Turns a raw count into "how unusual is this for THIS user".
    """
    query = db.query(UserSession).filter(
        UserSession.user_id == user_id, UserSession.session_duration.isnot(None)
    )
    if exclude_session_id is not None:
        query = query.filter(UserSession.session_id != exclude_session_id)

    other_sessions = query.all()

    if not other_sessions:
        # No history yet (e.g. this is the user's very first session) —
        # z-scores default to 0 rather than dividing by nothing.
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


def build_session_feature_vector(db: DBSession, session: UserSession) -> dict:
    """
    Full feature dict for one session, keyed exactly by FEATURE_COLUMNS.
    This is the single function both training and live scoring call.
    """
    raw = build_raw_session_features(db, session)
    stats = build_user_history_stats(db, session.user_id, exclude_session_id=session.session_id)

    features = dict(raw)
    for col in ZSCORE_SOURCE_COLUMNS:
        mean = stats[f"{col}_mean"]
        std = stats[f"{col}_std"]
        features[f"{col}_zscore"] = (raw[col] - mean) / (std + 1e-6)

    # Guarantee consistent column ordering downstream (scaler/model expect it)
    return {col: features[col] for col in FEATURE_COLUMNS}