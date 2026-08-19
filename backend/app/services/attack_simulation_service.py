"""
Live attack simulation for demo purposes.
"""

from __future__ import annotations

import random 
from datetime import datetime, timedelta
from sqlalchemy.orm import Session as DBSession

from app.models.session import UserSession, AccessLog
from app.models.user import User
from app.models.anomaly import AnomalyAlert
from app.models.notification import Notification
from app.services import anomaly_service

RESOURCES = ["dashboard", "role", "user"]
ACTIONS = ["read", "write", "delete"]


SCENARIOS = {
    "offhours_exfil": {
        "label": "Unusual Login Time + High Activity",
        "description": (
            "Logs in at an unusual hour (around 2 AM) and accesses far more "
            "resources than this user normally does, with a heavy concentration "
            "of write actions."
        ),
        "login_hour": 2,
        "duration_sec": 5400,
        "n_events": 40,
        "write_ratio": 0.6,
        "delete_ratio": 0.1,
        "new_ip": True,
    },
    "snooping": {
        "label": "Login From an Unrecognized Location",
        "description": (
            "Logs in from a location/IP never seen before for this user, then "
            "browses across a much wider range of resources than usual — mostly "
            "reads, consistent with someone looking around rather than doing "
            "their normal job."
        ),
        "login_hour": 10,
        "duration_sec": 2700,
        "n_events": 25,
        "write_ratio": 0.1,
        "delete_ratio": 0.0,
        "new_ip": True,
    },
    "pre_departure_purge": {
        "label": "Sudden Spike in Deletions",
        "description": (
            "A short session late in the evening with an unusually high number "
            "of delete actions compared to how this user normally behaves."
        ),
        "login_hour": 20,
        "duration_sec": 900,
        "n_events": 18,
        "write_ratio": 0.2,
        "delete_ratio": 0.5,
        "new_ip": False,
    },
}


def list_scenarios() -> list[dict]:
    return [
        {"key": key, "label": cfg["label"], "description": cfg["description"]}
        for key, cfg in SCENARIOS.items()
    ]


def _pick_unseen_ip(db: DBSession, user_id: int) -> str:
    prior = {
        loc
        for (loc,) in db.query(UserSession.access_location)
        .filter(UserSession.user_id == user_id)
        .all()
        if loc
    }
    candidate = f"203.0.113.{random.randint(2, 254)}"
    while candidate in prior:
        candidate = f"203.0.113.{random.randint(2, 254)}"
    return candidate


def _pick_seen_ip(db: DBSession, user_id: int) -> str | None:
    row = (
        db.query(UserSession.access_location)
        .filter(UserSession.user_id == user_id, UserSession.access_location.isnot(None))
        .first()
    )
    return row[0] if row else None


def run_scenario(
    db: DBSession, user_id: int, scenario_key: str, demo_mode: str = "isolated"
) -> dict:
    if scenario_key not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_key}")
    if demo_mode not in ("isolated", "naive"):
        raise ValueError("demo_mode must be 'isolated' or 'naive'")
    cfg = SCENARIOS[scenario_key]

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise ValueError("User not found")

    now = datetime.utcnow()

    # Jitter login hour slightly (±1h) and land on a random recent day, so
    # repeated runs of the same scenario don't look robotically identical —
    # more realistic than firing at the exact same minute every time.
    hour_jitter = random.choice([-1, 0, 0, 1])
    jittered_hour = max(0, min(23, cfg["login_hour"] + hour_jitter))
    day_offset = random.randint(0, 3)

    login_time = (now - timedelta(days=day_offset)).replace(
        hour=jittered_hour, minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0
    )

    duration_jitter = random.uniform(0.85, 1.15)
    duration_sec = int(cfg["duration_sec"] * duration_jitter)
    logout_time = login_time + timedelta(seconds=duration_sec)

    access_location = (
        _pick_unseen_ip(db, user_id) if cfg["new_ip"] else (_pick_seen_ip(db, user_id) or "10.0.0.50")
    )

    session = UserSession(
        user_id=user_id,
        login_time=login_time,
        logout_time=logout_time,
        session_duration=duration_sec,
        access_location=access_location,
        terminated=False,
        simulated_scenario=scenario_key,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    n_events = max(3, int(cfg["n_events"] * random.uniform(0.8, 1.2)))
    n_write = int(n_events * cfg["write_ratio"])
    n_delete = int(n_events * cfg["delete_ratio"])
    n_read = max(0, n_events - n_write - n_delete)

    action_pool = (["read"] * n_read) + (["write"] * n_write) + (["delete"] * n_delete)
    random.shuffle(action_pool)

    event_span = max(1, cfg["duration_sec"] - 5)
    for i, action in enumerate(action_pool):
        ts = login_time + timedelta(seconds=int((i / max(1, len(action_pool))) * event_span))
        db.add(
            AccessLog(
                session_id=session.session_id,
                resource_name=random.choice(RESOURCES),
                action_performed=action,
                access_timestamp=ts,
            )
        )
    db.commit()

    include_simulated = demo_mode == "naive"
    alert = anomaly_service.score_session(
        db, session.session_id, include_simulated_in_baseline=include_simulated
    )

    return {
        "scenario": scenario_key,
        "scenario_label": cfg["label"],
        "demo_mode": demo_mode,
        "session_id": session.session_id,
        "user_id": user.user_id,
        "username": user.username,
        "alert_id": alert.alert_id if alert else None,
        "anomaly_score": alert.anomaly_score if alert else None,
        "is_anomaly": alert.is_anomaly if alert else None,
        "detection_reason": alert.detection_reason if alert else None,
    }


def reset_simulated_data(db: DBSession, user_id: int) -> int:
    """Purges synthetic attack sessions for this user so the next simulation
    starts from a clean baseline instead of an inflated one from prior runs."""
    session_ids = [
        s.session_id
        for s in db.query(UserSession.session_id)
        .filter(UserSession.user_id == user_id, UserSession.simulated_scenario.isnot(None))
        .all()
    ]
    if not session_ids:
        return 0

    alert_ids = [
        a.alert_id
        for a in db.query(AnomalyAlert.alert_id).filter(AnomalyAlert.session_id.in_(session_ids)).all()
    ]
    if alert_ids:
        db.query(Notification).filter(Notification.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        db.query(AnomalyAlert).filter(AnomalyAlert.alert_id.in_(alert_ids)).delete(synchronize_session=False)

    db.query(AccessLog).filter(AccessLog.session_id.in_(session_ids)).delete(synchronize_session=False)
    db.query(UserSession).filter(UserSession.session_id.in_(session_ids)).delete(synchronize_session=False)
    db.commit()
    return len(session_ids)

def full_reset_user_history(db: DBSession, user_id: int) -> int:
    """
    DANGER: wipes ALL session history for a user — real and simulated alike,
    plus every alert/notification tied to those sessions. Intended only for
    resetting demo/test accounts to a clean slate before a presentation, not
    for use on genuine production users with real activity worth keeping.
    """
    session_ids = [
        s.session_id for s in db.query(UserSession.session_id).filter(UserSession.user_id == user_id).all()
    ]
    if not session_ids:
        return 0

    alert_ids = [
        a.alert_id
        for a in db.query(AnomalyAlert.alert_id).filter(AnomalyAlert.session_id.in_(session_ids)).all()
    ]
    if alert_ids:
        db.query(Notification).filter(Notification.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        db.query(AnomalyAlert).filter(AnomalyAlert.alert_id.in_(alert_ids)).delete(synchronize_session=False)

    db.query(AccessLog).filter(AccessLog.session_id.in_(session_ids)).delete(synchronize_session=False)
    db.query(UserSession).filter(UserSession.session_id.in_(session_ids)).delete(synchronize_session=False)
    db.commit()
    return len(session_ids)