"""
Live attack simulation for demo purposes.

Builds real sessions and access logs for named suspicious behaviours and scores them
through the unmodified detection pipeline. Simulated sessions never count toward a
user's baseline, so repeated runs behave consistently. Administrator verdicts still
teach the detector: mark a missed run as a confirmed threat and the next run of the
same behaviour is flagged.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from sqlalchemy.orm import Session as DBSession

from app.core.business_time import local_now, to_utc
from app.models.session import UserSession, AccessLog
from app.models.user import User
from app.models.anomaly import AnomalyAlert
from app.models.notification import Notification
from app.services import anomaly_service, live_detection_service

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
        "login_hour": 21,
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


def _pick_weekday_offset(now: datetime) -> int:
    """A recent past WEEKDAY (1-4 days ago), so a stray 'weekend' flag never changes the
    behaviour pattern between runs of the same scenario."""
    options = [d for d in range(1, 5) if (now - timedelta(days=d)).weekday() < 5]
    return random.choice(options or [1])


def create_scenario_session(
    db: DBSession, user_id: int, scenario_key: str, day=None
) -> UserSession:
    """
    Creates the simulated session and its access logs WITHOUT scoring it.

    day: a date or datetime choosing the LOCAL calendar day; by default a recent weekday.
    Scenario hours are local business time (2 AM means 2 AM in Nairobi); the session is
    stored in UTC like every other session.
    """
    if scenario_key not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_key}")
    cfg = SCENARIOS[scenario_key]

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise ValueError("User not found")

    now = local_now()

    # Small jitter so repeated runs are not robotically identical. Scenario hours are
    # chosen so the jitter never moves a login across the off-hours boundary.
    hour_jitter = random.choice([-1, 0, 0, 1])
    jittered_hour = max(0, min(23, cfg["login_hour"] + hour_jitter))
    if day is None:
        base_day = now - timedelta(days=_pick_weekday_offset(now))
    else:
        base_day = datetime(day.year, day.month, day.day)

    login_time = to_utc(base_day.replace(
        hour=jittered_hour, minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0
    ))

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
    return session


def run_scenario(db: DBSession, user_id: int, scenario_key: str) -> dict:
    session = create_scenario_session(db, user_id, scenario_key)
    cfg = SCENARIOS[scenario_key]
    user = db.query(User).filter(User.user_id == user_id).first()

    alert = anomaly_service.score_session(db, session.session_id)

    return {
        "scenario": scenario_key,
        "scenario_label": cfg["label"],
        "session_id": session.session_id,
        "user_id": user.user_id,
        "username": user.username,
        "alert_id": alert.alert_id if alert else None,
        "anomaly_score": alert.anomaly_score if alert else None,
        "is_anomaly": alert.is_anomaly if alert else None,
        "detection_reason": alert.detection_reason if alert else None,
        "pattern_signature": alert.pattern_signature if alert else None,
    }


def reset_simulated_data(db: DBSession, user_id: int) -> int:
    """Purges synthetic attack sessions for this user (and their alerts), so the next
    simulation starts without earlier simulated verdicts acting as precedent."""
    session_ids = [
        s.session_id
        for s in db.query(UserSession.session_id)
        .filter(UserSession.user_id == user_id, UserSession.simulated_scenario.isnot(None))
        .all()
    ]
    if not session_ids:
        return 0

    live_detection_service.delete_for_sessions(db, session_ids)
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

    live_detection_service.delete_for_sessions(db, session_ids)
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