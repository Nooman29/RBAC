"""
Live attack simulation for demo purposes. Creates a real, closed UserSession
with real AccessLog rows shaped to match a known CERT-style attack pattern,
then scores it through the ACTUAL trained Isolation Forest pipeline — same
anomaly_service.score_session() used for every real session. Nothing here
fakes the anomaly score or SHAP output; the model genuinely evaluates
synthetic-but-realistic behavior.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from sqlalchemy.orm import Session as DBSession

from app.models.session import UserSession, AccessLog
from app.models.user import User
from app.services import anomaly_service

RESOURCES = ["dashboard", "role", "user"]
ACTIONS = ["read", "write", "delete"]


SCENARIOS = {
    "offhours_exfil": {
        "label": "Off-hours mass access + write burst",
        "description": (
            "Mirrors the CERT 'after-hours + removable drive' pattern: a login "
            "at 2–3am, an unusually large number of resource accesses, and a "
            "spike in write actions compared to this user's normal behavior."
        ),
        "login_hour": 2,
        "duration_sec": 5400,
        "n_events": 40,
        "write_ratio": 0.6,
        "delete_ratio": 0.1,
        "new_ip": True,
    },
    "snooping": {
        "label": "Cross-resource snooping from a new location",
        "description": (
            "Mirrors CERT's 'cross-machine snooping' pattern: login from an IP "
            "never seen before for this user, touching far more distinct "
            "resources than usual, mostly reads (browsing/reconnaissance)."
        ),
        "login_hour": 10,
        "duration_sec": 2700,
        "n_events": 25,
        "write_ratio": 0.1,
        "delete_ratio": 0.0,
        "new_ip": True,
    },
    "pre_departure_purge": {
        "label": "Pre-departure delete spike",
        "description": (
            "Mirrors CERT's 'Dropbox uploads before a layoff' pattern: a short, "
            "late-evening session with a heavy concentration of delete actions "
            "relative to this user's usual read/write ratio."
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
    candidate = f"203.0.113.{random.randint(2, 254)}"  # TEST-NET-3, never real traffic
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


def run_scenario(db: DBSession, user_id: int, scenario_key: str) -> dict:
    if scenario_key not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_key}")
    cfg = SCENARIOS[scenario_key]

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise ValueError("User not found")

    now = datetime.utcnow()
    login_time = now.replace(hour=cfg["login_hour"], minute=random.randint(0, 59), second=0, microsecond=0)
    if login_time > now:
        login_time -= timedelta(days=1)
    logout_time = login_time + timedelta(seconds=cfg["duration_sec"])

    access_location = (
        _pick_unseen_ip(db, user_id) if cfg["new_ip"] else (_pick_seen_ip(db, user_id) or "10.0.0.50")
    )

    session = UserSession(
        user_id=user_id,
        login_time=login_time,
        logout_time=logout_time,
        session_duration=cfg["duration_sec"],
        access_location=access_location,
        terminated=False,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    n_events = cfg["n_events"]
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
    }