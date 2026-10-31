"""
Verifies the verdict feedback loop.

    docker compose exec backend python -m scripts.verify_feedback

Prerequisites: backend running with the new code, roles seeded, model trained
(the end-to-end part is skipped if no model artifacts exist).
Creates temporary users, sessions and alerts and removes them at the end.
The script sends no emails of its own (notifications are disabled inside this process).
"""

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.business_time import local_now, to_utc
from app.core.security import create_access_token
from app.db.database import SessionLocal
from app.ml import feature_engineering
from app.models.anomaly import AnomalyAlert
from app.models.notification import Notification
from app.models.role import Role
from app.models.session import AccessLog, UserSession
from app.models.user import User
from app.services import anomaly_service, attack_simulation_service, notification_service, session_service

BASE = os.getenv("VERIFY_BASE_URL", "http://127.0.0.1:8000")
failures = []

# No admin emails from the sessions this script flags.
notification_service.notify_admins_of_anomaly = lambda *args, **kwargs: None


def check(name, condition, detail=""):
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not condition) else ""))
    if not condition:
        failures.append(name)


def api(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as err:
        raw, status = err.read(), err.code
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    return status, parsed


def make_user(db, role=None):
    tag = uuid.uuid4().hex[:8]
    user = User(username=f"verify4_{tag}", password="x", email=f"verify4_{tag}@example.com", department="IT")
    if role is not None:
        user.roles = [role]
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def add_session(db, user, days_ago, hour=10, duration=1800.0, ip="10.0.0.50", n_events=6, resource="dashboard"):
    # hour is local business time
    login = to_utc((local_now() - timedelta(days=days_ago)).replace(hour=hour, minute=0, second=0, microsecond=0))
    session = UserSession(
        user_id=user.user_id,
        login_time=login,
        logout_time=login + timedelta(seconds=duration),
        session_duration=duration,
        access_location=ip,
        terminated=False,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    for i in range(n_events):
        db.add(AccessLog(session_id=session.session_id, resource_name=resource,
                         action_performed="read", access_timestamp=login + timedelta(seconds=i * 10)))
    db.commit()
    return session


def add_alert(db, session, is_anomaly, signature, verdict=None):
    alert = AnomalyAlert(
        session_id=session.session_id,
        anomaly_score=0.5,
        is_anomaly=is_anomaly,
        pattern_signature=signature,
        review_verdict=verdict,
        reviewed=verdict is not None,
        detection_reason="ml_model",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def cleanup(db):
    db.rollback()
    users = db.query(User).filter(User.username.like("verify4_%")).all()
    for user in users:
        attack_simulation_service.full_reset_user_history(db, user.user_id)
    # The temporary admin can also be notified by the running backend about OTHER users'
    # alerts (e.g. a stale session it auto-closes and scores), so remove those too.
    user_ids = [user.user_id for user in users]
    if user_ids:
        db.query(Notification).filter(Notification.user_id.in_(user_ids)).delete(synchronize_session=False)
    for user in users:
        db.delete(user)
    db.commit()


def precedent_case(db, name, flagged, signature, verdict, current_signature, expected, other_user=False):
    owner = make_user(db)
    prior = add_session(db, owner, days_ago=3)
    add_alert(db, prior, flagged, signature, verdict)
    subject = make_user(db) if other_user else owner
    current = add_session(db, subject, days_ago=1)
    got = anomaly_service._find_precedent(db, current, current_signature)
    check(name, got == expected, f"got {got}, expected {expected}")


def baseline_case(db, name, flagged, verdict, expected_mean):
    user = make_user(db)
    for days in (5, 4, 3):
        add_session(db, user, days_ago=days, n_events=6)
    odd = add_session(db, user, days_ago=2, n_events=50)
    add_alert(db, odd, flagged, "highvolume", verdict)
    current = add_session(db, user, days_ago=1, n_events=6)
    stats = feature_engineering.build_user_history_stats(db, user.user_id, exclude_session_id=current.session_id)
    mean = stats["n_access_events_mean"]
    check(name, abs(mean - expected_mean) < 1e-6, f"mean={mean}, expected {expected_mean}")


def main():
    db = SessionLocal()
    try:
        cleanup(db)
        roles = {r.role_name: r for r in db.query(Role).all()}
        if "Administrator" not in roles:
            print("Roles missing. Run: python -m scripts.seed_roles_and_permissions")
            sys.exit(1)

        # ---- 1. Which earlier alerts count as precedent --------------------------
        CT = "confirmed_threat"
        precedent_case(db, "precedent: unflagged + confirmed threat -> confirmed_threat_pattern",
                       False, "highvolume|newip", CT, "highvolume|newip", "confirmed_threat_pattern")
        precedent_case(db, "precedent: matches when the new session trips extra indicators",
                       False, "highvolume|newip", CT, "highvolume|newip|weekend", "confirmed_threat_pattern")
        precedent_case(db, "precedent: does not match when an indicator is missing",
                       False, "highvolume|newip", CT, "newip", None)
        precedent_case(db, "precedent: unflagged with no verdict is ignored",
                       False, "highvolume|newip", None, "highvolume|newip", None)
        precedent_case(db, "precedent: unflagged + false_positive is ignored",
                       False, "highvolume|newip", "false_positive", "highvolume|newip", None)
        precedent_case(db, "precedent: unflagged + authorized_exception is ignored",
                       False, "highvolume|newip", "authorized_exception", "highvolume|newip", None)
        precedent_case(db, "precedent: flagged and still unreviewed -> repeat_pattern_override",
                       True, "highvolume|newip", None, "highvolume|newip", "repeat_pattern_override")
        precedent_case(db, "precedent: flagged + false_positive is cleared",
                       True, "highvolume|newip", "false_positive", "highvolume|newip", None)
        precedent_case(db, "precedent: flagged + confirmed threat -> confirmed_threat_pattern",
                       True, "highvolume|newip", CT, "highvolume|newip", "confirmed_threat_pattern")
        precedent_case(db, "precedent: a confirmed 'normal' pattern cannot be matched",
                       False, "normal", CT, "highvolume|newip", None)
        precedent_case(db, "precedent: a normal-looking new session never matches",
                       False, "highvolume|newip", CT, "normal", None)
        precedent_case(db, "precedent: another user's confirmed threat does not apply",
                       False, "highvolume|newip", CT, "highvolume|newip", None, other_user=True)

        # ---- 2. Which sessions count toward a user's baseline ----------------------
        baseline_case(db, "baseline: unflagged, no verdict -> counts", False, None, 17.0)
        baseline_case(db, "baseline: unflagged but confirmed threat -> excluded", False, CT, 6.0)
        baseline_case(db, "baseline: unflagged + false_positive -> counts", False, "false_positive", 17.0)
        baseline_case(db, "baseline: flagged, unreviewed -> excluded", True, None, 6.0)
        baseline_case(db, "baseline: flagged + false_positive -> counts", True, "false_positive", 17.0)
        baseline_case(db, "baseline: flagged + confirmed threat -> excluded", True, CT, 6.0)

        # ---- 3. End to end: miss -> report -> next run is flagged -> clear -> not flagged
        if not anomaly_service._load_artifacts():
            print("SKIP  end-to-end loop: no trained model found (run scripts.train_isolation_forest)")
        else:
            real_threshold = anomaly_service._threshold
            real_tiers = anomaly_service._tier_thresholds
            # Only the verdict rule can flag in this block. Per-tier thresholds take priority
            # over the single one when threshold.json has them, so both are overridden.
            anomaly_service._threshold = 99.0
            anomaly_service._tier_thresholds = None
            try:
                admin = make_user(db, roles["Administrator"])
                admin_session = session_service.create_session(db, user_id=admin.user_id, access_location="verify4")
                token = create_access_token({"sub": str(admin.user_id), "sid": admin_session.session_id})

                subject = make_user(db)
                for days in range(2, 8):
                    add_session(db, subject, days_ago=days, n_events=6)
                control = make_user(db)
                for days in range(2, 8):
                    add_session(db, control, days_ago=days, n_events=6)

                run1 = attack_simulation_service.run_scenario(db, subject.user_id, "snooping")
                check("loop: result carries no demo_mode", "demo_mode" not in run1)
                check("loop: first run is not flagged (no precedent yet)", run1["is_anomaly"] is False, str(run1))
                check("loop: pattern signature recorded", "newip" in (run1.get("pattern_signature") or ""),
                      str(run1.get("pattern_signature")))

                status, body = api("GET", "/api/dashboard/sessions", token=token)
                check("api: sessions include alert details",
                      status == 200 and isinstance(body, list) and (not body or "alert_id" in body[0]), f"{status}")
                status, before = api("GET", "/api/dashboard/detection-outcomes", token=token)
                check("api: detection outcomes expose missed_threat", status == 200 and "missed_threat" in (before or {}), f"{status} {before}")

                status, body = api("PATCH", f"/api/dashboard/alerts/{run1['alert_id']}",
                                   {"review_verdict": CT}, token=token)
                check("api: verdict can be set on an unflagged session",
                      status == 200 and (body or {}).get("review_verdict") == CT, f"{status} {body}")
                status, after = api("GET", "/api/dashboard/detection-outcomes", token=token)
                check("api: missed_threat increases by one",
                      status == 200 and after["missed_threat"] == before["missed_threat"] + 1, f"{before} -> {after}")

                db.expire_all()
                run2 = attack_simulation_service.run_scenario(db, subject.user_id, "snooping")
                check("loop: same behaviour is flagged after the verdict", run2["is_anomaly"] is True, str(run2))
                check("loop: reason is confirmed_threat_pattern", run2["detection_reason"] == "confirmed_threat_pattern",
                      str(run2.get("detection_reason")))

                control_run = attack_simulation_service.run_scenario(db, control.user_id, "snooping")
                check("loop: another user is unaffected", control_run["is_anomaly"] is False, str(control_run))

                for alert_id in (run1["alert_id"], run2["alert_id"]):
                    status, body = api("PATCH", f"/api/dashboard/alerts/{alert_id}",
                                       {"review_verdict": "false_positive"}, token=token)
                    check(f"api: alert {alert_id} cleared as false positive", status == 200, f"{status} {body}")
                db.expire_all()
                run3 = attack_simulation_service.run_scenario(db, subject.user_id, "snooping")
                check("loop: once cleared, the behaviour is no longer flagged", run3["is_anomaly"] is False, str(run3))
            finally:
                anomaly_service._threshold = real_threshold
                anomaly_service._tier_thresholds = real_tiers
    finally:
        cleanup(db)
        db.close()

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED:")
        for name in failures:
            print(f"  - {name}")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()