"""Detection pipeline fixes: what the global model trains on, familiar addresses, stale-session duration."""
from datetime import datetime, timedelta

import pytest

from app.ml import feature_engineering as fe
from app.models.anomaly import AnomalyAlert
from app.models.session import AccessLog, UserSession
from app.services import anomaly_service, model_registry_service as registry, session_service


def _closed(db, user, login, ip="10.0.0.1", simulated=None, alert=None):
    """alert: None, or (is_anomaly, review_verdict, detection_reason)."""
    s = UserSession(user_id=user.user_id, login_time=login, logout_time=login + timedelta(minutes=10),
                    session_duration=600.0, access_location=ip, simulated_scenario=simulated)
    db.add(s)
    db.commit()
    if alert is not None:
        is_anomaly, verdict, reason = alert
        db.add(AnomalyAlert(session_id=s.session_id, anomaly_score=0.6, is_anomaly=is_anomaly,
                            review_verdict=verdict, detection_reason=reason))
        db.commit()
    return s


# --- training set of the global model ------------------------------------------------------------

def test_training_keeps_unreviewed_flags_and_drops_only_known_threats(db, make_user):
    user = make_user()
    t = datetime.utcnow() - timedelta(days=30)
    keep = {
        "never scored": _closed(db, user, t),
        "scored normal": _closed(db, user, t + timedelta(days=1), alert=(False, None, "ml_model")),
        "flagged, unreviewed": _closed(db, user, t + timedelta(days=2), alert=(True, None, "ml_model")),
        "repeat of an unreviewed flag": _closed(db, user, t + timedelta(days=3),
                                                alert=(True, None, "repeat_pattern_override")),
        "false positive": _closed(db, user, t + timedelta(days=4), alert=(True, "false_positive", "ml_model")),
        "pattern match later cleared": _closed(db, user, t + timedelta(days=5),
                                               alert=(True, "authorized_exception", "confirmed_threat_pattern")),
    }
    drop = {
        "confirmed threat": _closed(db, user, t + timedelta(days=6), alert=(True, "confirmed_threat", "ml_model")),
        "missed, then confirmed": _closed(db, user, t + timedelta(days=7), alert=(False, "confirmed_threat", "ml_model")),
        "repeats a confirmed threat": _closed(db, user, t + timedelta(days=8),
                                              alert=(True, None, "confirmed_threat_pattern")),
        "simulated attack": _closed(db, user, t + timedelta(days=9), simulated="offhours_exfil"),
    }
    db.add(UserSession(user_id=user.user_id, login_time=t + timedelta(days=10)))  # still open
    db.commit()

    trained = {s.session_id for s in registry._training_sessions_query(db).all()}

    assert trained == {s.session_id for s in keep.values()}
    assert not trained & {s.session_id for s in drop.values()}


def test_training_set_is_oldest_first(db, make_user):
    user = make_user()
    late = _closed(db, user, datetime.utcnow() - timedelta(days=1))
    early = _closed(db, user, datetime.utcnow() - timedelta(days=9))
    assert [s.session_id for s in registry._training_sessions_query(db).all()] == [early.session_id, late.session_id]


def test_personal_baseline_still_excludes_unreviewed_flags(db, make_user):
    """The looser training rule must not change the per-user baseline (verify_feedback relies on it)."""
    user = make_user()
    t = datetime.utcnow() - timedelta(days=30)
    _closed(db, user, t)
    _closed(db, user, t + timedelta(days=1), alert=(True, None, "ml_model"))
    assert fe.build_user_history_stats(db, user.user_id)["n_sessions"] == 1


# --- familiar addresses (new_ip) -------------------------------------------------------------------

@pytest.mark.parametrize("label, simulated, alert", [
    ("simulated attack", "snooping", None),
    ("confirmed threat", None, (False, "confirmed_threat", "ml_model")),
    ("flagged, unreviewed", None, (True, None, "ml_model")),
])
def test_address_from_a_suspicious_session_does_not_become_familiar(db, make_user, label, simulated, alert):
    user = make_user()
    t = datetime.utcnow() - timedelta(days=10)
    _closed(db, user, t, ip="10.0.0.1")
    _closed(db, user, t + timedelta(days=1), ip="203.0.113.50", simulated=simulated, alert=alert)
    again = _closed(db, user, t + timedelta(days=2), ip="203.0.113.50")

    assert fe.build_raw_session_features(db, again)["new_ip"] == 1, label


def test_address_from_a_cleared_session_is_familiar(db, make_user):
    user = make_user()
    t = datetime.utcnow() - timedelta(days=10)
    _closed(db, user, t, ip="10.0.0.1")
    _closed(db, user, t + timedelta(days=1), ip="41.90.0.7", alert=(True, "false_positive", "ml_model"))
    again = _closed(db, user, t + timedelta(days=2), ip="41.90.0.7")

    assert fe.build_raw_session_features(db, again)["new_ip"] == 0


# --- stale sessions --------------------------------------------------------------------------------

@pytest.fixture
def no_scoring(monkeypatch):
    scored = []
    monkeypatch.setattr(anomaly_service, "score_session", lambda db, sid, **k: scored.append(sid))
    return scored


def _open(db, user, minutes_ago, activity_minutes=()):
    login = datetime.utcnow() - timedelta(minutes=minutes_ago)
    s = UserSession(user_id=user.user_id, login_time=login, access_location="10.0.0.1")
    db.add(s)
    db.commit()
    for m in activity_minutes:
        db.add(AccessLog(session_id=s.session_id, resource_name="dashboard", action_performed="read",
                         access_timestamp=login + timedelta(minutes=m)))
    db.commit()
    return s


def test_stale_session_ends_at_its_last_activity(db, make_user, no_scoring):
    s = _open(db, make_user(), minutes_ago=90, activity_minutes=[1, 4, 7])

    session_service.close_stale_sessions(db, max_minutes=30)

    db.refresh(s)
    assert s.session_duration == pytest.approx(7 * 60)
    assert s.logout_time == s.login_time + timedelta(minutes=7)
    assert no_scoring == [s.session_id]


def test_stale_session_without_activity_lasted_zero_seconds(db, make_user, no_scoring):
    s = _open(db, make_user(), minutes_ago=90)
    session_service.close_stale_sessions(db, max_minutes=30)
    db.refresh(s)
    assert s.session_duration == 0.0


def test_stale_session_never_outlasts_its_token(db, make_user, no_scoring):
    s = _open(db, make_user(), minutes_ago=90, activity_minutes=[45])  # e.g. a late module event
    session_service.close_stale_sessions(db, max_minutes=30)
    db.refresh(s)
    assert s.session_duration == pytest.approx(30 * 60)


def test_recent_open_session_is_left_alone(db, make_user, no_scoring):
    s = _open(db, make_user(), minutes_ago=10, activity_minutes=[2])
    assert session_service.close_stale_sessions(db, max_minutes=30) == []
    db.refresh(s)
    assert s.logout_time is None and no_scoring == []
