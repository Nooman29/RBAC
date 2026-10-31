"""Live (mid-session) detection: rules R1-R4, provisional model scoring R5, alerts and cleanup."""
import json
from datetime import datetime, timedelta

import numpy as np
import pytest
from fastapi import HTTPException

from app.api.routes import dashboard
from app.core import rbac
from app.core.business_time import to_utc
from app.core.security import create_access_token
from app.ml import feature_engineering
from app.models.anomaly import AnomalyAlert
from app.models.live_alert import DeniedAttempt, LiveAlert, LiveSessionScore
from app.models.module_event import ModuleEvent
from app.models.notification import Notification
from app.models.session import AccessLog, UserSession
from app.services import anomaly_service, attack_simulation_service, live_detection_service as live
from app.services import session_service

NOW_LOCAL = datetime(2026, 10, 28, 10, 30)  # a Wednesday, inside business hours (Nairobi time)
NOW = to_utc(NOW_LOCAL)                     # as stored (UTC)


def _local(hour, minute=0, days_ago=0):
    """A local (Nairobi) clock time on NOW's day, converted to stored UTC."""
    return to_utc((NOW_LOCAL - timedelta(days=days_ago)).replace(hour=hour, minute=minute))


# --- helpers -------------------------------------------------------------------------------------

def _session(db, user, login=None, ip="10.0.0.1"):
    s = UserSession(user_id=user.user_id, login_time=login or NOW - timedelta(minutes=10), access_location=ip)
    db.add(s)
    db.commit()
    return s


def _closed(db, user, login, minutes=60, ip="10.0.0.1"):
    s = UserSession(
        user_id=user.user_id, login_time=login, logout_time=login + timedelta(minutes=minutes),
        session_duration=minutes * 60.0, access_location=ip,
    )
    db.add(s)
    db.commit()
    return s


def _log(db, session, at=NOW, endpoint="GET /api/users/", action="read", resource="user"):
    db.add(AccessLog(session_id=session.session_id, resource_name=resource, action_performed=action,
                     endpoint=endpoint, access_timestamp=at))
    db.commit()


def _module_event(db, session, action, permitted=True, at=NOW, resource="payment"):
    event = ModuleEvent(user_id=session.user_id, session_id=session.session_id, resource_name=resource,
                        action_type=action, permitted=permitted, created_at=at)
    db.add(event)
    db.commit()
    return event


def _alerts(db, session, rule=None):
    q = db.query(LiveAlert).filter(LiveAlert.session_id == session.session_id)
    if rule:
        q = q.filter(LiveAlert.rule == rule)
    return q.all()


def _usual_history(db, user, n=5):
    """n earlier normal sessions, 09:00-11:00 local time on the days before NOW."""
    for d in range(1, n + 1):
        _closed(db, user, _local(9, days_ago=d), minutes=120)


class _StubModel:
    def __init__(self, score):
        self.score = score
        self.calls = 0

    def score_samples(self, rows):
        self.calls += 1
        return np.array([-self.score] * len(rows))


class _IdentityScaler:
    def transform(self, rows):
        return np.asarray(rows, dtype=float)


@pytest.fixture(autouse=True)
def no_model(monkeypatch):
    # Rules are tested without a model; R5 tests switch it on with `live_model`.
    monkeypatch.setattr(anomaly_service, "_load_artifacts", lambda: False)


@pytest.fixture
def live_model(monkeypatch):
    monkeypatch.setattr(anomaly_service, "_load_artifacts", lambda: True)
    monkeypatch.setattr(anomaly_service, "_scaler", _IdentityScaler())
    monkeypatch.setattr(anomaly_service, "_threshold", 0.6)
    monkeypatch.setattr(anomaly_service, "_tier_thresholds", None)
    monkeypatch.setattr(anomaly_service, "_explainer", None)

    def _use(score, tiers=None):
        model = _StubModel(score)
        monkeypatch.setattr(anomaly_service, "_model", model)
        if tiers:
            monkeypatch.setattr(anomaly_service, "_tier_thresholds", tiers)
        return model

    return _use


@pytest.fixture
def standard_user(make_role, make_user):
    return make_user(roles=[make_role("Standard User", [("user", "read")])], department="Finance")


# --- baseline ------------------------------------------------------------------------------------

def test_normal_activity_raises_nothing(db, standard_user):
    s = _session(db, standard_user)
    for i in range(3):
        _log(db, s, at=NOW - timedelta(minutes=i))

    live.on_access(db, s.session_id, now=NOW)

    assert _alerts(db, s) == []


def test_closed_or_terminated_sessions_are_ignored(db, standard_user):
    closed = _closed(db, standard_user, NOW - timedelta(hours=1))
    terminated = _session(db, standard_user)
    terminated.terminated = True
    db.commit()

    for s in (closed, terminated):
        for _ in range(4):
            live.on_denied(db, s.session_id, "user", "write", now=NOW)

    assert db.query(LiveAlert).count() == 0
    assert db.query(DeniedAttempt).count() == 0


# --- R1 out_of_scope -----------------------------------------------------------------------------

def test_third_refused_request_within_window_fires(db, standard_user):
    s = _session(db, standard_user)
    live.on_denied(db, s.session_id, "user", "write", now=NOW - timedelta(minutes=2))
    live.on_denied(db, s.session_id, "role", "write", now=NOW - timedelta(minutes=1))
    assert _alerts(db, s) == []

    live.on_denied(db, s.session_id, "user", "write", now=NOW)

    [alert] = _alerts(db, s)
    assert alert.rule == live.RULE_OUT_OF_SCOPE
    assert alert.severity == "medium"
    assert alert.status == "open"


def test_refused_requests_spread_over_more_than_the_window_do_not_fire(db, standard_user):
    s = _session(db, standard_user, login=NOW - timedelta(hours=1))
    for minutes_ago in (25, 12, 0):
        live.on_denied(db, s.session_id, "user", "write", now=NOW - timedelta(minutes=minutes_ago))

    assert _alerts(db, s) == []


def test_permission_denials_through_the_guard_are_counted_but_never_logged(db, standard_user):
    s = _session(db, standard_user, login=datetime.utcnow())
    guard = rbac.require_permission("user", "write")

    for _ in range(3):
        with pytest.raises(HTTPException) as exc:
            guard(current=(standard_user, s.session_id), db=db)
        assert exc.value.status_code == 403

    assert db.query(AccessLog).count() == 0  # the model never sees refused requests
    assert db.query(DeniedAttempt).filter(DeniedAttempt.reason == "permission").count() == 3
    assert [a.rule for a in _alerts(db, s)] == [live.RULE_OUT_OF_SCOPE]


def test_out_of_scope_record_access_counts_as_a_refusal(db, standard_user, make_role, make_user):
    viewer = make_user(roles=[make_role("Manager", [("dashboard", "read")])], department="HR")
    s = _session(db, viewer, login=datetime.utcnow())
    scope = dashboard._visibility_scope(viewer)

    for _ in range(3):
        with pytest.raises(HTTPException):
            dashboard._refuse_out_of_scope(db, (viewer, s.session_id), "alert", scope, "read", "GET /x")

    assert db.query(DeniedAttempt).filter(DeniedAttempt.reason == "visibility").count() == 3
    assert len(_alerts(db, s, live.RULE_OUT_OF_SCOPE)) == 1


def test_model_management_refusals_are_counted(db, make_role, make_user):
    from app.api.routes import model as model_routes

    manager = make_user(roles=[make_role("Manager", [("dashboard", "read")])], department="HR")
    s = _session(db, manager, login=datetime.utcnow())

    for _ in range(3):
        with pytest.raises(HTTPException) as exc:
            model_routes.model_status(current_user=manager, current=(manager, s.session_id), db=db)
        assert exc.value.status_code == 403

    assert db.query(DeniedAttempt).filter(DeniedAttempt.endpoint == "GET /api/model/status").count() == 3
    assert len(_alerts(db, s, live.RULE_OUT_OF_SCOPE)) == 1


def test_unpermitted_module_write_fires_immediately(db, standard_user):
    s = _session(db, standard_user)
    event = _module_event(db, s, "approve", permitted=False)

    live.on_module_events(db, s.session_id, [event], now=NOW)

    [alert] = _alerts(db, s, live.RULE_OUT_OF_SCOPE)
    assert alert.severity == "high"
    assert "approve" in alert.summary


def test_unpermitted_module_read_only_counts_as_a_refusal(db, standard_user):
    s = _session(db, standard_user)
    event = _module_event(db, s, "read", permitted=False)

    live.on_module_events(db, s.session_id, [event], now=NOW)

    assert _alerts(db, s, live.RULE_OUT_OF_SCOPE) == []
    assert db.query(DeniedAttempt).filter(DeniedAttempt.reason == "module").count() == 1


# --- R2 destructive_burst ------------------------------------------------------------------------

def test_five_deletes_in_two_minutes_fire(db, standard_user):
    s = _session(db, standard_user)
    for i in range(5):
        _log(db, s, at=NOW - timedelta(seconds=20 * i), endpoint=f"DELETE /api/users/{i}", action="write")

    live.on_access(db, s.session_id, now=NOW)

    [alert] = _alerts(db, s, live.RULE_BURST)
    assert alert.severity == "high"
    assert json.loads(alert.evidence_json)[0]["deletes"] == 5


def test_four_deletes_do_not_fire(db, standard_user):
    s = _session(db, standard_user)
    for i in range(4):
        _log(db, s, at=NOW - timedelta(seconds=20 * i), endpoint=f"DELETE /api/users/{i}", action="write")

    live.on_access(db, s.session_id, now=NOW)

    assert _alerts(db, s, live.RULE_BURST) == []


def test_deletes_spread_over_ten_minutes_do_not_fire(db, standard_user):
    s = _session(db, standard_user, login=NOW - timedelta(minutes=30))
    for i in range(5):
        _log(db, s, at=NOW - timedelta(minutes=2.5 * i), endpoint=f"DELETE /api/users/{i}", action="write")

    live.on_access(db, s.session_id, now=NOW)

    assert _alerts(db, s, live.RULE_BURST) == []


def test_high_risk_tier_fires_at_three(db, make_role, make_user):
    finance = make_user(roles=[make_role("Finance Officer", [("payment", "export")])])
    s = _session(db, finance)
    for i in range(3):
        _module_event(db, s, "export", at=NOW - timedelta(seconds=10 * i))

    live.on_access(db, s.session_id, now=NOW)

    [alert] = _alerts(db, s, live.RULE_BURST)
    assert json.loads(alert.evidence_json)[0]["risk_tier"] == "high"


def test_export_burst_from_module_events_fires(db, standard_user):
    s = _session(db, standard_user)
    events = [_module_event(db, s, "export", at=NOW - timedelta(seconds=10 * i)) for i in range(5)]

    live.on_module_events(db, s.session_id, events, now=NOW)

    [alert] = _alerts(db, s, live.RULE_BURST)
    assert json.loads(alert.evidence_json)[0]["exports"] == 5


# --- R3 unusual_hour -----------------------------------------------------------------------------

def test_activity_outside_the_users_usual_hours_fires(db, standard_user):
    _usual_history(db, standard_user)
    night = _local(3)
    s = _session(db, standard_user, login=night - timedelta(minutes=5))

    live.on_access(db, s.session_id, now=night)

    [alert] = _alerts(db, s, live.RULE_UNUSUAL_HOUR)
    assert alert.severity == "low"
    assert alert.is_learning is False


def test_activity_inside_the_users_usual_hours_does_not_fire(db, standard_user):
    _usual_history(db, standard_user)
    s = _session(db, standard_user)

    live.on_access(db, s.session_id, now=NOW)  # 10:30, inside 09:00-11:00 (+-1 h)

    assert _alerts(db, s, live.RULE_UNUSUAL_HOUR) == []


def test_flagged_unreviewed_session_does_not_make_its_hour_usual(db, standard_user):
    _usual_history(db, standard_user)
    suspicious = _closed(db, standard_user, _local(3, days_ago=6))
    db.add(AnomalyAlert(session_id=suspicious.session_id, anomaly_score=0.9, is_anomaly=True))
    db.commit()
    night = _local(3)
    s = _session(db, standard_user, login=night - timedelta(minutes=5))

    live.on_access(db, s.session_id, now=night)

    assert len(_alerts(db, s, live.RULE_UNUSUAL_HOUR)) == 1


def test_unusual_hour_reads_local_time(db, standard_user):
    # Usual hours 08:00-10:00 in Nairobi (05:00-07:00 UTC). Activity at 08:30 local is usual;
    # read as UTC (05:30) it would have looked like a night-time login.
    for d in range(1, 6):
        _closed(db, standard_user, _local(8, days_ago=d), minutes=120)
    s = _session(db, standard_user, login=_local(8, 20))

    live.on_access(db, s.session_id, now=_local(8, 30))
    assert _alerts(db, s, live.RULE_UNUSUAL_HOUR) == []

    live.on_access(db, s.session_id, now=_local(16, 0))
    [alert] = _alerts(db, s, live.RULE_UNUSUAL_HOUR)
    assert "16:00 EAT" in alert.summary


def test_learning_user_falls_back_to_business_hours(db, standard_user):
    night = _local(3)
    s = _session(db, standard_user, login=night - timedelta(minutes=5))

    live.on_access(db, s.session_id, now=night)

    [alert] = _alerts(db, s, live.RULE_UNUSUAL_HOUR)
    assert alert.is_learning is True


def test_learning_user_at_midday_does_not_fire(db, standard_user):
    s = _session(db, standard_user)

    live.on_access(db, s.session_id, now=_local(12))

    assert _alerts(db, s, live.RULE_UNUSUAL_HOUR) == []


# --- R4 confirmed_threat_pattern -----------------------------------------------------------------

def _precedent(db, user, verdict, signature="newip|offhours"):
    earlier = _closed(db, user, _local(2, days_ago=2), ip="10.0.0.1")
    db.add(AnomalyAlert(session_id=earlier.session_id, anomaly_score=0.4, is_anomaly=False,
                        review_verdict=verdict, pattern_signature=signature))
    db.commit()


def test_repeat_of_a_confirmed_threat_pattern_fires(db, standard_user):
    _precedent(db, standard_user, "confirmed_threat")
    login = _local(2)
    s = _session(db, standard_user, login=login, ip="203.0.113.9")  # off-hours + unfamiliar IP

    live.on_access(db, s.session_id, now=login + timedelta(minutes=3))

    [alert] = _alerts(db, s, live.RULE_CONFIRMED_PATTERN)
    assert alert.severity == "high"
    assert json.loads(alert.evidence_json)[0]["matched"] == "newip|offhours"


def test_false_positive_precedent_does_not_fire(db, standard_user):
    _precedent(db, standard_user, "false_positive")
    login = _local(2)
    s = _session(db, standard_user, login=login, ip="203.0.113.9")

    live.on_access(db, s.session_id, now=login + timedelta(minutes=3))

    assert _alerts(db, s, live.RULE_CONFIRMED_PATTERN) == []


def test_no_feature_building_without_confirmed_threats(db, standard_user, monkeypatch):
    def _fail(*args, **kwargs):
        raise AssertionError("features should not be built")

    monkeypatch.setattr(live, "build_session_feature_vector", _fail)
    s = _session(db, standard_user)
    _log(db, s)

    live.on_access(db, s.session_id, now=NOW)

    assert _alerts(db, s) == []


# --- alert lifecycle, notifications, isolation ---------------------------------------------------

def test_repeat_hits_update_one_alert_and_notify_once(db, standard_user, make_role, make_user):
    admin = make_user(roles=[make_role("Administrator", [("dashboard", "write")])], department="IT")
    s = _session(db, standard_user)

    for i in range(4):
        live.on_denied(db, s.session_id, "user", "write", now=NOW + timedelta(seconds=i))

    [alert] = _alerts(db, s)
    assert alert.hit_count == 2
    notes = db.query(Notification).filter(Notification.live_alert_id == alert.id).all()
    assert [n.user_id for n in notes] == [admin.user_id]
    assert notes[0].alert_id is None


def test_recipients_are_chosen_by_permission_and_scope(db, make_role, make_user):
    flagged = make_user(roles=[make_role("Standard User", [("user", "read")])], department="Finance")
    admin = make_user(roles=[make_role("Administrator", [("dashboard", "write")])], department="IT")
    manager_role = make_role("Manager", [("dashboard", "write")])
    same_dept = make_user(roles=[manager_role], department="Finance")
    other_dept = make_user(roles=[manager_role], department="HR")
    make_user(roles=[make_role("Auditor", [("dashboard", "read")])])  # can see, cannot act
    s = _session(db, flagged)

    live.on_module_events(db, s.session_id, [_module_event(db, s, "write", permitted=False)], now=NOW)

    recipients = {n.user_id for n in db.query(Notification).all()}
    assert recipients == {admin.user_id, same_dept.user_id}
    assert other_dept.user_id not in recipients and flagged.user_id not in recipients


def test_dismissed_alert_stays_dismissed_on_repeat(db, standard_user):
    s = _session(db, standard_user)
    live.on_module_events(db, s.session_id, [_module_event(db, s, "write", permitted=False)], now=NOW)
    [alert] = _alerts(db, s)
    alert.status = live.STATUS_DISMISSED
    db.commit()

    live.on_module_events(db, s.session_id, [_module_event(db, s, "write", permitted=False)], now=NOW)

    db.refresh(alert)
    assert alert.status == live.STATUS_DISMISSED
    assert alert.hit_count == 2


def test_a_failing_check_never_stops_the_others(db, standard_user, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(live, "_check_burst", _boom)
    night = _local(3)
    s = _session(db, standard_user, login=night - timedelta(minutes=5))

    live.on_access(db, s.session_id, now=night)  # must not raise

    assert len(_alerts(db, s, live.RULE_UNUSUAL_HOUR)) == 1


def test_live_detection_failure_never_breaks_the_request(db, standard_user, monkeypatch):
    def _boom(*args, **kwargs):
        raise RuntimeError("database hiccup")

    monkeypatch.setattr(live, "_open_session", _boom)
    s = _session(db, standard_user)

    assert rbac.require_permission("user", "read")(current=(standard_user, s.session_id), db=db) is standard_user
    with pytest.raises(HTTPException) as exc:
        rbac.require_permission("user", "write")(current=(standard_user, s.session_id), db=db)
    assert exc.value.status_code == 403


def test_polling_guard_checks_permission_but_logs_nothing(db, standard_user, make_role, make_user):
    reader = make_user(roles=[make_role("Viewer", [("dashboard", "read")])])
    s = _session(db, reader)

    guard = rbac.require_permission("dashboard", "read", audit=False)
    assert guard(current=(reader, s.session_id), db=db) is reader
    assert db.query(AccessLog).count() == 0

    with pytest.raises(HTTPException):
        rbac.require_permission("dashboard", "write", audit=False)(current=(reader, s.session_id), db=db)


def test_live_data_never_changes_the_models_features(db, standard_user):
    s = _session(db, standard_user)
    _log(db, s)
    s.logout_time, s.session_duration = NOW, 600.0
    db.commit()
    before = feature_engineering.build_session_feature_vector(db, s)

    s.logout_time, s.session_duration = None, None
    db.commit()
    for i in range(4):
        live.on_denied(db, s.session_id, "user", "write", now=NOW + timedelta(seconds=i))
    assert _alerts(db, s)
    s.logout_time, s.session_duration = NOW, 600.0
    db.commit()

    assert feature_engineering.build_session_feature_vector(db, s) == before


# --- dashboard routes ----------------------------------------------------------------------------

def _admin_with_session(db, make_role, make_user):
    admin = make_user(roles=[make_role("Administrator", [("dashboard", "read"), ("dashboard", "write")])],
                      department="IT")
    return admin, _session(db, admin, login=datetime.utcnow())


def test_terminate_resolves_live_alerts_and_ends_the_session(db, standard_user, make_role, make_user):
    admin, admin_session = _admin_with_session(db, make_role, make_user)
    s = _session(db, standard_user, login=datetime.utcnow() - timedelta(minutes=5))
    # A fixed business-hours clock, so R3 (unusual hour) cannot also fire when the suite runs at night
    live.on_module_events(db, s.session_id, [_module_event(db, s, "write", permitted=False)], now=NOW)

    dashboard.terminate_session(s.session_id, current_user=admin, current=(admin, admin_session.session_id), db=db)

    [alert] = _alerts(db, s)
    assert alert.status == live.STATUS_TERMINATED
    assert alert.resolved_by == admin.user_id
    token = create_access_token({"sub": str(standard_user.user_id), "sid": str(s.session_id)})
    with pytest.raises(HTTPException) as exc:
        rbac.get_current_user_and_session(
            rbac.HTTPAuthorizationCredentials(scheme="Bearer", credentials=token), db
        )
    assert exc.value.status_code == 401


def test_live_alert_list_is_scoped_and_dismiss_checks_scope(db, standard_user, make_role, make_user):
    admin, admin_session = _admin_with_session(db, make_role, make_user)
    outsider = make_user(roles=[make_role("Manager", [("dashboard", "read"), ("dashboard", "write")])],
                         department="HR")
    outsider_session = _session(db, outsider, login=datetime.utcnow())
    s = _session(db, standard_user)
    live.on_module_events(db, s.session_id, [_module_event(db, s, "write", permitted=False)], now=NOW)

    assert [a.username for a in dashboard.list_live_alerts(status="open", current_user=admin, db=db)] == [
        standard_user.username
    ]
    assert dashboard.list_live_alerts(status="open", current_user=outsider, db=db) == []

    [alert] = _alerts(db, s)
    with pytest.raises(HTTPException) as exc:
        dashboard.dismiss_live_alert(alert.id, current_user=outsider,
                                     current=(outsider, outsider_session.session_id), db=db)
    assert exc.value.status_code == 403

    out = dashboard.dismiss_live_alert(alert.id, current_user=admin, current=(admin, admin_session.session_id), db=db)
    assert out.status == live.STATUS_DISMISSED
    assert dashboard.list_live_alerts(status="open", current_user=admin, db=db) == []
    assert len(dashboard.list_live_alerts(status="all", current_user=admin, db=db)) == 1


def test_sessions_list_shows_open_live_rules(db, standard_user, make_role, make_user):
    admin, _ = _admin_with_session(db, make_role, make_user)
    s = _session(db, standard_user, login=datetime.utcnow())
    live.on_module_events(db, s.session_id, [_module_event(db, s, "write", permitted=False)], now=NOW)

    rows = dashboard.list_sessions(active_only=True, current_user=admin, db=db)

    assert next(r for r in rows if r.session_id == s.session_id).live_rules == [live.RULE_OUT_OF_SCOPE]


# --- cleanup -------------------------------------------------------------------------------------

def test_deleting_sessions_removes_live_rows(db, standard_user, make_role, make_user):
    make_user(roles=[make_role("Administrator", [("dashboard", "write")])])
    s = _session(db, standard_user)
    live.on_module_events(db, s.session_id, [_module_event(db, s, "write", permitted=False)], now=NOW)
    live.on_denied(db, s.session_id, "user", "write", now=NOW)
    db.add(LiveSessionScore(session_id=s.session_id, scored_at=NOW, anomaly_score=0.1, peak_score=0.1,
                            threshold_used=0.6, risk_tier="standard", is_learning=True, n_events=0,
                            elapsed_sec=0.0))
    db.commit()
    assert db.query(Notification).count() == 1

    assert attack_simulation_service.full_reset_user_history(db, standard_user.user_id) == 1

    for model in (LiveAlert, LiveSessionScore, DeniedAttempt, Notification, UserSession):
        assert db.query(model).count() == 0, model.__name__


# --- R5 model_provisional ------------------------------------------------------------------------

def test_live_duration_only_changes_duration_and_defaults_to_old_behaviour(db, standard_user):
    closed = _closed(db, standard_user, NOW - timedelta(hours=2), minutes=2)
    assert feature_engineering.build_session_feature_vector(db, closed)["session_duration_sec"] == 120.0

    s = _session(db, standard_user)
    assert feature_engineering.build_session_feature_vector(db, s)["session_duration_sec"] == 0.0
    assert feature_engineering.build_session_feature_vector(db, s, live_duration_sec=300.0)[
        "session_duration_sec"] == 300.0


def test_no_model_scoring_before_warm_up(db, standard_user, live_model):
    model = live_model(0.9)
    s = _session(db, standard_user, login=NOW - timedelta(minutes=1))
    for i in range(3):
        _log(db, s, at=NOW - timedelta(seconds=i))

    live.on_access(db, s.session_id, now=NOW)

    assert model.calls == 0
    assert db.query(LiveSessionScore).count() == 0


def test_warm_up_by_activity_count(db, standard_user, live_model):
    model = live_model(0.3)
    s = _session(db, standard_user, login=NOW - timedelta(minutes=1))
    for i in range(10):
        _log(db, s, at=NOW - timedelta(seconds=i))

    live.on_access(db, s.session_id, now=NOW)

    assert model.calls == 1
    assert db.query(LiveSessionScore).one().n_events == 10


def test_warm_up_by_elapsed_time(db, standard_user, live_model):
    model = live_model(0.3)
    s = _session(db, standard_user, login=NOW - timedelta(minutes=6))
    _log(db, s)

    live.on_access(db, s.session_id, now=NOW)

    assert model.calls == 1
    assert db.query(LiveSessionScore).one().elapsed_sec == 360.0


def test_model_scoring_is_throttled_per_session(db, standard_user, live_model):
    model = live_model(0.3)
    s = _session(db, standard_user, login=NOW - timedelta(minutes=10))
    _log(db, s)

    live.on_access(db, s.session_id, now=NOW)
    live.on_access(db, s.session_id, now=NOW + timedelta(seconds=30))
    assert model.calls == 1

    live.on_access(db, s.session_id, now=NOW + timedelta(seconds=61))
    assert model.calls == 2


def test_anomalous_session_in_progress_raises_a_provisional_model_alert(db, standard_user, live_model):
    live_model(0.9)
    s = _session(db, standard_user, login=NOW - timedelta(minutes=10))
    _log(db, s)

    live.on_access(db, s.session_id, now=NOW)

    [alert] = _alerts(db, s, live.RULE_MODEL)
    evidence = json.loads(alert.evidence_json)[0]
    assert (evidence["score"], evidence["threshold"], evidence["risk_tier"]) == (0.9, 0.6, "standard")
    assert "provisional" in alert.summary
    assert alert.is_learning is True  # no earlier sessions; the threshold was not relaxed


def test_normal_session_in_progress_is_scored_but_not_flagged(db, standard_user, live_model):
    live_model(0.3)
    s = _session(db, standard_user, login=NOW - timedelta(minutes=10))
    _log(db, s)

    live.on_access(db, s.session_id, now=NOW)

    assert _alerts(db, s, live.RULE_MODEL) == []
    score = db.query(LiveSessionScore).one()
    assert (score.anomaly_score, score.threshold_used) == (0.3, 0.6)


def test_model_uses_the_users_risk_tier_threshold(db, make_role, make_user, live_model):
    tiers = {"high": 0.5, "standard": 0.6, "low": 0.7}
    live_model(0.55, tiers=tiers)
    finance = make_user(roles=[make_role("Finance Officer", [("payment", "read")])])
    standard = make_user(roles=[make_role("Standard User", [("user", "read")])])
    s_high = _session(db, finance, login=NOW - timedelta(minutes=10))
    s_std = _session(db, standard, login=NOW - timedelta(minutes=10))

    live.on_access(db, s_high.session_id, now=NOW)
    live.on_access(db, s_std.session_id, now=NOW)

    assert len(_alerts(db, s_high, live.RULE_MODEL)) == 1
    assert _alerts(db, s_std, live.RULE_MODEL) == []


def test_model_failure_never_breaks_the_request_or_the_rules(db, standard_user, live_model, monkeypatch):
    model = live_model(0.9)
    monkeypatch.setattr(model, "score_samples", lambda rows: (_ for _ in ()).throw(RuntimeError("bad model")))
    night = _local(3)
    s = _session(db, standard_user, login=night - timedelta(minutes=10))

    live.on_access(db, s.session_id, now=night)

    assert _alerts(db, s, live.RULE_MODEL) == []
    assert len(_alerts(db, s, live.RULE_UNUSUAL_HOUR)) == 1


def test_end_of_session_verdict_is_unchanged_and_training_is_untouched(db, standard_user, live_model, monkeypatch):
    from app.services import model_registry_service

    def _forbidden(*args, **kwargs):
        raise AssertionError("live detection must not train or write model files")

    monkeypatch.setattr(model_registry_service, "train_candidate", _forbidden)
    monkeypatch.setattr(anomaly_service.joblib, "dump", _forbidden)
    monkeypatch.setattr(anomaly_service.notification_service, "notify_admins_of_anomaly", lambda db, alert: None)
    live_model(0.9)
    s = _session(db, standard_user, login=datetime.utcnow() - timedelta(minutes=10))
    _log(db, s, at=datetime.utcnow())
    live.on_access(db, s.session_id)
    assert len(_alerts(db, s, live.RULE_MODEL)) == 1

    session_service.close_session(db, s.session_id)

    official = db.query(AnomalyAlert).filter(AnomalyAlert.session_id == s.session_id).one()
    assert official.detection_reason == anomaly_service.REASON_ML
    assert json.loads(official.features_json) == feature_engineering.build_session_feature_vector(db, s)
    assert db.query(LiveSessionScore).one().session_id == s.session_id  # kept next to the verdict
