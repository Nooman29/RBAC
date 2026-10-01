from datetime import datetime, timedelta

import pytest

from app.ml import feature_engineering as fe
from app.models.anomaly import AnomalyAlert
from app.models.session import AccessLog, UserSession

SATURDAY_NIGHT = datetime(2026, 8, 8, 23, 15)


def _session(db, user, login_time, duration=None, location=None, simulated=None, actions=()):
    s = UserSession(
        user_id=user.user_id,
        login_time=login_time,
        session_duration=duration,
        access_location=location,
        simulated_scenario=simulated,
    )
    db.add(s)
    db.commit()
    for resource, action in actions:
        db.add(AccessLog(session_id=s.session_id, resource_name=resource, action_performed=action))
    db.commit()
    return s


def test_feature_columns_are_raw_plus_zscores_in_fixed_order():
    assert len(fe.FEATURE_COLUMNS) == len(fe.RAW_FEATURE_COLUMNS) + len(fe.ZSCORE_SOURCE_COLUMNS)
    assert fe.FEATURE_COLUMNS[: len(fe.RAW_FEATURE_COLUMNS)] == fe.RAW_FEATURE_COLUMNS
    assert all(c.endswith("_zscore") for c in fe.FEATURE_COLUMNS[len(fe.RAW_FEATURE_COLUMNS):])


@pytest.mark.parametrize("hour,expected", [(6, 1), (7, 0), (12, 0), (19, 0), (20, 1), (23, 1)])
def test_offhours_boundaries(hour, expected):
    assert fe._offhours(hour) == expected


def test_raw_features_count_actions_and_time_context(db, make_user):
    user = make_user()
    s = _session(
        db, user, SATURDAY_NIGHT, duration=600.0, location="10.0.0.1",
        actions=[("users", "read"), ("users", "read"), ("roles", "write"), ("users", "delete")],
    )

    raw = fe.build_raw_session_features(db, s)

    assert raw["login_hour"] == 23
    assert raw["is_offhours"] == 1
    assert raw["is_weekend"] == 1
    assert raw["session_duration_sec"] == 600.0
    assert raw["n_access_events"] == 4
    assert raw["distinct_resources"] == 2
    assert raw["distinct_actions"] == 3
    assert (raw["n_read"], raw["n_write"], raw["n_delete"]) == (2, 1, 1)


def test_new_ip_flag_compares_against_prior_locations(db, make_user):
    user = make_user()
    _session(db, user, SATURDAY_NIGHT - timedelta(days=1), duration=60, location="10.0.0.1")
    known = _session(db, user, SATURDAY_NIGHT, duration=60, location="10.0.0.1")
    unknown = _session(db, user, SATURDAY_NIGHT + timedelta(hours=1), duration=60, location="203.0.113.9")

    assert fe.build_raw_session_features(db, known)["new_ip"] == 0
    assert fe.build_raw_session_features(db, unknown)["new_ip"] == 1


def test_baseline_excludes_simulated_and_unreviewed_flagged_sessions(db, make_user):
    user = make_user()
    base = SATURDAY_NIGHT - timedelta(days=10)
    _session(db, user, base, duration=100.0)
    _session(db, user, base + timedelta(days=1), duration=300.0)
    _session(db, user, base + timedelta(days=2), duration=10_000.0, simulated="privilege_escalation")
    flagged = _session(db, user, base + timedelta(days=3), duration=5_000.0)
    db.add(AnomalyAlert(session_id=flagged.session_id, anomaly_score=0.9, is_anomaly=True))
    db.commit()

    stats = fe.build_user_history_stats(db, user.user_id)

    assert stats["session_duration_sec_mean"] == pytest.approx(200.0)
    assert stats["session_duration_sec_std"] == pytest.approx(100.0)


def test_false_positive_verdict_returns_session_to_baseline(db, make_user):
    user = make_user()
    s = _session(db, user, SATURDAY_NIGHT, duration=500.0)
    db.add(AnomalyAlert(session_id=s.session_id, anomaly_score=0.9, is_anomaly=True,
                        review_verdict="false_positive"))
    db.commit()

    stats = fe.build_user_history_stats(db, user.user_id)

    assert stats["session_duration_sec_mean"] == pytest.approx(500.0)


def test_feature_vector_zscore_against_user_history(db, make_user):
    user = make_user()
    base = SATURDAY_NIGHT - timedelta(days=10)
    _session(db, user, base, duration=100.0)
    _session(db, user, base + timedelta(days=1), duration=300.0)
    target = _session(db, user, SATURDAY_NIGHT, duration=400.0)

    vector = fe.build_session_feature_vector(db, target)

    assert list(vector) == fe.FEATURE_COLUMNS
    assert vector["session_duration_sec_zscore"] == pytest.approx(2.0, rel=1e-4)
