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


def _history(db, user, durations, actions=(), start=None):
    start = start or SATURDAY_NIGHT - timedelta(days=60)
    return [
        _session(db, user, start + timedelta(days=i), duration=d, actions=actions)
        for i, d in enumerate(durations)
    ]


def _zscores(vector):
    return {c: vector[f"{c}_zscore"] for c in fe.ZSCORE_SOURCE_COLUMNS}


def test_feature_columns_are_raw_plus_zscores_in_fixed_order():
    assert len(fe.FEATURE_COLUMNS) == len(fe.RAW_FEATURE_COLUMNS) + len(fe.ZSCORE_SOURCE_COLUMNS)
    assert fe.FEATURE_COLUMNS[: len(fe.RAW_FEATURE_COLUMNS)] == fe.RAW_FEATURE_COLUMNS
    assert all(c.endswith("_zscore") for c in fe.FEATURE_COLUMNS[len(fe.RAW_FEATURE_COLUMNS):])


def test_every_zscore_source_has_a_std_floor():
    assert set(fe.MIN_STD) == set(fe.ZSCORE_SOURCE_COLUMNS)


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

    assert stats["n_sessions"] == 2
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


# ---- z-score behaviour -----------------------------------------------------------------------

def test_feature_vector_zscore_against_user_history(db, make_user):
    user = make_user()
    _history(db, user, [100.0, 300.0] * 3)          # mean 200, std 100 (above both floors)
    target = _session(db, user, SATURDAY_NIGHT, duration=400.0)

    vector = fe.build_session_feature_vector(db, target)

    assert list(vector) == fe.FEATURE_COLUMNS
    assert vector["session_duration_sec_zscore"] == pytest.approx(2.0, rel=1e-4)


def test_user_with_no_history_gets_neutral_zscores(db, make_user):
    user = make_user()
    target = _session(db, user, SATURDAY_NIGHT, duration=1800.0, actions=[("dashboard", "read")] * 6)

    vector = fe.build_session_feature_vector(db, target)

    assert all(z == 0.0 for z in _zscores(vector).values())


def test_short_history_gets_neutral_zscores(db, make_user):
    user = make_user()
    _history(db, user, [100.0, 200.0, 300.0, 400.0])    # one short of the minimum
    target = _session(db, user, SATURDAY_NIGHT, duration=5000.0)

    vector = fe.build_session_feature_vector(db, target)

    assert all(z == 0.0 for z in _zscores(vector).values())


def test_minimum_history_is_inclusive(db, make_user):
    user = make_user()
    _history(db, user, [100.0, 200.0, 300.0, 400.0, 500.0])   # mean 300, std ~141.4
    target = _session(db, user, SATURDAY_NIGHT, duration=600.0)

    vector = fe.build_session_feature_vector(db, target)

    assert vector["session_duration_sec_zscore"] == pytest.approx(300.0 / (20000.0 ** 0.5), rel=1e-4)


def test_simulated_sessions_do_not_count_toward_history_length(db, make_user):
    user = make_user()
    start = SATURDAY_NIGHT - timedelta(days=60)
    for i in range(3):
        _session(db, user, start + timedelta(days=i), duration=100.0 * (i + 1))
    for i in range(3):
        _session(db, user, start + timedelta(days=10 + i), duration=9000.0, simulated="snooping")
    target = _session(db, user, SATURDAY_NIGHT, duration=400.0)

    vector = fe.build_session_feature_vector(db, target)

    assert all(z == 0.0 for z in _zscores(vector).values())     # only 3 real sessions


def test_uniform_history_does_not_explode(db, make_user):
    user = make_user()
    _history(db, user, [1000.0] * 6)                      # std is exactly 0
    target = _session(db, user, SATURDAY_NIGHT, duration=1100.0)

    vector = fe.build_session_feature_vector(db, target)

    # scale = max(std 0, 10% of 1000 = 100, floor 60) = 100
    assert vector["session_duration_sec_zscore"] == pytest.approx(1.0, rel=1e-4)


def test_count_features_use_an_absolute_floor(db, make_user):
    user = make_user()
    _history(db, user, [900.0] * 6, actions=[("dashboard", "read")] * 6)   # always 6 reads
    target = _session(db, user, SATURDAY_NIGHT, duration=900.0, actions=[("dashboard", "read")] * 8)

    vector = fe.build_session_feature_vector(db, target)

    # n_access_events: mean 6, std 0, scale = max(0, 0.6, 1.0) = 1.0 -> z = 2.0 (it was ~2,000,000 before)
    assert vector["n_access_events_zscore"] == pytest.approx(2.0, rel=1e-4)


def test_zscores_are_clamped(db, make_user):
    user = make_user()
    _history(db, user, [1000.0] * 6, actions=[("dashboard", "read")] * 6)
    target = _session(db, user, SATURDAY_NIGHT, duration=1_000_000.0, actions=[("dashboard", "delete")] * 500)

    vector = fe.build_session_feature_vector(db, target)

    assert vector["session_duration_sec_zscore"] == pytest.approx(fe.Z_CLIP)
    assert vector["n_access_events_zscore"] == pytest.approx(fe.Z_CLIP)
    assert all(-fe.Z_CLIP <= z <= fe.Z_CLIP for z in _zscores(vector).values())