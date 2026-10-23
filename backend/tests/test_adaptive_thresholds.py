"""Pass 2: role-tiered thresholds and the cold-start (learning period) flag."""
from datetime import datetime, timedelta

import numpy as np
import pytest

from app.core.dsfs_catalog import (
    RISK_TIERS, ROLE_RISK_TIERS, ROLE_SCOPES, TIER_PERCENTILES, risk_tier_for_roles,
)
from app.models.role import Role
from app.models.session import UserSession
from app.services import anomaly_service

TIERS = {"high": 0.5, "standard": 0.6, "low": 0.7}


class _StubModel:
    def __init__(self, score):
        self.score = score

    def score_samples(self, rows):
        return np.array([-self.score] * len(rows))


class _IdentityScaler:
    def transform(self, rows):
        return np.asarray(rows, dtype=float)


@pytest.fixture
def stub(monkeypatch):
    monkeypatch.setattr(anomaly_service, "_scaler", _IdentityScaler())
    monkeypatch.setattr(anomaly_service, "_threshold", 0.6)
    monkeypatch.setattr(anomaly_service, "_tier_thresholds", dict(TIERS))
    monkeypatch.setattr(anomaly_service, "_explainer", None)
    monkeypatch.setattr(anomaly_service.notification_service, "notify_admins_of_anomaly", lambda db, alert: None)

    def _use(score):
        monkeypatch.setattr(anomaly_service, "_model", _StubModel(score))

    return _use


def _with_role(db, user, role_name):
    role = db.query(Role).filter(Role.role_name == role_name).first()
    if role is None:
        role = Role(role_name=role_name, scope=ROLE_SCOPES.get(role_name, "own"))
        db.add(role)
        db.commit()
    user.roles = [role]
    db.commit()
    return user


def _closed_session(db, user, login_time=None):
    s = UserSession(user_id=user.user_id, session_duration=120.0, access_location="10.0.0.1",
                    login_time=login_time or datetime.utcnow())
    db.add(s)
    db.commit()
    return s


# ---- catalog -------------------------------------------------------------

def test_every_role_has_a_valid_tier_and_tiers_are_ordered():
    for role in ROLE_SCOPES:
        assert ROLE_RISK_TIERS.get(role, "standard") in RISK_TIERS
    assert TIER_PERCENTILES["high"] < TIER_PERCENTILES["standard"] < TIER_PERCENTILES["low"]


def test_original_roles_keep_the_standard_tier():
    for role in ["Administrator", "Manager", "Standard User"]:
        assert risk_tier_for_roles([role]) == "standard"


def test_tier_for_roles():
    assert risk_tier_for_roles(["Finance Officer"]) == "high"
    assert risk_tier_for_roles(["Parent/Guardian"]) == "low"
    assert risk_tier_for_roles(["Parent/Guardian", "Teacher"]) == "standard"   # strictest wins
    assert risk_tier_for_roles(["Teacher", "Auditor"]) == "high"
    assert risk_tier_for_roles([]) == "standard"
    assert risk_tier_for_roles(["Some New Role"]) == "standard"


def test_threshold_falls_back_to_the_single_threshold(monkeypatch):
    monkeypatch.setattr(anomaly_service, "_threshold", 0.6)
    monkeypatch.setattr(anomaly_service, "_tier_thresholds", None)
    for tier in RISK_TIERS:
        assert anomaly_service._threshold_for_tier(tier) == pytest.approx(0.6)


# ---- scoring -------------------------------------------------------------

def test_same_score_flags_a_high_tier_user_but_not_a_standard_one(db, make_user, stub):
    stub(0.55)
    finance = _with_role(db, make_user(), "Finance Officer")
    teacher = _with_role(db, make_user(), "Teacher")

    a_high = anomaly_service.score_session(db, _closed_session(db, finance).session_id)
    a_std = anomaly_service.score_session(db, _closed_session(db, teacher).session_id)

    assert a_high.is_anomaly is True
    assert a_high.risk_tier == "high"
    assert a_high.threshold_used == pytest.approx(0.5)
    assert a_std.is_anomaly is False
    assert a_std.risk_tier == "standard"
    assert a_std.threshold_used == pytest.approx(0.6)


def test_low_tier_user_uses_the_looser_threshold(db, make_user, stub):
    stub(0.65)
    parent = _with_role(db, make_user(), "Parent/Guardian")

    alert = anomaly_service.score_session(db, _closed_session(db, parent).session_id)

    assert alert.risk_tier == "low"
    assert alert.threshold_used == pytest.approx(0.7)
    assert alert.is_anomaly is False


def test_new_user_is_in_the_learning_period(db, make_user, stub):
    stub(0.2)
    user = _with_role(db, make_user(), "Teacher")

    alert = anomaly_service.score_session(db, _closed_session(db, user).session_id)

    assert alert.is_learning is True
    assert alert.prior_sessions == 0


def test_learning_period_ends_after_enough_history(db, make_user, stub):
    stub(0.2)
    user = _with_role(db, make_user(), "Teacher")
    now = datetime.utcnow()
    needed = anomaly_service.MIN_HISTORY_FOR_ZSCORE
    for i in range(needed):
        _closed_session(db, user, login_time=now - timedelta(days=i + 1))

    alert = anomaly_service.score_session(db, _closed_session(db, user, login_time=now).session_id)

    assert alert.prior_sessions == needed
    assert alert.is_learning is False


def test_simulated_sessions_do_not_count_as_history(db, make_user, stub):
    stub(0.2)
    user = _with_role(db, make_user(), "Teacher")
    now = datetime.utcnow()
    for i in range(anomaly_service.MIN_HISTORY_FOR_ZSCORE):
        s = _closed_session(db, user, login_time=now - timedelta(days=i + 1))
        s.simulated_scenario = "unusual_login_time"
    db.commit()

    alert = anomaly_service.score_session(db, _closed_session(db, user, login_time=now).session_id)

    assert alert.prior_sessions == 0
    assert alert.is_learning is True
