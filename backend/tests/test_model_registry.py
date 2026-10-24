"""Pass 3: versioned models, guardrails, promotion/rollback, drift."""
import json
from datetime import datetime, timedelta

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.core.config import settings
from app.ml.feature_engineering import FEATURE_COLUMNS
from app.models.session import UserSession
from app.services import anomaly_service
from app.services import model_registry_service as registry


# ---- pure: guardrails ----------------------------------------------------

def _guard(**overrides):
    args = dict(n_sessions=500, train_score_std=0.05, n_holdout=100, holdout_flag_rate=0.05,
                n_known_bad=40, known_bad_rate_new=0.95, known_bad_rate_live=0.95)
    args.update(overrides)
    return {c["name"]: c for c in registry.evaluate_guardrails(**args)}


def test_healthy_candidate_passes_every_check():
    checks = _guard()
    assert all(c["passed"] and not c["skipped"] for c in checks.values())


def test_too_little_data_fails():
    assert not _guard(n_sessions=10)["enough_data"]["passed"]


def test_constant_scores_fail():
    assert not _guard(train_score_std=0.0)["scores_vary"]["passed"]


def test_too_many_recent_false_alarms_fail():
    assert not _guard(holdout_flag_rate=0.30)["recent_false_alarms"]["passed"]


def test_recent_check_is_skipped_with_few_recent_sessions():
    c = _guard(n_holdout=5, holdout_flag_rate=0.6)["recent_false_alarms"]
    assert c["passed"] and c["skipped"]


def test_forgetting_known_attacks_fails():
    assert not _guard(known_bad_rate_new=0.60, known_bad_rate_live=0.95)["known_attacks"]["passed"]
    assert _guard(known_bad_rate_new=0.90, known_bad_rate_live=0.95)["known_attacks"]["passed"]


def test_known_attack_check_without_live_model_passes():
    c = _guard(known_bad_rate_live=None)["known_attacks"]
    assert c["passed"] and not c["skipped"]


# ---- pure: drift -----------------------------------------------------------

def _drift(**overrides):
    args = dict(scores=[0.40] * 100, ml_flagged=5, train_mean=0.40, train_std=0.05,
                age_days=1, new_sessions=10, n_train=500, interval_days=7)
    args.update(overrides)
    return registry.assess_drift(**args)


def test_stable_when_behaviour_matches_training():
    d = _drift()
    assert d["status"] == "stable"
    assert d["retrain_recommended"] is False


def test_insufficient_data_with_few_recent_sessions():
    assert _drift(scores=[0.4] * 5, ml_flagged=0)["status"] == "insufficient_data"


def test_high_flag_rate_is_drift():
    d = _drift(ml_flagged=30)
    assert d["status"] == "drifting"
    assert d["retrain_recommended"] is True


def test_score_shift_is_drift():
    d = _drift(scores=[0.50] * 100)
    assert d["status"] == "drifting"
    assert d["mean_shift"] == pytest.approx(2.0)


def test_old_model_recommends_retrain_without_drift():
    d = _drift(age_days=10)
    assert d["status"] == "stable"
    assert d["retrain_recommended"] is True


# ---- workflow against the test database -----------------------------------

@pytest.fixture
def model_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ISOLATION_FOREST_MODEL_PATH", str(tmp_path / "isolation_forest.joblib"))
    monkeypatch.setattr(settings, "ISOLATION_FOREST_SCALER_PATH", str(tmp_path / "scaler.joblib"))
    monkeypatch.setattr(settings, "ISOLATION_FOREST_THRESHOLD_PATH", str(tmp_path / "threshold.json"))
    # promotion reloads the scoring service; restore its state after the test
    for name in ["_model", "_scaler", "_threshold", "_tier_thresholds", "_explainer", "_load_attempted"]:
        monkeypatch.setattr(anomaly_service, name, getattr(anomaly_service, name, None))
    return tmp_path


def _add_sessions(db, user, n):
    start = datetime.utcnow() - timedelta(days=n + 1)
    for i in range(n):
        login = start + timedelta(days=i, hours=8 + (i % 5))
        duration = 300.0 + (i % 7) * 60
        db.add(UserSession(user_id=user.user_id, session_duration=duration, access_location="10.0.0.1",
                           login_time=login, logout_time=login + timedelta(seconds=duration)))
    db.commit()


def test_not_enough_data_raises(db, make_user, model_dir):
    _add_sessions(db, make_user(), 5)
    with pytest.raises(registry.NotEnoughData):
        registry.train_candidate(db, triggered_by="test")


def test_first_version_is_saved_promoted_and_loaded(db, make_user, model_dir):
    _add_sessions(db, make_user(), 40)

    record = registry.train_candidate(db, triggered_by="test")

    assert record["passed"] is True
    assert record["status"] == "live"
    assert (model_dir / "versions" / record["version_id"] / "isolation_forest.joblib").exists()
    assert (model_dir / "isolation_forest.joblib").exists()
    meta = json.loads((model_dir / "threshold.json").read_text())
    assert meta["version_id"] == record["version_id"]
    assert set(meta["tier_thresholds"]) == {"high", "standard", "low"}
    assert registry.load_registry()["current"] == record["version_id"]
    assert anomaly_service._model is not None  # hot reload happened


def test_rollback_to_an_earlier_version(db, make_user, model_dir):
    _add_sessions(db, make_user(), 40)
    first = registry.train_candidate(db, triggered_by="test")
    second = registry.train_candidate(db, triggered_by="test")
    assert first["version_id"] != second["version_id"]

    registry.promote_version(first["version_id"])

    reg = registry.load_registry()
    statuses = {v["version_id"]: v["status"] for v in reg["versions"]}
    assert reg["current"] == first["version_id"]
    assert statuses[first["version_id"]] == "live"
    assert statuses[second["version_id"]] == "previous"
    assert json.loads((model_dir / "threshold.json").read_text())["version_id"] == first["version_id"]


def test_failed_version_cannot_be_promoted(db, make_user, model_dir):
    _add_sessions(db, make_user(), 40)
    record = registry.train_candidate(db, triggered_by="test", promote=False)
    reg = registry.load_registry()
    registry._find(reg, record["version_id"])["passed"] = False
    registry._save_registry(reg)

    with pytest.raises(registry.PromotionRefused):
        registry.promote_version(record["version_id"])


def test_existing_model_is_imported_as_legacy_version(model_dir):
    X = np.random.default_rng(0).normal(size=(50, len(FEATURE_COLUMNS)))
    scaler = StandardScaler().fit(X)
    joblib.dump(IsolationForest(n_estimators=10, random_state=0).fit(scaler.transform(X)),
                model_dir / "isolation_forest.joblib")
    joblib.dump(scaler, model_dir / "scaler.joblib")
    (model_dir / "threshold.json").write_text(json.dumps({"threshold": 0.55, "trained_on_n_sessions": 50}))

    reg = registry.load_registry()

    assert len(reg["versions"]) == 1
    legacy = reg["versions"][0]
    assert legacy["version_id"].startswith("legacy-")
    assert legacy["status"] == "live" and reg["current"] == legacy["version_id"]