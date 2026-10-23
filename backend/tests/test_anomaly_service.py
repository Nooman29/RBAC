import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.ml.feature_engineering import FEATURE_COLUMNS
from app.models.anomaly import AnomalyAlert
from app.models.session import UserSession
from app.services import anomaly_service


class _StubModel:
    def __init__(self, score):
        self.score = score

    def score_samples(self, rows):
        return np.array([-self.score] * len(rows))


class _IdentityScaler:
    def transform(self, rows):
        return np.asarray(rows, dtype=float)


@pytest.fixture
def stub_artifacts(monkeypatch):
    notified = []
    monkeypatch.setattr(anomaly_service, "_scaler", _IdentityScaler())
    monkeypatch.setattr(anomaly_service, "_threshold", 0.6)
    monkeypatch.setattr(anomaly_service, "_tier_thresholds", None)  # single threshold for every tier
    monkeypatch.setattr(anomaly_service, "_explainer", None)
    monkeypatch.setattr(anomaly_service.notification_service, "notify_admins_of_anomaly",
                        lambda db, alert: notified.append(alert.alert_id))

    def _use(score):
        monkeypatch.setattr(anomaly_service, "_model", _StubModel(score))
        return notified

    return _use


def _closed_session(db, user):
    s = UserSession(user_id=user.user_id, session_duration=120.0, access_location="10.0.0.1")
    db.add(s)
    db.commit()
    return s


def test_isolation_forest_scores_outlier_above_threshold_and_normal_below():
    rng = np.random.default_rng(42)
    normal = rng.normal(0, 1, size=(500, len(FEATURE_COLUMNS)))
    scaler = StandardScaler().fit(normal)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(scaler.transform(normal))
    threshold = np.percentile(-model.score_samples(scaler.transform(normal)), 99)

    typical = np.zeros((1, len(FEATURE_COLUMNS)))
    outlier = np.full((1, len(FEATURE_COLUMNS)), 8.0)

    assert -model.score_samples(scaler.transform(typical))[0] < threshold
    assert -model.score_samples(scaler.transform(outlier))[0] >= threshold


def test_pattern_signature_is_normal_without_flags():
    assert anomaly_service._compute_pattern_signature({}) == "normal"


def test_pattern_signature_is_sorted_and_stable():
    features = {"new_ip": 1, "is_offhours": 1, "n_delete_zscore": 3.0, "n_write_zscore": 0.2}

    assert anomaly_service._compute_pattern_signature(features) == "highdelete|newip|offhours"


def test_score_session_returns_none_when_artifacts_missing(db, make_user, monkeypatch, tmp_path):
    monkeypatch.setattr(anomaly_service, "_model", None)
    monkeypatch.setattr(anomaly_service, "_load_attempted", False)
    monkeypatch.setattr(anomaly_service.settings, "ISOLATION_FOREST_MODEL_PATH", str(tmp_path / "missing.joblib"))
    s = _closed_session(db, make_user())

    assert anomaly_service.score_session(db, s.session_id) is None
    assert db.query(AnomalyAlert).count() == 0


def test_score_above_threshold_creates_alert_and_notifies_admins(db, make_user, stub_artifacts):
    notified = stub_artifacts(0.9)
    s = _closed_session(db, make_user())

    alert = anomaly_service.score_session(db, s.session_id)

    assert alert.is_anomaly is True
    assert alert.anomaly_score == pytest.approx(0.9)
    assert alert.detection_reason == "ml_model"
    assert alert.threshold_used == pytest.approx(0.6)
    assert notified == [alert.alert_id]


def test_score_below_threshold_is_recorded_but_not_notified(db, make_user, stub_artifacts):
    notified = stub_artifacts(0.2)
    s = _closed_session(db, make_user())

    alert = anomaly_service.score_session(db, s.session_id)

    assert alert.is_anomaly is False
    assert notified == []


def test_scoring_is_idempotent_per_session(db, make_user, stub_artifacts):
    stub_artifacts(0.9)
    s = _closed_session(db, make_user())

    first = anomaly_service.score_session(db, s.session_id)
    second = anomaly_service.score_session(db, s.session_id)

    assert first.alert_id == second.alert_id
    assert db.query(AnomalyAlert).count() == 1
