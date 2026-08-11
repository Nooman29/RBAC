"""
Live Isolation Forest scoring service.

Loads the model artifacts produced by scripts/train_isolation_forest.py,
scores a single closed session, computes SHAP feature-contribution values
for that specific prediction, and writes an AnomalyAlert row.

SHAP note: shap.TreeExplainer explains the model's internal path-length
score, not the exact -score_samples() value we display as anomaly_score.
The relative RANKING of which features pushed the score toward "anomalous"
is meaningful and is what we surface; the raw shap numbers should not be
read as an exact numeric decomposition of anomaly_score.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import shap
from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.ml.feature_engineering import FEATURE_COLUMNS, build_session_feature_vector
from app.models.session import UserSession
from app.models.anomaly import AnomalyAlert

logger = logging.getLogger(__name__)

_model = None
_scaler = None
_threshold: Optional[float] = None
_explainer = None
_load_attempted = False

TOP_N_CONTRIBUTIONS = 6


def _load_artifacts() -> bool:
    global _model, _scaler, _threshold, _explainer, _load_attempted

    if _model is not None:
        return True
    if _load_attempted:
        return False
    _load_attempted = True

    model_path = Path(settings.ISOLATION_FOREST_MODEL_PATH)
    scaler_path = Path(settings.ISOLATION_FOREST_SCALER_PATH)
    threshold_path = Path(settings.ISOLATION_FOREST_THRESHOLD_PATH)

    if not (model_path.exists() and scaler_path.exists() and threshold_path.exists()):
        logger.warning(
            "Isolation Forest artifacts not found at %s. Anomaly scoring is "
            "disabled until scripts/train_isolation_forest.py has been run.",
            model_path,
        )
        return False

    _model = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    _threshold = json.loads(threshold_path.read_text())["threshold"]
    try:
        _explainer = shap.TreeExplainer(_model)
    except Exception:
        logger.exception("Failed to build SHAP explainer — alerts will save without explanations.")
        _explainer = None
    logger.info("Isolation Forest artifacts loaded. threshold=%.4f", _threshold)
    return True


def _compute_shap_contributions(scaled_row: np.ndarray) -> Optional[list]:
    if _explainer is None:
        return None
    try:
        sv = _explainer.shap_values(scaled_row)
        if isinstance(sv, list):
            sv = sv[0]
        row = np.array(sv)[0]
    except Exception:
        logger.exception("SHAP computation failed for this session — continuing without it.")
        return None

    contributions = [
        {
            "feature": FEATURE_COLUMNS[i],
            # Negated to match anomaly_score's convention (higher = more anomalous)
            "shap_value": float(-row[i]),
        }
        for i in range(len(FEATURE_COLUMNS))
    ]
    contributions.sort(key=lambda c: abs(c["shap_value"]), reverse=True)
    return contributions[:TOP_N_CONTRIBUTIONS]


def score_session(db: DBSession, session_id: int) -> Optional[AnomalyAlert]:
    if not _load_artifacts():
        return None

    session: Optional[UserSession] = (
        db.query(UserSession).filter(UserSession.session_id == session_id).first()
    )
    if session is None or session.session_duration is None:
        return None

    existing = db.query(AnomalyAlert).filter(AnomalyAlert.session_id == session_id).first()
    if existing:
        return existing

    features = build_session_feature_vector(db, session)
    ordered_values = [[features[col] for col in FEATURE_COLUMNS]]

    scaled = _scaler.transform(ordered_values)
    raw_score = float(-_model.score_samples(scaled)[0])
    is_anomaly = bool(raw_score >= _threshold)

    contributions = _compute_shap_contributions(scaled)

    alert = AnomalyAlert(
        session_id=session_id,
        anomaly_score=raw_score,
        is_anomaly=is_anomaly,
        features_json=json.dumps(features),
        shap_values_json=json.dumps(contributions) if contributions is not None else None,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    if is_anomaly:
        logger.info(
            "Anomaly flagged: session_id=%s user_id=%s score=%.4f (threshold=%.4f)",
            session_id, session.user_id, raw_score, _threshold,
        )

    return alert