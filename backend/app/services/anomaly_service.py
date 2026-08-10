"""
Live Isolation Forest scoring service.

Loads the model artifacts produced by scripts/train_isolation_forest.py
and scores a single closed session, writing an AnomalyAlert row.

Design notes:
- This is unsupervised, percentile-thresholded scoring — there is no
  ground truth for live data (unlike the CERT offline evaluation), so we
  cannot report a live F1/precision/recall. The threshold is the score
  percentile chosen at training time.
- Model artifacts are optional at runtime: if they don't exist yet (model
  not trained), scoring is skipped rather than raising, so session
  open/close flows never break because of the ML layer.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import joblib
from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.ml.feature_engineering import FEATURE_COLUMNS, build_session_feature_vector
from app.models.session import UserSession
from app.models.anomaly import AnomalyAlert

logger = logging.getLogger(__name__)

_model = None
_scaler = None
_threshold: Optional[float] = None
_load_attempted = False


def _load_artifacts() -> bool:
    """Lazy-load model/scaler/threshold once per process. True if available."""
    global _model, _scaler, _threshold, _load_attempted

    if _model is not None:
        return True
    if _load_attempted:
        # Already tried and failed this process lifetime — don't hit the
        # filesystem again on every single session close.
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
    logger.info("Isolation Forest artifacts loaded. threshold=%.4f", _threshold)
    return True


def score_session(db: DBSession, session_id: int) -> Optional[AnomalyAlert]:
    """
    Score a single closed session and persist an AnomalyAlert.
    Returns the AnomalyAlert, or None if scoring was skipped (model not
    trained yet, session not found, or session not yet closed).
    """
    if not _load_artifacts():
        return None

    session: Optional[UserSession] = (
        db.query(UserSession).filter(UserSession.session_id == session_id).first()
    )
    if session is None or session.session_duration is None:
        return None  # must be closed (logout_time set) to have full features

    existing = db.query(AnomalyAlert).filter(AnomalyAlert.session_id == session_id).first()
    if existing:
        return existing  # don't double-score

    features = build_session_feature_vector(db, session)
    ordered_values = [[features[col] for col in FEATURE_COLUMNS]]

    scaled = _scaler.transform(ordered_values)
    # -score_samples: higher = more anomalous, matching the notebook's convention
    raw_score = float(-_model.score_samples(scaled)[0])
    is_anomaly = bool(raw_score >= _threshold)

    alert = AnomalyAlert(
        session_id=session_id,
        anomaly_score=raw_score,
        is_anomaly=is_anomaly,
        features_json=json.dumps(features),
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