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

Human feedback: administrator verdicts feed back into detection. A session
confirmed as a threat (even one the model let through) becomes precedent: later
sessions of the same user that trip every indicator it tripped are flagged.
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
from sqlalchemy import and_, or_

from app.core.config import settings
from app.ml.feature_engineering import FEATURE_COLUMNS, build_session_feature_vector
from app.models.session import UserSession
from app.models.anomaly import AnomalyAlert
from app.services import notification_service

logger = logging.getLogger(__name__)

_model = None
_scaler = None
_threshold: Optional[float] = None
_explainer = None
_load_attempted = False

TOP_N_CONTRIBUTIONS = 6

REASON_ML = "ml_model"
REASON_REPEAT = "repeat_pattern_override"        # matches an earlier flagged, still-unreviewed alert
REASON_CONFIRMED = "confirmed_threat_pattern"    # matches a pattern an administrator confirmed as a threat
CONFIRMED_THREAT = "confirmed_threat"

REPEAT_PATTERN_THRESHOLD = 1  # min prior flagged-and-unreviewed occurrences of the pattern


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


def _compute_pattern_signature(features: dict) -> str:
    flags = []
    if features.get("is_offhours"):
        flags.append("offhours")
    if features.get("is_weekend"):
        flags.append("weekend")
    if features.get("new_ip"):
        flags.append("newip")
    if features.get("n_write_zscore", 0) > 1.5:
        flags.append("highwrite")
    if features.get("n_delete_zscore", 0) > 1.5:
        flags.append("highdelete")
    if features.get("distinct_resources_zscore", 0) > 1.5:
        flags.append("highresourcevariety")
    if features.get("n_access_events_zscore", 0) > 1.5:
        flags.append("highvolume")
    return "|".join(sorted(flags)) if flags else "normal"


def _signature_flags(signature: Optional[str]) -> set:
    if not signature or signature == "normal":
        return set()
    return {flag for flag in signature.split("|") if flag}


def _find_precedent(db: DBSession, session: UserSession, signature: str) -> Optional[str]:
    """
    Has this user already done this before, in a way that mattered?

    Precedents are this user's other alerts that are either
      - confirmed as a threat by an administrator (flagged or NOT flagged by the model), or
      - flagged by the system and still unreviewed.
    Alerts cleared as false_positive / authorized_exception, and unflagged alerts with no
    verdict, never count.

    A precedent matches when the current session trips EVERY indicator the precedent
    tripped (extra indicators are fine). Returns the detection reason, or None.
    """
    current = _signature_flags(signature)
    if not current:
        return None

    rows = (
        db.query(AnomalyAlert.pattern_signature, AnomalyAlert.review_verdict)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.user_id == session.user_id,
            AnomalyAlert.session_id != session.session_id,
            AnomalyAlert.pattern_signature.isnot(None),
            or_(
                AnomalyAlert.review_verdict == CONFIRMED_THREAT,
                and_(AnomalyAlert.is_anomaly.is_(True), AnomalyAlert.review_verdict.is_(None)),
            ),
        )
        .all()
    )

    confirmed_matches = 0
    unreviewed_matches = 0
    for precedent_signature, verdict in rows:
        flags = _signature_flags(precedent_signature)
        if flags and flags <= current:
            if verdict == CONFIRMED_THREAT:
                confirmed_matches += 1
            else:
                unreviewed_matches += 1

    if confirmed_matches >= 1:
        return REASON_CONFIRMED
    if unreviewed_matches >= REPEAT_PATTERN_THRESHOLD:
        return REASON_REPEAT
    return None


def _is_repeat_offender(db: DBSession, session: UserSession, signature: str) -> bool:
    """Kept for compatibility with older callers."""
    return _find_precedent(db, session, signature) is not None


def score_session(
    db: DBSession, session_id: int, include_simulated_in_baseline: bool = False
) -> Optional[AnomalyAlert]:
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

    features = build_session_feature_vector(
        db, session, include_simulated_in_baseline=include_simulated_in_baseline
    )
    ordered_values = [[features[col] for col in FEATURE_COLUMNS]]

    scaled = _scaler.transform(ordered_values)
    raw_score = float(-_model.score_samples(scaled)[0])
    is_anomaly = bool(raw_score >= _threshold)

    signature = _compute_pattern_signature(features)
    detection_reason = REASON_ML

    if not is_anomaly:
        precedent_reason = _find_precedent(db, session, signature)
        if precedent_reason:
            is_anomaly = True
            detection_reason = precedent_reason
            logger.info(
                "Pattern match (%s): session_id=%s user_id=%s signature=%s "
                "(ML score %.4f was below threshold %.4f)",
                precedent_reason, session_id, session.user_id, signature, raw_score, _threshold,
            )

    contributions = _compute_shap_contributions(scaled)

    alert = AnomalyAlert(
        session_id=session_id,
        anomaly_score=raw_score,
        is_anomaly=is_anomaly,
        features_json=json.dumps(features),
        shap_values_json=json.dumps(contributions) if contributions is not None else None,
        detection_reason=detection_reason,
        pattern_signature=signature,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    if is_anomaly:
        logger.info(
            "Anomaly flagged: session_id=%s user_id=%s score=%.4f (threshold=%.4f)",
            session_id, session.user_id, raw_score, _threshold,
        )
        try:
            notification_service.notify_admins_of_anomaly(db, alert)
        except Exception:
            logger.exception("Failed to notify admins for alert_id=%s", alert.alert_id)

    return alert