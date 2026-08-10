"""
Offline training script for the live-schema Isolation Forest model.

Run manually from backend/ (not part of the FastAPI app):
    python -m scripts.train_isolation_forest

Reads all CLOSED sessions from the live database, builds the same feature
vectors app/services/anomaly_service.py uses at inference time (via
app.ml.feature_engineering, so training and inference can never drift
apart), trains IsolationForest, and persists:
    - isolation_forest.joblib   (fitted model)
    - scaler.joblib             (fitted StandardScaler)
    - threshold.json            (score cutoff used to flag anomalies)

Threshold strategy:
    There is no ground-truth label for live sessions (unlike CERT), so we
    can't tune a threshold against F1 the way the offline notebook did.
    Instead the threshold is a chosen PERCENTILE of the training score
    distribution (default: top 5% most anomalous = flagged) — a first,
    honest, deployable baseline until enough live volume exists to do
    proper validation the way the CERT notebook did.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # allow `app.*` imports

from app.core.config import settings
from app.db.database import SessionLocal
from app.ml.feature_engineering import FEATURE_COLUMNS, build_session_feature_vector
from app.models.session import UserSession

MIN_SESSIONS_TO_TRAIN = 30  # sanity floor; below this, z-scores are meaningless
ANOMALY_PERCENTILE = 95     # top 5% of scores flagged as anomalous


def load_training_table(db) -> tuple[list[int], np.ndarray]:
    sessions = (
        db.query(UserSession)
        .filter(UserSession.session_duration.isnot(None))
        .order_by(UserSession.login_time.asc())
        .all()
    )
    session_ids, rows = [], []
    for s in sessions:
        features = build_session_feature_vector(db, s)
        rows.append([features[col] for col in FEATURE_COLUMNS])
        session_ids.append(s.session_id)
    return session_ids, np.array(rows, dtype=float)


def main():
    db = SessionLocal()
    try:
        session_ids, X = load_training_table(db)
    finally:
        db.close()

    n = len(session_ids)
    print(f"Loaded {n} closed sessions for training.")
    if n < MIN_SESSIONS_TO_TRAIN:
        print(
            f"Only {n} closed sessions found (< {MIN_SESSIONS_TO_TRAIN}). "
            f"Run scripts/seed_synthetic_data.py first, or wait for more real usage."
        )
        return

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    scores = -model.score_samples(X_scaled)
    threshold = float(np.percentile(scores, ANOMALY_PERCENTILE))
    flagged = int((scores >= threshold).sum())

    print(f"Training score distribution: min={scores.min():.4f} "
          f"mean={scores.mean():.4f} max={scores.max():.4f}")
    print(f"Threshold @ p{ANOMALY_PERCENTILE}: {threshold:.4f} "
          f"-> {flagged}/{n} training sessions flagged")

    model_path = Path(settings.ISOLATION_FOREST_MODEL_PATH)
    scaler_path = Path(settings.ISOLATION_FOREST_SCALER_PATH)
    threshold_path = Path(settings.ISOLATION_FOREST_THRESHOLD_PATH)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    threshold_path.write_text(json.dumps({
        "threshold": threshold,
        "percentile": ANOMALY_PERCENTILE,
        "trained_on_n_sessions": n,
        "feature_columns": FEATURE_COLUMNS,
    }, indent=2))

    print(f"Saved model     -> {model_path}")
    print(f"Saved scaler    -> {scaler_path}")
    print(f"Saved threshold -> {threshold_path}")


if __name__ == "__main__":
    main()