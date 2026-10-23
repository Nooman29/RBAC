"""
Offline training script for the live-schema Isolation Forest model.

Run manually from backend/ (not part of the FastAPI app):
    python -m scripts.train_isolation_forest

Reads CLOSED sessions from the live database, builds the same feature
vectors app/services/anomaly_service.py uses at inference time (via
app.ml.feature_engineering, so training and inference can never drift
apart), trains IsolationForest, and persists:
    - isolation_forest.joblib   (fitted model)
    - scaler.joblib             (fitted StandardScaler)
    - threshold.json            (score cutoff used to flag anomalies)

Which sessions are used:
    Only sessions that count as NORMAL behaviour, by the same rule the per-user baseline uses:
      - simulated attack sessions are never used
      - sessions confirmed as threats (even ones the model missed) are never used
      - flagged sessions still awaiting review are not used
      - sessions an administrator cleared (false positive / authorized exception) are used
    Otherwise retraining after a demo would teach the model that the demo attacks are normal.

Threshold strategy:
    There is no ground-truth label for live sessions (unlike CERT), so we
    can't tune a threshold against F1 the way the offline notebook did.
    Instead each threshold is a chosen PERCENTILE of the training score
    distribution. One cutoff is saved per risk tier (app.core.dsfs_catalog):
        high     -> 90th percentile (stricter: finance, programme-wide, audit roles)
        standard -> 95th percentile (default; also stored as "threshold")
        low      -> 97th percentile (looser: read-only access to own records)
    The role-tiered strategy was benchmarked in scripts/model_experiments.py.

After training, restart the backend so it reloads the new artifacts.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy import and_, or_

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # allow `app.*` imports

from app.core.config import settings
from app.core.dsfs_catalog import TIER_PERCENTILES
from app.db.database import SessionLocal
from app.ml.feature_engineering import FEATURE_COLUMNS, build_session_feature_vector
from app.models.anomaly import AnomalyAlert
from app.models.session import UserSession

MIN_SESSIONS_TO_TRAIN = 30  # sanity floor; below this, z-scores are meaningless
ANOMALY_PERCENTILE = TIER_PERCENTILES["standard"]  # default: top 5% of scores flagged


def load_training_table(db) -> tuple[list[int], np.ndarray, int]:
    closed = db.query(UserSession).filter(UserSession.session_duration.isnot(None))
    total_closed = closed.count()

    sessions = (
        closed.outerjoin(AnomalyAlert, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.simulated_scenario.is_(None),
            or_(
                AnomalyAlert.alert_id.is_(None),
                and_(
                    AnomalyAlert.is_anomaly.is_(False),
                    or_(
                        AnomalyAlert.review_verdict.is_(None),
                        AnomalyAlert.review_verdict != "confirmed_threat",
                    ),
                ),
                AnomalyAlert.review_verdict.in_(["false_positive", "authorized_exception"]),
            ),
        )
        .order_by(UserSession.login_time.asc())
        .all()
    )

    session_ids, rows = [], []
    for s in sessions:
        features = build_session_feature_vector(db, s)
        rows.append([features[col] for col in FEATURE_COLUMNS])
        session_ids.append(s.session_id)
    return session_ids, np.array(rows, dtype=float), total_closed


def main():
    db = SessionLocal()
    try:
        session_ids, X, total_closed = load_training_table(db)
    finally:
        db.close()

    n = len(session_ids)
    print(f"Loaded {n} sessions for training "
          f"({total_closed - n} of {total_closed} closed sessions excluded: simulated attacks, "
          f"confirmed threats, or flagged and not yet reviewed).")
    if n < MIN_SESSIONS_TO_TRAIN:
        print(
            f"Only {n} usable sessions found (< {MIN_SESSIONS_TO_TRAIN}). "
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
    tier_thresholds = {tier: float(np.percentile(scores, pct)) for tier, pct in TIER_PERCENTILES.items()}

    print(f"Training score distribution: min={scores.min():.4f} "
          f"mean={scores.mean():.4f} max={scores.max():.4f}")
    print(f"Threshold @ p{ANOMALY_PERCENTILE}: {threshold:.4f} "
          f"-> {flagged}/{n} training sessions flagged")
    for tier, pct in TIER_PERCENTILES.items():
        t = tier_thresholds[tier]
        print(f"  {tier:<8} tier @ p{pct}: {t:.4f} -> {int((scores >= t).sum())}/{n} flagged")

    model_path = Path(settings.ISOLATION_FOREST_MODEL_PATH)
    scaler_path = Path(settings.ISOLATION_FOREST_SCALER_PATH)
    threshold_path = Path(settings.ISOLATION_FOREST_THRESHOLD_PATH)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    threshold_path.write_text(json.dumps({
        "threshold": threshold,
        "percentile": ANOMALY_PERCENTILE,
        "tier_thresholds": tier_thresholds,
        "tier_percentiles": TIER_PERCENTILES,
        "trained_on_n_sessions": n,
        "feature_columns": FEATURE_COLUMNS,
    }, indent=2))

    print(f"Saved model     -> {model_path}")
    print(f"Saved scaler    -> {scaler_path}")
    print(f"Saved threshold -> {threshold_path}")
    print("Restart the backend so it loads the new model: docker compose restart backend")


if __name__ == "__main__":
    main()