"""
Train a new Isolation Forest version from the command line.

Run from backend/ (or inside the container):
    python -m scripts.train_isolation_forest

This uses the same workflow as the Retrain button on the Model page
(app/services/model_registry_service.py):
  - trains on every closed, real session except simulated attacks and known threats
    (confirmed, or repeating a confirmed threat's pattern); unreviewed flags stay in so
    the threshold does not drop with every retrain
  - saves the run as a new version in app/ml/models/versions/<version_id>/
  - runs the guardrails (enough data, recent false alarms, known attacks)
  - promotes the version to live only if every guardrail passes

Thresholds are percentiles of the training scores, one per risk tier:
high p90, standard p95, low p97 (app.core.dsfs_catalog.TIER_PERCENTILES).

This command runs in its own process, so restart the backend afterwards to load
a newly promoted model (the Model page's Retrain button reloads it in place).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # allow `app.*` imports

from app.core.dsfs_catalog import TIER_PERCENTILES
from app.db.database import SessionLocal
from app.services import model_registry_service as registry

MIN_SESSIONS_TO_TRAIN = registry.MIN_SESSIONS_TO_TRAIN
ANOMALY_PERCENTILE = TIER_PERCENTILES["standard"]


def load_training_table(db):
    """Kept for older callers: (session_ids, X, total_closed)."""
    return registry.load_training_table(db)


def _pct(value):
    return "n/a" if value is None else f"{value:.1%}"


def main():
    db = SessionLocal()
    try:
        record = registry.train_candidate(db, triggered_by="command line", promote=True)
    except registry.NotEnoughData as e:
        print(f"{e} Run scripts/seed_synthetic_data.py first, or wait for more real usage.")
        return
    except registry.RetrainInProgress as e:
        print(e)
        return
    finally:
        db.close()

    m = record["metrics"]
    print(f"Version {record['version_id']}: trained on {m['n_sessions']} sessions "
          f"({m['excluded_sessions']} closed sessions excluded: simulated attacks and known threats).")
    print(f"Training score: mean={m['train_score_mean']:.4f} sd={m['train_score_std']:.4f}")
    for tier, pct in TIER_PERCENTILES.items():
        print(f"  {tier:<8} tier @ p{pct}: {m['tier_thresholds'][tier]:.4f}")
    print(f"Recent false-alarm check: {_pct(m['holdout_flag_rate'])} of the {m['n_holdout']} most recent "
          f"training sessions flagged")
    print(f"Known attacks caught: new {_pct(m['known_bad_caught_new'])}, "
          f"live {_pct(m['known_bad_caught_live'])} (of {m['n_known_bad']})")
    print("Checks:")
    for c in record["checks"]:
        mark = "SKIP" if c["skipped"] else ("PASS" if c["passed"] else "FAIL")
        print(f"  {mark}  {c['name']}: {c['detail']}")

    if record["status"] == "live":
        print("Promoted to live. Restart the backend so it loads the new model: docker compose restart backend")
    else:
        print("NOT promoted: a check failed. The live model is unchanged; the version is kept for review.")


if __name__ == "__main__":
    main()