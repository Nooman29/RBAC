"""
Model registry and retraining workflow for the Isolation Forest.

Every training run becomes a VERSION in app/ml/models/versions/<version_id>/
(model, scaler, threshold.json). The live model is whichever version was last
promoted; its files are copied to the paths in settings, which is where
anomaly_service loads from. registry.json records every version, its checks
and its metrics, so any earlier version can be promoted again (rollback).

Training data: every closed, real session except simulated attacks and known threats (confirmed by
an administrator, or flagged for repeating a confirmed threat's pattern and not cleared since).
Sessions the model itself flagged that nobody has reviewed yet STAY in: the threshold is a
percentile of the training scores, so dropping the model's own flags would cut off the top of the
distribution on every retrain and lower the threshold each time (more and more false alarms).
Isolation Forest tolerates a few unusual sessions in its training data. Per-user baselines are
stricter (feature_engineering.counts_as_normal_behaviour).

Guardrails, checked before a new version may go live:
  1. enough_data          at least MIN_SESSIONS_TO_TRAIN training sessions
  2. scores_vary          the model does not give every session the same score
  3. recent_false_alarms  trained on all but the most recent 20% of training
                          sessions, it flags at most 15% of those recent ones
                          (about 5% is expected at the 95th percentile)
  4. known_attacks        on simulated attacks and confirmed threats (never used
                          for training), it catches at least as many as the live
                          model, minus 10 percentage points
A version that fails is saved as "rejected" and never goes live.

Drift indicators compare the sessions scored since promotion with the model's
own training scores: the share flagged by the model, and how far the average
score has moved (in training standard deviations).

Schedule: a background thread retrains when the latest version is older than
MODEL_RETRAIN_INTERVAL_DAYS. It only promotes if the guardrails pass. Drift
alone does not trigger an automatic retrain: behaviour that drifted could be
an attack, so an administrator decides from the Model page.

Hot reload: promotion reloads the artifacts inside the running backend, so no
restart is needed. (With several worker processes each would need a reload; the
backend runs one.)
"""
from __future__ import annotations

import json
import logging
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy import and_, func, not_, or_

from app.core.config import settings
from app.core.dsfs_catalog import TIER_PERCENTILES
from app.ml.feature_engineering import FEATURE_COLUMNS, build_session_feature_vector
from app.models.anomaly import AnomalyAlert
from app.models.session import UserSession
from app.services.anomaly_service import CONFIRMED_THREAT, REASON_CONFIRMED as REASON_CONFIRMED_PATTERN

logger = logging.getLogger(__name__)

MIN_SESSIONS_TO_TRAIN = 30
HOLDOUT_FRACTION = 0.20
MIN_HOLDOUT_FOR_CHECK = 20
MAX_HOLDOUT_FLAG_RATE = 0.15
MIN_KNOWN_BAD_FOR_CHECK = 5
KNOWN_BAD_TOLERANCE = 0.10
MAX_KNOWN_BAD_SESSIONS = 300

MIN_DRIFT_SAMPLES = 20
DRIFT_FLAG_RATE_FACTOR = 2.0
DRIFT_MEAN_SHIFT = 0.5
EXPECTED_FLAG_RATE = round(1 - TIER_PERCENTILES["standard"] / 100, 4)

# max_samples=1.0 is the setting selected on validation in scripts/model_experiments.py. The number
# of trees made almost no difference there (validation F1 0.955-0.960 for 100-500 trees; the top
# configuration used 500), so 200 keeps retraining and SHAP explanations fast. contamination is
# not used: the threshold is a percentile of the training scores.
MODEL_PARAMS = {"n_estimators": 200, "max_samples": 1.0, "random_state": 42, "n_jobs": -1}

FILE_NAMES = {"model": "isolation_forest.joblib", "scaler": "scaler.joblib", "threshold": "threshold.json"}

_lock = threading.Lock()
_scheduler_started = False


class RetrainInProgress(Exception):
    pass


class NotEnoughData(Exception):
    pass


class PromotionRefused(Exception):
    pass


# ---------------------------------------------------------------- paths and registry

def _live_paths() -> dict:
    return {
        "model": Path(settings.ISOLATION_FOREST_MODEL_PATH),
        "scaler": Path(settings.ISOLATION_FOREST_SCALER_PATH),
        "threshold": Path(settings.ISOLATION_FOREST_THRESHOLD_PATH),
    }


def _models_dir() -> Path:
    return _live_paths()["model"].parent


def _versions_dir() -> Path:
    return _models_dir() / "versions"


def _registry_path() -> Path:
    return _models_dir() / "registry.json"


def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _parse(ts: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(ts.rstrip("Z")) if ts else None


def _new_version_id(prefix: str = "") -> str:
    base = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    if prefix:
        base = f"{prefix}-{base}"
    version_id, i = base, 2
    while (_versions_dir() / version_id).exists():
        version_id = f"{base}-{i}"
        i += 1
    return version_id


def _save_registry(registry: dict) -> None:
    path = _registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(registry, indent=2))
    tmp.replace(path)


def _find(registry: dict, version_id: Optional[str]) -> Optional[dict]:
    for v in registry.get("versions", []):
        if v["version_id"] == version_id:
            return v
    return None


def load_registry() -> dict:
    """Reads registry.json. On first use, registers the model already live as a 'legacy' version."""
    path = _registry_path()
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            logger.exception("registry.json is unreadable; starting a new registry.")

    registry = {"current": None, "versions": []}
    live = _live_paths()
    if all(p.exists() for p in live.values()):
        version_id = _new_version_id("legacy")
        target = _versions_dir() / version_id
        target.mkdir(parents=True, exist_ok=True)
        for key, src in live.items():
            shutil.copy2(src, target / FILE_NAMES[key])
        meta = json.loads(live["threshold"].read_text())
        registry["versions"].append({
            "version_id": version_id,
            "created_at": _now(),
            "triggered_by": "existing model (before versioning)",
            "status": "live",
            "passed": True,
            "checks": [{"name": "imported", "passed": True, "skipped": False,
                        "detail": "The model that was live before versioning was added."}],
            "metrics": {
                "n_sessions": meta.get("trained_on_n_sessions"),
                "threshold": meta.get("threshold"),
                "tier_thresholds": meta.get("tier_thresholds"),
            },
            "promoted_at": _now(),
        })
        registry["current"] = version_id
        _save_registry(registry)
    return registry


# ---------------------------------------------------------------- data

def is_known_threat():
    """SQL condition (on a query outer-joined to AnomalyAlert): confirmed by an administrator, or
    flagged for repeating a confirmed threat's pattern and not reviewed since.

    NULLs are replaced with "" first: in SQL, NULL = 'x' is NULL (not false), and NOT NULL is
    still NULL, so not_(...) would silently drop every session that has no verdict yet."""
    verdict = func.coalesce(AnomalyAlert.review_verdict, "")
    return or_(
        verdict == CONFIRMED_THREAT,
        and_(func.coalesce(AnomalyAlert.detection_reason, "") == REASON_CONFIRMED_PATTERN, verdict == ""),
    )


def _training_sessions_query(db):
    """Closed, real sessions except known threats, oldest first (see the module docstring for
    why unreviewed flags stay in)."""
    return (
        db.query(UserSession)
        .filter(UserSession.session_duration.isnot(None))
        .outerjoin(AnomalyAlert, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.simulated_scenario.is_(None),
            or_(AnomalyAlert.alert_id.is_(None), not_(is_known_threat())),
        )
        .order_by(UserSession.login_time.asc())
    )


def _matrix(db, sessions) -> np.ndarray:
    rows = []
    for s in sessions:
        features = build_session_feature_vector(db, s)
        rows.append([features[col] for col in FEATURE_COLUMNS])
    return np.array(rows, dtype=float).reshape(-1, len(FEATURE_COLUMNS))


def load_training_table(db) -> tuple:
    """(session_ids, X, total_closed) for the training sessions, oldest first."""
    total_closed = db.query(UserSession).filter(UserSession.session_duration.isnot(None)).count()
    sessions = _training_sessions_query(db).all()
    return [s.session_id for s in sessions], _matrix(db, sessions), total_closed


def _known_bad_matrix(db) -> np.ndarray:
    """Simulated attacks and confirmed threats: never trained on, used to test a candidate."""
    sessions = (
        db.query(UserSession)
        .outerjoin(AnomalyAlert, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.session_duration.isnot(None),
            or_(UserSession.simulated_scenario.isnot(None), AnomalyAlert.review_verdict == "confirmed_threat"),
        )
        .order_by(UserSession.login_time.desc())
        .limit(MAX_KNOWN_BAD_SESSIONS)
        .all()
    )
    return _matrix(db, sessions)


# ---------------------------------------------------------------- model helpers

def _fit(X: np.ndarray):
    scaler = StandardScaler().fit(X)
    model = IsolationForest(**MODEL_PARAMS).fit(scaler.transform(X))
    scores = -model.score_samples(scaler.transform(X))
    return model, scaler, scores


def _flag_rate(model, scaler, threshold: float, X: np.ndarray) -> Optional[float]:
    if X is None or len(X) == 0:
        return None
    scores = -model.score_samples(scaler.transform(X))
    return float((scores >= threshold).mean())


def _live_model_rate(X: np.ndarray) -> Optional[float]:
    live = _live_paths()
    if len(X) == 0 or not all(p.exists() for p in live.values()):
        return None
    try:
        model = joblib.load(live["model"])
        scaler = joblib.load(live["scaler"])
        threshold = json.loads(live["threshold"].read_text())["threshold"]
        return _flag_rate(model, scaler, threshold, X)
    except Exception:
        logger.exception("Could not score known attacks with the live model (feature set changed?).")
        return None


def reload_live_model() -> bool:
    """Makes the running backend load the files now at the live paths."""
    from app.services import anomaly_service

    for name in ["_model", "_scaler", "_threshold", "_tier_thresholds", "_explainer"]:
        setattr(anomaly_service, name, None)
    anomaly_service._load_attempted = False
    return anomaly_service._load_artifacts()


# ---------------------------------------------------------------- guardrails and drift (pure)

def _check(name: str, passed: bool, detail: str, skipped: bool = False) -> dict:
    return {"name": name, "passed": bool(passed), "skipped": skipped, "detail": detail}


def evaluate_guardrails(*, n_sessions: int, train_score_std: float, n_holdout: int,
                        holdout_flag_rate: Optional[float], n_known_bad: int,
                        known_bad_rate_new: Optional[float], known_bad_rate_live: Optional[float]) -> list:
    checks = [
        _check("enough_data", n_sessions >= MIN_SESSIONS_TO_TRAIN,
               f"{n_sessions} training sessions (minimum {MIN_SESSIONS_TO_TRAIN})"),
        _check("scores_vary", train_score_std > 1e-6,
               "training scores vary between sessions" if train_score_std > 1e-6
               else "every session got the same score; the features carry no signal"),
    ]

    if n_holdout >= MIN_HOLDOUT_FOR_CHECK and holdout_flag_rate is not None:
        checks.append(_check(
            "recent_false_alarms", holdout_flag_rate <= MAX_HOLDOUT_FLAG_RATE,
            f"{holdout_flag_rate:.1%} of the {n_holdout} most recent training sessions would be flagged "
            f"(limit {MAX_HOLDOUT_FLAG_RATE:.0%}, about {EXPECTED_FLAG_RATE:.0%} expected)"))
    else:
        checks.append(_check("recent_false_alarms", True,
                             f"skipped: only {n_holdout} recent sessions (needs {MIN_HOLDOUT_FOR_CHECK})",
                             skipped=True))

    if n_known_bad >= MIN_KNOWN_BAD_FOR_CHECK and known_bad_rate_new is not None:
        if known_bad_rate_live is None:
            checks.append(_check("known_attacks", True,
                                 f"catches {known_bad_rate_new:.0%} of {n_known_bad} known attacks "
                                 f"(no live model to compare with)"))
        else:
            ok = known_bad_rate_new >= known_bad_rate_live - KNOWN_BAD_TOLERANCE
            checks.append(_check("known_attacks", ok,
                                 f"catches {known_bad_rate_new:.0%} of {n_known_bad} known attacks, "
                                 f"live model {known_bad_rate_live:.0%} "
                                 f"(may be at most {KNOWN_BAD_TOLERANCE:.0%} lower)"))
    else:
        checks.append(_check("known_attacks", True,
                             f"skipped: only {n_known_bad} known attacks or confirmed threats "
                             f"(needs {MIN_KNOWN_BAD_FOR_CHECK})", skipped=True))
    return checks


def assess_drift(*, scores: list, ml_flagged: int, train_mean: Optional[float], train_std: Optional[float],
                 age_days: float, new_sessions: int, n_train: int, interval_days: int) -> dict:
    n = len(scores)
    out = {
        "n_recent": n,
        "recent_flag_rate": None,
        "expected_flag_rate": EXPECTED_FLAG_RATE,
        "mean_shift": None,
        "age_days": round(age_days, 1),
        "new_sessions_since": new_sessions,
    }
    reasons = []
    if n < MIN_DRIFT_SAMPLES:
        status = "insufficient_data"
    else:
        rate = ml_flagged / n
        out["recent_flag_rate"] = round(rate, 4)
        if rate > EXPECTED_FLAG_RATE * DRIFT_FLAG_RATE_FACTOR:
            reasons.append(f"{rate:.0%} of recent sessions were flagged by the model "
                           f"(about {EXPECTED_FLAG_RATE:.0%} expected)")
        if train_mean is not None and train_std:
            shift = (float(np.mean(scores)) - train_mean) / train_std
            out["mean_shift"] = round(shift, 2)
            if abs(shift) > DRIFT_MEAN_SHIFT:
                reasons.append(f"the average anomaly score moved {shift:+.2f} standard deviations "
                               f"from training")
        status = "drifting" if reasons else "stable"

    recommend = []
    if status == "drifting":
        recommend.append("recent behaviour no longer matches the training data")
    if age_days >= interval_days:
        recommend.append(f"the model is {age_days:.0f} days old (scheduled every {interval_days} days)")
    if n_train and new_sessions >= 0.5 * n_train:
        recommend.append(f"{new_sessions} new sessions since training ({n_train} were used)")

    out.update(status=status, reasons=reasons, retrain_recommended=bool(recommend), recommend_reasons=recommend)
    return out


# ---------------------------------------------------------------- workflow

def _promote(registry: dict, version_id: str) -> dict:
    record = _find(registry, version_id)
    if record is None:
        raise KeyError(version_id)
    if not record.get("passed"):
        raise PromotionRefused("This version failed its checks and cannot go live.")

    source = _versions_dir() / version_id
    live = _live_paths()
    live["model"].parent.mkdir(parents=True, exist_ok=True)
    for key, dst in live.items():
        shutil.copy2(source / FILE_NAMES[key], dst)

    for v in registry["versions"]:
        if v["status"] == "live":
            v["status"] = "previous"
    record["status"] = "live"
    record["promoted_at"] = _now()
    registry["current"] = version_id
    _save_registry(registry)

    loaded = reload_live_model()
    logger.info("Model version %s promoted (reloaded=%s).", version_id, loaded)
    return record


def train_candidate(db, triggered_by: str, promote: bool = True) -> dict:
    """Trains a new version, runs the guardrails, and promotes it if they pass."""
    if not _lock.acquire(blocking=False):
        raise RetrainInProgress("A retraining run is already in progress.")
    try:
        registry = load_registry()
        _, X, total_closed = load_training_table(db)
        n = len(X)
        if n < MIN_SESSIONS_TO_TRAIN:
            raise NotEnoughData(f"Only {n} usable sessions (at least {MIN_SESSIONS_TO_TRAIN} needed).")

        # 1) Out-of-time check: fit on older sessions, count flags on the most recent ones
        n_holdout = max(1, int(round(n * HOLDOUT_FRACTION)))
        m_h, s_h, scores_h = _fit(X[:-n_holdout])
        thr_h = float(np.percentile(scores_h, TIER_PERCENTILES["standard"]))
        holdout_rate = _flag_rate(m_h, s_h, thr_h, X[-n_holdout:])

        # 2) Final model on all training sessions
        model, scaler, scores = _fit(X)
        threshold = float(np.percentile(scores, TIER_PERCENTILES["standard"]))
        tier_thresholds = {t: float(np.percentile(scores, p)) for t, p in TIER_PERCENTILES.items()}

        # 3) Known attacks and confirmed threats
        X_bad = _known_bad_matrix(db)
        bad_new = _flag_rate(model, scaler, threshold, X_bad)
        bad_live = _live_model_rate(X_bad)

        checks = evaluate_guardrails(
            n_sessions=n, train_score_std=float(scores.std()), n_holdout=n_holdout,
            holdout_flag_rate=holdout_rate, n_known_bad=len(X_bad),
            known_bad_rate_new=bad_new, known_bad_rate_live=bad_live,
        )
        passed = all(c["passed"] for c in checks)

        version_id = _new_version_id()
        target = _versions_dir() / version_id
        target.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, target / FILE_NAMES["model"])
        joblib.dump(scaler, target / FILE_NAMES["scaler"])
        (target / FILE_NAMES["threshold"]).write_text(json.dumps({
            "threshold": threshold,
            "percentile": TIER_PERCENTILES["standard"],
            "tier_thresholds": tier_thresholds,
            "tier_percentiles": TIER_PERCENTILES,
            "trained_on_n_sessions": n,
            "feature_columns": FEATURE_COLUMNS,
            "version_id": version_id,
            "model_params": {k: v for k, v in MODEL_PARAMS.items() if k != "n_jobs"},
        }, indent=2))

        record = {
            "version_id": version_id,
            "created_at": _now(),
            "triggered_by": triggered_by,
            "status": "candidate" if passed else "rejected",
            "passed": passed,
            "checks": checks,
            "metrics": {
                "n_sessions": n,
                "excluded_sessions": total_closed - n,
                "n_holdout": n_holdout,
                "holdout_flag_rate": holdout_rate,
                "n_known_bad": int(len(X_bad)),
                "known_bad_caught_new": bad_new,
                "known_bad_caught_live": bad_live,
                "threshold": threshold,
                "tier_thresholds": tier_thresholds,
                "train_score_mean": float(scores.mean()),
                "train_score_std": float(scores.std()),
                "flagged_in_training": int((scores >= threshold).sum()),
            },
            "promoted_at": None,
        }
        registry["versions"].append(record)
        _save_registry(registry)
        logger.info("Model version %s trained by %s: passed=%s", version_id, triggered_by, passed)

        if passed and promote:
            record = _promote(registry, version_id)
        return record
    finally:
        _lock.release()


def promote_version(version_id: str) -> dict:
    """Puts an earlier (or a candidate) version live. Used for rollback."""
    if not _lock.acquire(blocking=False):
        raise RetrainInProgress("A retraining run is in progress; try again in a moment.")
    try:
        return _promote(load_registry(), version_id)
    finally:
        _lock.release()


def compute_drift(db, current: Optional[dict]) -> dict:
    if current is None:
        return {"status": "no_model", "reasons": [], "retrain_recommended": True,
                "recommend_reasons": ["no model is live yet"]}
    metrics = current.get("metrics") or {}
    since = _parse(current.get("promoted_at") or current.get("created_at"))

    rows = (
        db.query(AnomalyAlert.anomaly_score, AnomalyAlert.is_anomaly, AnomalyAlert.detection_reason)
        .join(UserSession, AnomalyAlert.session_id == UserSession.session_id)
        .filter(AnomalyAlert.alert_timestamp >= since, UserSession.simulated_scenario.is_(None))
        .all()
    )
    new_sessions = (
        db.query(UserSession)
        .filter(UserSession.session_duration.isnot(None), UserSession.simulated_scenario.is_(None),
                UserSession.login_time >= since)
        .count()
    )
    age_days = (datetime.utcnow() - _parse(current["created_at"])).total_seconds() / 86400
    return assess_drift(
        scores=[r[0] for r in rows],
        ml_flagged=sum(1 for r in rows if r[1] and r[2] == "ml_model"),
        train_mean=metrics.get("train_score_mean"),
        train_std=metrics.get("train_score_std"),
        age_days=age_days,
        new_sessions=new_sessions,
        n_train=metrics.get("n_sessions") or 0,
        interval_days=settings.MODEL_RETRAIN_INTERVAL_DAYS,
    )


def get_status(db) -> dict:
    registry = load_registry()
    current = _find(registry, registry.get("current"))
    versions = sorted(registry.get("versions", []), key=lambda v: v["created_at"], reverse=True)
    return {
        "current": current,
        "drift": compute_drift(db, current),
        "schedule": {
            "auto_retrain": settings.MODEL_AUTO_RETRAIN,
            "interval_days": settings.MODEL_RETRAIN_INTERVAL_DAYS,
            "check_hours": settings.MODEL_RETRAIN_CHECK_HOURS,
        },
        "retrain_in_progress": _lock.locked(),
        "versions": versions[:25],
    }


# ---------------------------------------------------------------- schedule

def run_scheduled_check() -> Optional[dict]:
    """Retrains when the newest version (live or not) is older than the interval."""
    from app.db.database import SessionLocal

    registry = load_registry()
    versions = registry.get("versions", [])
    if versions:
        newest = max(versions, key=lambda v: v["created_at"])
        age_days = (datetime.utcnow() - _parse(newest["created_at"])).total_seconds() / 86400
        if age_days < settings.MODEL_RETRAIN_INTERVAL_DAYS:
            return None

    db = SessionLocal()
    try:
        record = train_candidate(db, triggered_by="weekly schedule", promote=True)
        logger.info("Scheduled retrain: version %s status=%s", record["version_id"], record["status"])
        return record
    except (NotEnoughData, RetrainInProgress) as e:
        logger.info("Scheduled retrain skipped: %s", e)
        return None
    finally:
        db.close()


def _scheduler_loop() -> None:
    time.sleep(max(0, settings.MODEL_RETRAIN_FIRST_CHECK_SECONDS))
    while True:
        try:
            run_scheduled_check()
        except Exception:
            logger.exception("Scheduled retraining check failed.")
        time.sleep(max(1, settings.MODEL_RETRAIN_CHECK_HOURS) * 3600)


def start_scheduler() -> None:
    global _scheduler_started
    if _scheduler_started or not settings.MODEL_AUTO_RETRAIN:
        return
    _scheduler_started = True
    threading.Thread(target=_scheduler_loop, daemon=True, name="model-retrain-scheduler").start()
    logger.info("Model retraining schedule: every %s days (checked every %s h).",
                settings.MODEL_RETRAIN_INTERVAL_DAYS, settings.MODEL_RETRAIN_CHECK_HOURS)