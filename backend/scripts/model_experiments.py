"""
Leakage-safe model experiments for the anomaly detector.

    docker compose exec backend python -m scripts.model_experiments --quick   # smoke test, about a minute
    docker compose exec backend python -m scripts.model_experiments           # full run, several minutes

Everything happens in a throwaway IN-MEMORY database: your real data is never touched, and all labels
are known by construction. The production feature code is reused unchanged.

Design (the rules that prevent data leakage):
  * Time-based split per user: the first 60% of a user's sessions is TRAINING, the next 20% VALIDATION,
    the last 20% TEST. Attacks are injected only into the validation and test windows.
  * Baselines (per-user z-scores, new-IP) use only sessions BEFORE the session being featurised.
  * The StandardScaler is fitted on training rows only, then applied to validation and test rows.
  * Hyper-parameters are chosen with GridSearchCV whose single fold trains on the training partition and
    scores on the validation partition. The test partition is evaluated once per model, after selection.
  * Training data is unlabeled (it contains about 6% unusual sessions, as in production); labels are only
    used to score validation and test results.
Models: Isolation Forest, One-Class SVM, Local Outlier Factor, and a shallow autoencoder
(scikit-learn MLPRegressor reconstructing its input). Higher score = more anomalous for every model.
"""

import argparse
import random
import sys
import time
import uuid
import warnings
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
from sklearn.base import BaseEstimator
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import GridSearchCV
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import Base
import app.models  # noqa: F401  registers the core tables
import app.models.anomaly  # noqa: F401
import app.models.notification  # noqa: F401
from app.ml import feature_engineering as fe
from app.models.session import UserSession
from app.models.user import User
from app.services import attack_simulation_service as sim
from scripts import seed_synthetic_data as seed

warnings.filterwarnings("ignore", category=ConvergenceWarning)

SCENARIOS = list(sim.SCENARIOS)
FAMILIES = ["unusual"] + SCENARIOS
MIN_USER_SESSIONS_FOR_ADAPTIVE = 20
TIER_PERCENTILES = {"high": 90, "standard": 95, "low": 97}
Z_INDEX = [i for i, c in enumerate(fe.FEATURE_COLUMNS) if c.endswith("_zscore")]


# ------------------------------------------------------------------ models

class ReconstructionAutoencoder(BaseEstimator):
    """A shallow autoencoder: an MLP trained to reproduce its input. Anomaly = reconstruction error."""

    def __init__(self, hidden=(12, 6, 12), alpha=1e-4, max_iter=400, random_state=0):
        self.hidden = hidden
        self.alpha = alpha
        self.max_iter = max_iter
        self.random_state = random_state

    def fit(self, X, y=None):
        self.net_ = MLPRegressor(
            hidden_layer_sizes=self.hidden, alpha=self.alpha,
            max_iter=self.max_iter, random_state=self.random_state,
        )
        self.net_.fit(X, X)
        return self

    def score_samples(self, X):
        """Higher = more normal (the scikit-learn convention), so that -score_samples is the anomaly score."""
        X = np.asarray(X, dtype=float)
        return -np.mean((X - self.net_.predict(X)) ** 2, axis=1)


def default_models():
    return {
        "Isolation Forest": IsolationForest(n_estimators=300, contamination="auto", random_state=42),
        "One-Class SVM": OneClassSVM(kernel="rbf", nu=0.05, gamma="scale"),
        "Local Outlier Factor": LocalOutlierFactor(n_neighbors=20, novelty=True),
        "Autoencoder (MLP)": ReconstructionAutoencoder(random_state=42),
    }


def grids(quick):
    if quick:
        return {
            "Isolation Forest": {"n_estimators": [100, 300], "max_samples": [128, 256],
                                 "contamination": [0.05, "auto"], "random_state": [0, 1]},
            "One-Class SVM": {"nu": [0.05, 0.1], "gamma": ["scale", 0.05]},
            "Local Outlier Factor": {"n_neighbors": [20, 35]},
            "Autoencoder (MLP)": {"hidden": [(8, 4, 8), (12, 6, 12)], "alpha": [1e-4]},
        }
    return {
        "Isolation Forest": {"n_estimators": [100, 200, 300, 500], "max_samples": [64, 128, 256, 1.0],
                             "contamination": [0.02, 0.05, 0.10, "auto"], "random_state": [0, 1, 2]},
        "One-Class SVM": {"nu": [0.02, 0.05, 0.1], "gamma": ["scale", 0.01, 0.05, 0.1]},
        "Local Outlier Factor": {"n_neighbors": [10, 20, 35, 50]},
        "Autoencoder (MLP)": {"hidden": [(8, 4, 8), (12, 6, 12), (16, 8, 16)], "alpha": [1e-4, 1e-2]},
    }


def auc_scorer(est, X, y):
    return roc_auc_score(y, -est.score_samples(X))


def f1_predict_scorer(est, X, y):
    return f1_score(y, (est.predict(X) == -1).astype(int))


# ------------------------------------------------------------------ metrics

def prf(y, flag):
    y = np.asarray(y).astype(int)
    flag = np.asarray(flag).astype(bool)
    tp = int(((y == 1) & flag).sum())
    fp = int(((y == 0) & flag).sum())
    fn = int(((y == 1) & ~flag).sum())
    tn = int(((y == 0) & ~flag).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def best_f1_threshold(y, scores):
    best_t, best_f = float(np.max(scores)) + 1e-9, -1.0
    for t in np.unique(scores):
        f = prf(y, scores >= t)["f1"]
        if f > best_f:
            best_t, best_f = float(t), f
    return best_t


def bootstrap_ci(y, scores, threshold, n_boot, rng):
    y = np.asarray(y)
    scores = np.asarray(scores)
    n = len(y)
    aucs, f1s = [], []
    for _ in range(n_boot):
        idx = rng.integers(0, n, n)
        yb, sb = y[idx], scores[idx]
        if yb.min() == yb.max():
            continue
        aucs.append(roc_auc_score(yb, sb))
        f1s.append(prf(yb, sb >= threshold)["f1"])

    def interval(values):
        if not values:
            return float("nan"), float("nan")
        return float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))

    return interval(aucs), interval(f1s)


def pc(x):
    return f"{100 * x:.1f}%"


def with_ci(value, ci):
    return f"{value:.2f} ({ci[0]:.2f}-{ci[1]:.2f})"


def print_table(headers, rows):
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join("---" for _ in headers) + "|")
    for row in rows:
        print("| " + " | ".join(str(c) for c in row) + " |")
    print()


# ------------------------------------------------------------------ benchmark data

def make_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False)()


def make_user(db, name):
    user = User(username=name, password="x", email=f"{name}@bench.example.com", department="IT")
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def with_day(day, make):
    """Run the seed generator's session builder on a chosen calendar day."""
    day = datetime(day.year, day.month, day.day)
    original = seed.random_day
    seed.random_day = lambda weekend: day
    try:
        return make()
    finally:
        seed.random_day = original


def weekday_in(start, end):
    span = max(1, int((end - start).total_seconds()))
    candidate = start
    for _ in range(30):
        candidate = start + timedelta(seconds=random.randint(0, span))
        if candidate.weekday() < 5:
            return candidate
    return candidate


def build_history(db, user, n_sessions):
    """Synthetic history for one user: (session, label) pairs, label 1 = deliberately unusual."""
    profile = seed.make_profile()
    used = set()
    items = []
    for _ in range(n_sessions):
        unusual = random.random() < seed.ANOMALOUS_SESSION_RATE
        params = seed.anomalous_params(profile, used) if unusual else seed.normal_params(profile)
        items.append((seed.add_session(db, user.user_id, params), int(unusual)))
    db.commit()
    return profile, items


def split_for(items):
    """Chronological 60/20/20 split of (session, label) pairs."""
    ordered = sorted(items, key=lambda it: it[0].login_time)
    n = len(ordered)
    a, b = int(n * 0.6), int(n * 0.8)
    return ordered[:a], ordered[a:b], ordered[b:]


def generate_established(db, n_users, attacks):
    rows = []
    for i in range(n_users):
        user = make_user(db, f"bench_{i:03d}")
        _, items = build_history(db, user, random.randint(*seed.SESSIONS_PER_USER))
        train, val, test = split_for(items)
        for name, part in (("train", train), ("val", val), ("test", test)):
            for session, label in part:
                rows.append({"session_id": session.session_id, "user": user.user_id, "split": name,
                             "label": label, "family": "unusual" if label else "normal"})
        for name, part in (("val", val), ("test", test)):
            start, end = part[0][0].login_time, part[-1][0].login_time
            for key in SCENARIOS:
                for _ in range(attacks):
                    session = sim.create_scenario_session(db, user.user_id, key, day=weekday_in(start, end))
                    rows.append({"session_id": session.session_id, "user": user.user_id, "split": name,
                                 "label": 1, "family": key})
    return rows


def featurize(db, rows):
    """Production feature builder, with raw per-session features cached (the database is static now)."""
    cache = {}
    original = fe.build_raw_session_features

    def cached(db_, session):
        if session.session_id not in cache:
            cache[session.session_id] = original(db_, session)
        return cache[session.session_id]

    fe.build_raw_session_features = cached
    try:
        sessions = {s.session_id: s for s in db.query(UserSession).all()}
        vectors = []
        for row in rows:
            vector = fe.build_session_feature_vector(db, sessions[row["session_id"]])
            vectors.append([vector[c] for c in fe.FEATURE_COLUMNS])
    finally:
        fe.build_raw_session_features = original
    return np.array(vectors, dtype=float)


def assert_point_in_time(db, rows, sample=60):
    """Check that baselines count exactly the earlier normal sessions and nothing from the future."""
    history = [r for r in rows if r["family"] in ("normal", "unusual")]
    chosen = random.sample(history, min(sample, len(history)))
    sessions = {s.session_id: s for s in db.query(UserSession).all()}
    for row in chosen:
        s = sessions[row["session_id"]]
        stats = fe.build_user_history_stats(db, s.user_id, exclude_session_id=s.session_id, before=s.login_time)
        expected = db.query(UserSession).filter(
            UserSession.user_id == s.user_id,
            UserSession.simulated_scenario.is_(None),
            UserSession.session_duration.isnot(None),
            UserSession.login_time < s.login_time,
            UserSession.session_id != s.session_id,
        ).count()
        assert stats["n_sessions"] == expected, "baseline used a session that is not strictly earlier"
    return len(chosen)


# ------------------------------------------------------------------ evaluation

def evaluate_model(name, config, model, X_train, X_val, y_val, X_test, y_test, fam_test,
                   n_boot, rng, percentile=95.0, fixed_threshold=None):
    t0 = time.perf_counter()
    model.fit(X_train)
    fit_s = time.perf_counter() - t0
    train_s = -model.score_samples(X_train)
    val_s = -model.score_samples(X_val)
    t1 = time.perf_counter()
    test_s = -model.score_samples(X_test)
    ms = 1000 * (time.perf_counter() - t1) / len(X_test)

    thr = float(fixed_threshold) if fixed_threshold is not None else float(np.percentile(train_s, percentile))
    thr_val = best_f1_threshold(y_val, val_s)
    (auc_lo, auc_hi), f1_ci = bootstrap_ci(y_test, test_s, thr, n_boot, rng)
    family_recall = {}
    for family in FAMILIES:
        mask = fam_test == family
        family_recall[family] = float((test_s[mask] >= thr).mean()) if mask.any() else float("nan")

    return {
        "name": name, "config": config, "model": model, "fit_s": fit_s, "ms": ms,
        "auc": float(roc_auc_score(y_test, test_s)), "auc_ci": (auc_lo, auc_hi),
        "op": prf(y_test, test_s >= thr), "f1_ci": f1_ci, "thr": thr,
        "val_best": prf(y_test, test_s >= thr_val), "family_recall": family_recall,
        "train_s": train_s, "val_s": val_s, "test_s": test_s,
    }


def print_comparison(title, results):
    print(f"\n### {title}\n")
    print("Operating point: the production rule (threshold at a percentile of the TRAINING scores).\n")
    print_table(
        ["Model", "Configuration", "AUC-ROC (95% CI)", "Precision", "Recall", "F1 (95% CI)", "False-positive rate",
         "Train s", "ms per session"],
        [[r["name"], r["config"], with_ci(r["auc"], r["auc_ci"]), pc(r["op"]["precision"]), pc(r["op"]["recall"]),
          with_ci(r["op"]["f1"], r["f1_ci"]), pc(r["op"]["fpr"]), f"{r['fit_s']:.2f}", f"{r['ms']:.3f}"]
         for r in results],
    )
    print("Best case: the threshold is chosen on the validation set (not available in production).\n")
    print_table(
        ["Model", "Precision", "Recall", "F1", "False-positive rate"],
        [[r["name"], pc(r["val_best"]["precision"]), pc(r["val_best"]["recall"]),
          f"{r['val_best']['f1']:.2f}", pc(r["val_best"]["fpr"])] for r in results],
    )
    print("Recall by attack type at the production operating point:\n")
    labels = {"unusual": "Generic unusual sessions"}
    labels.update({k: sim.SCENARIOS[k]["label"] for k in SCENARIOS})
    print_table(
        ["Model"] + [labels[f] for f in FAMILIES],
        [[r["name"]] + [pc(r["family_recall"][f]) for f in FAMILIES] for r in results],
    )


def tune(estimator, grid, X_fit, X_val, y_val, scoring):
    """GridSearchCV with ONE fold: fit on the training partition, score on the validation partition."""
    X_all = np.vstack([X_fit, X_val])
    y_all = np.concatenate([np.zeros(len(X_fit), dtype=int), y_val.astype(int)])
    train_idx = np.arange(len(X_fit))
    val_idx = np.arange(len(X_fit), len(X_all))
    search = GridSearchCV(estimator, grid, scoring=scoring, cv=[(train_idx, val_idx)],
                          refit=False, n_jobs=1, error_score="raise")
    search.fit(X_all, y_all)
    return search.cv_results_


def aggregate_if(results):
    groups = defaultdict(lambda: {"f1": [], "auc": []})
    for params, f1, auc in zip(results["params"], results["mean_test_f1"], results["mean_test_auc"]):
        key = (params["n_estimators"], params["max_samples"], params["contamination"])
        groups[key]["f1"].append(f1)
        groups[key]["auc"].append(auc)
    rows = [(key, float(np.mean(v["f1"])), float(np.std(v["f1"])), float(np.mean(v["auc"])), float(np.std(v["auc"])))
            for key, v in groups.items()]
    rows.sort(key=lambda r: (-r[1], -r[3], r[0][0]))
    return rows


def print_if_grid(rows):
    print("\n### Isolation Forest grid search (validation set, mean over random seeds)\n")
    print_table(
        ["n_estimators", "max_samples", "contamination", "Validation F1 (mean, sd)", "Validation AUC (mean, sd)"],
        [[k[0], k[1], k[2], f"{f:.3f} ({fs:.3f})", f"{a:.3f} ({as_:.3f})"] for k, f, fs, a, as_ in rows[:8]],
    )
    for position, label in ((0, "n_estimators"), (1, "max_samples"), (2, "contamination")):
        by_value = defaultdict(lambda: {"f1": [], "auc": []})
        for k, f, _, a, _ in rows:
            by_value[str(k[position])]["f1"].append(f)
            by_value[str(k[position])]["auc"].append(a)
        print(f"Effect of {label} (average over the other parameters):\n")
        print_table([label, "Validation F1", "Validation AUC"],
                    [[v, f"{np.mean(d['f1']):.3f}", f"{np.mean(d['auc']):.3f}"] for v, d in by_value.items()])
    print("Note: contamination only moves the score threshold (it does not change the scores), so it affects F1 but not AUC.\n")


def threshold_strategies(train_s, train_users, test_s, test_users, y_test, tiers):
    base = float(np.percentile(train_s, 95))
    tier_thr = {t: float(np.percentile(train_s, p)) for t, p in TIER_PERCENTILES.items()}
    adaptive = []
    for user in test_users:
        own = train_s[train_users == user]
        if len(own) >= MIN_USER_SESSIONS_FOR_ADAPTIVE:
            adaptive.append(float(np.clip(np.percentile(own, 95), base - 0.05, base + 0.05)))
        else:
            adaptive.append(base)
    strategies = {
        "Static (95th percentile for everyone)": np.full(len(test_s), base),
        "Role-tiered (high 90th, standard 95th, low 97th)": np.array([tier_thr[tiers[u]] for u in test_users]),
        "Per-user adaptive (own 95th, within +/-0.05 of static)": np.array(adaptive),
    }
    print("\n### Threshold strategies (test set, tuned Isolation Forest)\n")
    rows = []
    for name, thresholds in strategies.items():
        m = prf(y_test, test_s >= thresholds)
        rows.append([name, pc(m["precision"]), pc(m["recall"]), f"{m['f1']:.2f}", pc(m["fpr"])])
    print_table(["Strategy", "Precision", "Recall", "F1", "False-positive rate"], rows)

    tier_of_row = np.array([tiers[u] for u in test_users])
    rows = []
    for tier in ("high", "standard", "low"):
        mask = tier_of_row == tier
        if not mask.any():
            continue
        s = prf(y_test[mask], test_s[mask] >= strategies["Static (95th percentile for everyone)"][mask])
        t = prf(y_test[mask], test_s[mask] >= strategies["Role-tiered (high 90th, standard 95th, low 97th)"][mask])
        rows.append([tier, int(mask.sum()), pc(s["recall"]), pc(s["fpr"]), pc(t["recall"]), pc(t["fpr"])])
    print("Role tiers (assumed for the benchmark: one in four users 'high', one in four 'low'):\n")
    print_table(["Tier", "Test sessions", "Recall (static)", "False-positive rate (static)",
                 "Recall (tiered)", "False-positive rate (tiered)"], rows)
    print("Tiering is a risk-appetite policy: it trades more false alarms for higher recall on privileged roles.\n")


def cold_start(db, scaler, model, threshold, episodes):
    """New users: a fresh user with 0 or 3 earlier sessions, then one test session (normal or attack)."""
    rows = []
    now = datetime.utcnow()
    for history_len in (0, 3):
        for i in range(episodes * 2):
            attack = i >= episodes
            user = make_user(db, f"cold_{uuid.uuid4().hex[:10]}")
            profile = seed.make_profile()
            for _ in range(history_len):
                day = datetime(now.year, now.month, now.day) - timedelta(days=random.randint(30, 60))
                with_day(day, lambda: seed.add_session(db, user.user_id, seed.normal_params(profile)))
            test_day = weekday_in(now - timedelta(days=10), now - timedelta(days=1))
            if attack:
                session = sim.create_scenario_session(db, user.user_id, SCENARIOS[i % len(SCENARIOS)], day=test_day)
            else:
                session = with_day(test_day, lambda: seed.add_session(db, user.user_id, seed.normal_params(profile)))
            db.commit()
            rows.append({"session_id": session.session_id, "history": history_len, "attack": attack})
    X = featurize(db, rows)
    scores = -model.score_samples(scaler.transform(X))
    neutral = np.all(X[:, Z_INDEX] == 0.0, axis=1)

    print("\n### Cold start: users with little or no history (tuned Isolation Forest, trained on established users)\n")
    table = []
    for history_len in (0, 3):
        h = np.array([r["history"] == history_len for r in rows])
        a = np.array([r["attack"] for r in rows])
        normal_mask, attack_mask = h & ~a, h & a
        table.append([
            history_len, int(normal_mask.sum()), pc(float((scores[normal_mask] >= threshold).mean())),
            int(attack_mask.sum()), pc(float((scores[attack_mask] >= threshold).mean())),
            f"{int(neutral[h].sum())} of {int(h.sum())}",
        ])
    print_table(["Earlier sessions", "Normal episodes", "False-positive rate", "Attack episodes", "Attacks caught",
                 "Personal z-scores neutral"], table)
    print("With fewer than 5 earlier sessions the personal z-scores are neutral (0), so the decision rests on the "
          "raw behaviour alone.\n")


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=24, help="established users in the benchmark")
    parser.add_argument("--attacks", type=int, default=3, help="attacks per scenario per user in each of validation and test")
    parser.add_argument("--cold", type=int, default=20, help="cold-start episodes per kind and history length")
    parser.add_argument("--boot", type=int, default=500, help="bootstrap resamples for confidence intervals")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quick", action="store_true", help="small, fast run to check that everything works")
    args = parser.parse_args()
    if args.quick:
        args.users, args.attacks, args.cold, args.boot = 10, 2, 8, 100
    random.seed(args.seed)
    rng = np.random.default_rng(args.seed)
    grid = grids(args.quick)

    print("## Model experiments (isolated benchmark database, seed %d%s)\n" % (args.seed, ", quick mode" if args.quick else ""))
    db = make_db()
    rows = generate_established(db, args.users, args.attacks)
    X = featurize(db, rows)
    y = np.array([r["label"] for r in rows])
    split = np.array([r["split"] for r in rows])
    fam = np.array([r["family"] for r in rows])
    users = np.array([r["user"] for r in rows])
    train_m, val_m, test_m = split == "train", split == "val", split == "test"

    scaler = StandardScaler().fit(X[train_m])           # fitted on TRAINING rows only
    Xs = scaler.transform(X)
    X_train, X_val, X_test = Xs[train_m], Xs[val_m], Xs[test_m]
    y_val, y_test, fam_test = y[val_m], y[test_m], fam[test_m]

    print("### Data and leakage audit\n")
    print_table(
        ["Partition", "Sessions", "Attacks and unusual sessions (label 1)", "Normal sessions (label 0)"],
        [["Training (unlabeled, as in production)", int(train_m.sum()), "not used", "not used"],
         ["Validation", int(val_m.sum()), int(y_val.sum()), int((y_val == 0).sum())],
         ["Test", int(test_m.sum()), int(y_test.sum()), int((y_test == 0).sum())]],
    )
    checked = assert_point_in_time(db, rows)
    assert scaler.n_samples_seen_ == int(train_m.sum())
    print_table(
        ["Check", "Result"],
        [["Scaler fitted on training rows only", f"yes ({scaler.n_samples_seen_} rows; validation and test only transformed)"],
         ["Per-user baselines are point-in-time", f"verified on {checked} sampled sessions (only strictly earlier sessions used)"],
         ["Hyper-parameter search", "one fold: fit on the training partition, scored on the validation partition"],
         ["Test partition", "evaluated once per model, after selection"],
         ["Training labels", "never used (unsupervised); about 6% of training sessions are unusual, as in production"],
         ["Attacks", "only in validation and test windows; random draws differ between the two"]],
    )

    # 1. Default configurations
    default_results = []
    for name, model in default_models().items():
        configs = {"Isolation Forest": "300 trees, max_samples=auto", "One-Class SVM": "RBF, nu=0.05, gamma=scale",
                   "Local Outlier Factor": "20 neighbours", "Autoencoder (MLP)": "hidden (12, 6, 12)"}
        default_results.append(evaluate_model(name, configs[name], model, X_train, X_val, y_val, X_test, y_test,
                                              fam_test, args.boot, rng))
    print_comparison("A. Default configurations (test set)", default_results)

    # 2. Tuned configurations
    print("\n### B. Tuning on the validation set (GridSearchCV)\n")
    tuned_results, chosen_if = [], None
    for name, estimator in default_models().items():
        scoring = {"auc": auc_scorer}
        if name == "Isolation Forest":
            scoring["f1"] = f1_predict_scorer
        res = tune(estimator, grid[name], X_train, X_val, y_val, scoring)
        if name == "Isolation Forest":
            agg = aggregate_if(res)
            print_if_grid(agg)
            (n_est, max_s, contamination), *_ = agg[0]
            model = IsolationForest(n_estimators=n_est, max_samples=max_s, contamination=contamination, random_state=42)
            config = f"{n_est} trees, max_samples={max_s}, contamination={contamination}"
            fixed = 0.5 if contamination == "auto" else None
            percentile = 95.0 if contamination == "auto" else 100.0 * (1.0 - float(contamination))
            result = evaluate_model(name, config, model, X_train, X_val, y_val, X_test, y_test, fam_test,
                                    args.boot, rng, percentile=percentile, fixed_threshold=fixed)
            chosen_if = result
        else:
            best = int(np.argmax(res["mean_test_auc"]))
            params = res["params"][best]
            model = estimator.set_params(**params)
            config = ", ".join(f"{k}={v}" for k, v in params.items())
            result = evaluate_model(name, config, model, X_train, X_val, y_val, X_test, y_test, fam_test, args.boot, rng)
        tuned_results.append(result)
    print_comparison("C. Tuned configurations (test set)", tuned_results)

    # 3. Threshold strategies and cold start, using the tuned Isolation Forest
    unique_users = sorted(set(users[train_m].tolist()))
    tiers = {u: ("high" if i % 4 == 0 else "low" if i % 4 == 3 else "standard") for i, u in enumerate(unique_users)}
    threshold_strategies(chosen_if["train_s"], users[train_m], chosen_if["test_s"], users[test_m], y_test, tiers)
    cold_start(db, scaler, chosen_if["model"], chosen_if["thr"], args.cold)

    print("### Computational cost (why Isolation Forest suits this system)\n")
    print_table(
        ["Model", "Training", "Scoring one session", "Needs labels", "Explanations"],
        [["Isolation Forest", "O(t * psi * log psi) (t trees, psi sub-sample size)", "O(t * log psi)", "no", "exact per-feature (SHAP TreeExplainer)"],
         ["One-Class SVM", "between O(n^2) and O(n^3)", "O(support vectors * d)", "no", "model-agnostic approximations only"],
         ["Local Outlier Factor", "O(n log n) with an index", "O(k * log n) neighbour search", "no", "none built in"],
         ["Autoencoder", "O(epochs * n * parameters)", "O(parameters)", "no", "reconstruction error per feature only"]],
    )
    print("Reading the results: the attacks come from the system's own simulator, so all figures show how the models "
          "rank and separate simulated behaviour, not accuracy against real attackers. Quote the test-set tables, and "
          "say which configuration was selected on validation.")


if __name__ == "__main__":
    main()