"""
False alarms on REAL sessions. Read only: nothing is written to the database or the model registry.

    docker compose exec backend python -m scripts.evaluate_real_sessions
    docker compose exec backend python -m scripts.evaluate_real_sessions --test-share 0.3

Real sessions: closed, non-simulated sessions of accounts that are not synthetic or test accounts (prefixes in
TEST_PREFIXES) and not from the synthetic address ranges of seed_synthetic_data.

1. Out of time (the fair measurement): a model is trained exactly as production trains one (the training rule,
   MODEL_PARAMS, one threshold per risk tier) on sessions that started before a cutoff, then scores the real
   sessions after it. Real users are not known attackers, so a flag on them is counted as a false alarm, except
   sessions an administrator confirmed as a threat (reported separately).
2. As recorded: what the live models said about every real session when it ended, and administrators' verdicts.

Users are shown as User A, B, ... in order of how many real sessions they have.
"""

import argparse
import string
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sqlalchemy import or_

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.dsfs_catalog import TIER_PERCENTILES, risk_tier_for_roles
from app.db.database import SessionLocal
from app.ml.feature_engineering import FEATURE_COLUMNS, build_session_feature_vector
import app.models.service_client  # noqa: F401  (module_events has a foreign key to service_clients)
from app.models.anomaly import AnomalyAlert
from app.models.session import UserSession
from app.models.user import User
from app.services import model_registry_service as registry
from scripts.evaluate_realistic import wilson
from scripts.seed_synthetic_data import NEW_SYNTHETIC_IP_PATTERNS, OLD_SYNTHETIC_IP_PATTERNS

TEST_PREFIXES = ("synth_", "verify", "live_", "bench_", "eval", "stab_", "shots_", "sec_", "cold_", "screens_")


def real_sessions(db):
    test_users = [u.user_id for u in db.query(User).all() if u.username.lower().startswith(TEST_PREFIXES)]
    q = (
        db.query(UserSession)
        .filter(UserSession.session_duration.isnot(None), UserSession.simulated_scenario.is_(None))
        .filter(~UserSession.user_id.in_(test_users) if test_users else True)
    )
    for pattern in OLD_SYNTHETIC_IP_PATTERNS + NEW_SYNTHETIC_IP_PATTERNS:
        q = q.filter(or_(UserSession.access_location.is_(None), ~UserSession.access_location.like(pattern)))
    return q.order_by(UserSession.login_time.asc()).all()


def vectors(db, sessions):
    rows = []
    for s in sessions:
        f = build_session_feature_vector(db, s)
        rows.append([f[c] for c in FEATURE_COLUMNS])
    return np.array(rows, dtype=float).reshape(-1, len(FEATURE_COLUMNS))


def table(headers, rows):
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join("---" for _ in headers) + "|")
    for r in rows:
        print("| " + " | ".join(str(c) for c in r) + " |")
    print()


def pc(x):
    return f"{100 * x:.1f}%"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-share", type=float, default=0.3, help="latest share of real sessions to test on")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        real = real_sessions(db)
        if len(real) < 20:
            print(f"Only {len(real)} real sessions: too few to measure.")
            return
        alerts = {a.session_id: a for a in db.query(AnomalyAlert).filter(
            AnomalyAlert.session_id.in_([s.session_id for s in real])).all()}
        users = {u.user_id: u for u in db.query(User).filter(User.user_id.in_({s.user_id for s in real})).all()}
        counts = Counter(s.user_id for s in real)
        alias = {uid: f"User {string.ascii_uppercase[i]}" for i, (uid, _) in enumerate(counts.most_common())}
        tier = {uid: risk_tier_for_roles([r.role_name for r in u.roles]) for uid, u in users.items()}

        cut_index = int(round(len(real) * (1 - args.test_share)))
        cutoff = real[cut_index].login_time
        test = [s for s in real[cut_index:]]

        print("## False alarms on real sessions (read only)\n")
        print(f"{len(real)} real sessions from {len(counts)} accounts, {real[0].login_time:%d %b %Y} to "
              f"{real[-1].login_time:%d %b %Y} (UTC). Synthetic and test accounts are excluded.\n")

        # ---- 1. out of time -------------------------------------------------------------------
        train_sessions = [s for s in registry._training_sessions_query(db).all() if s.login_time < cutoff]
        X_train = vectors(db, train_sessions)
        model, scaler, train_scores = registry._fit(X_train)
        thresholds = {t: float(np.percentile(train_scores, p)) for t, p in TIER_PERCENTILES.items()}
        X_test = scaler.transform(vectors(db, test))
        scores = -model.score_samples(X_test)

        is_threat = np.array([(alerts.get(s.session_id) is not None
                               and alerts[s.session_id].review_verdict == "confirmed_threat") for s in test])
        flagged = np.array([sc >= thresholds[tier[s.user_id]] for s, sc in zip(test, scores)])
        normal = ~is_threat
        n_real_train = sum(1 for s in train_sessions if s.session_id in {r.session_id for r in real})

        print("### 1. Out of time: trained on the past, tested on later real sessions\n")
        print(f"Model trained as production does on the {len(train_sessions)} sessions before "
              f"{cutoff:%d %b %Y %H:%M} UTC ({n_real_train} real, the rest synthetic), thresholds per risk tier: "
              + ", ".join(f"{t} p{TIER_PERCENTILES[t]} = {v:.4f}" for t, v in thresholds.items())
              + f". Tested on the latest {len(test)} real sessions ({test[0].login_time:%d %b} to "
              f"{test[-1].login_time:%d %b %Y}).\n")
        k, n = int((flagged & normal).sum()), int(normal.sum())
        lo, hi = wilson(k, n)
        table(["Real sessions tested", "Confirmed threats among them", "Flagged (not confirmed threats)",
               "False-alarm rate (95% Wilson interval)", "Confirmed threats flagged"],
              [[len(test), int(is_threat.sum()), k, f"{pc(k / n)} ({pc(lo)}-{pc(hi)})",
                f"{int((flagged & is_threat).sum())} of {int(is_threat.sum())}" if is_threat.any() else "none"]])

        by_tier = defaultdict(lambda: [0, 0])
        by_user = defaultdict(lambda: [0, 0])
        for s, f, n in zip(test, flagged, normal):
            if not n:
                continue
            by_tier[tier[s.user_id]][0] += 1
            by_tier[tier[s.user_id]][1] += int(f)
            by_user[s.user_id][0] += 1
            by_user[s.user_id][1] += int(f)
        print("By risk tier (the high tier uses a lower threshold on purpose):\n")
        table(["Risk tier", "Threshold", "Sessions", "Flagged", "Rate"],
              [[t, f"p{TIER_PERCENTILES[t]}", n, k, pc(k / n)] for t, (n, k) in sorted(by_tier.items())])
        print("By account:\n")
        table(["Account", "Risk tier", "Sessions tested", "Flagged"],
              [[alias[u], tier[u], n, k] for u, (n, k) in sorted(by_user.items(), key=lambda kv: alias[kv[0]])])
        stale = sum(1 for s, f, n in zip(test, flagged, normal) if f and n and s.session_duration == 1800.0)
        print(f"{stale} of the flagged sessions have the made-up 1800 s duration of a session closed as stale "
              "before the pipeline fix (it now ends at the last recorded activity).\n")

        # What pushed the flagged sessions over the threshold (SHAP on the same out-of-time model)
        flagged_rows = X_test[flagged & normal]
        if len(flagged_rows):
            try:
                import shap
                sv = np.array(shap.TreeExplainer(model).shap_values(flagged_rows))
                push = -sv                                  # positive = towards "anomalous", as on the alert page
                top1, top3 = Counter(), Counter()
                for row in push:
                    order = np.argsort(-row)
                    top1[FEATURE_COLUMNS[order[0]]] += 1
                    for i in order[:3]:
                        top3[FEATURE_COLUMNS[i]] += 1
                print("What pushed the flagged real sessions over the threshold (SHAP, strongest feature first):\n")
                table(["Feature", "Strongest push in", "Among the top 3 in"],
                      [[f, f"{top1[f]} of {len(push)}", f"{top3[f]} of {len(push)}"]
                       for f, _ in top3.most_common()])
            except Exception as exc:  # noqa: BLE001  (explanations are a bonus; the rate above stands)
                print(f"(SHAP explanation unavailable: {exc})\n")

        # ---- 2. as recorded ------------------------------------------------------------------
        print("### 2. As recorded: what the live models said when each real session ended\n")
        scored = [alerts[s.session_id] for s in real if s.session_id in alerts]
        flagged_rec = [a for a in scored if a.is_anomaly]
        verdicts = Counter(a.review_verdict or "unreviewed" for a in flagged_rec)
        reasons = Counter(a.detection_reason or "ml_model" for a in flagged_rec)
        missed_confirmed = sum(1 for a in scored if not a.is_anomaly and a.review_verdict == "confirmed_threat")
        table(["Real sessions", "Scored", "Flagged", "Flag rate", "Confirmed threat", "False positive",
               "Authorised exception", "Unreviewed", "Not flagged but later confirmed"],
              [[len(real), len(scored), len(flagged_rec), pc(len(flagged_rec) / len(scored)) if scored else "-",
                verdicts.get("confirmed_threat", 0), verdicts.get("false_positive", 0),
                verdicts.get("authorized_exception", 0), verdicts.get("unreviewed", 0), missed_confirmed]])
        print("Flagged by: " + ", ".join(f"{k} {v}" for k, v in reasons.most_common()) + ".\n")
        print("Caveats: the real sessions are mostly development and demonstration use of this system by a few "
              "people (signing in to build, test and demonstrate it), so they are few and not representative of a "
              "school's daily use, and most of the training data is synthetic. Read the rates with the small "
              "sample and its wide interval in mind.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
