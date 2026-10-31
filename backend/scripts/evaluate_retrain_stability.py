"""
Does the threshold stay put when the model is retrained week after week?

    docker compose exec backend python -m scripts.evaluate_retrain_stability
    docker compose exec backend python -m scripts.evaluate_retrain_stability --review-rate 0.5

Everything happens in a throwaway IN-MEMORY database; real data is never touched.

Replays the production loop with synthetic users (the same generator as seed_synthetic_data): a few
weeks of history, then each week new sessions arrive, the live model scores them (writing alerts,
as score_session does), and the model is retrained on the training set. The same data is replayed
twice, once per training rule:

  previous  the rule before the pipeline fix: train only on sessions that count as normal behaviour,
            so every session the model flagged and nobody reviewed is left out
  current   model_registry_service._training_sessions_query: leave out only known threats

The threshold is the 95th percentile of the training scores, so leaving out the model's own flags
removes the top of the distribution on each retrain. The question is whether that makes the
threshold fall and the false alarms on NEW normal sessions rise. --review-rate is the share of each
week's flags an administrator reviews (unusual sessions confirmed, normal ones cleared).
Approximation: a week's sessions are scored together, against the history before that week.
"""

import argparse
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.business_time import local_now
from app.core.dsfs_catalog import TIER_PERCENTILES
from app.ml.feature_engineering import counts_as_normal_behaviour
from app.models.anomaly import AnomalyAlert
from app.models.session import UserSession
from app.services import model_registry_service as registry
from scripts import seed_synthetic_data as seed
from scripts.model_experiments import featurize, make_db, make_user, prf, with_day

PERCENTILE = TIER_PERCENTILES["standard"]


def previous_rule(db):
    """The training set before the pipeline fix (identical to the per-user baseline rule)."""
    return (
        db.query(UserSession)
        .filter(UserSession.session_duration.isnot(None), UserSession.simulated_scenario.is_(None))
        .outerjoin(AnomalyAlert, AnomalyAlert.session_id == UserSession.session_id)
        .filter(counts_as_normal_behaviour())
        .order_by(UserSession.login_time.asc())
    )


RULES = {"previous": previous_rule, "current": registry._training_sessions_query}


def add_week(db, users, week_start, per_user):
    """per_user sessions for each user on weekdays of the week starting week_start. Returns rows."""
    rows = []
    weekdays = [week_start + timedelta(days=d) for d in range(7) if (week_start + timedelta(days=d)).weekday() < 5]
    for user, profile, used in users:
        for _ in range(per_user):
            unusual = random.random() < seed.ANOMALOUS_SESSION_RATE
            params = seed.anomalous_params(profile, used) if unusual else seed.normal_params(profile)
            session = with_day(random.choice(weekdays), lambda: seed.add_session(db, user.user_id, params))
            rows.append({"session_id": session.session_id, "label": int(unusual)})
    db.commit()
    return rows


def train(db, rule):
    sessions = rule(db).all()
    X = featurize(db, [{"session_id": s.session_id} for s in sessions])
    n_hold = max(1, int(round(len(X) * registry.HOLDOUT_FRACTION)))
    m_h, s_h, scores_h = registry._fit(X[:-n_hold])          # guardrail 3, exactly as train_candidate
    hold_rate = float((-m_h.score_samples(s_h.transform(X[-n_hold:])) >= np.percentile(scores_h, PERCENTILE)).mean())
    model, scaler, scores = registry._fit(X)
    return model, scaler, float(np.percentile(scores, PERCENTILE)), len(X), hold_rate


def replay(rule_name, args):
    random.seed(args.seed)
    # Reviews draw from their own generator, once per session whether flagged or not, so the
    # session data stays identical for both rules (they flag different sessions).
    review_rng = random.Random(args.seed + 1_000_003)
    db = make_db()
    users = []
    for i in range(args.users):
        users.append((make_user(db, f"stab_{i:02d}"), seed.make_profile(), set()))

    today = datetime(*local_now().timetuple()[:3])
    start = today - timedelta(weeks=args.history_weeks + args.weeks)
    start -= timedelta(days=start.weekday())                       # a Monday
    for w in range(args.history_weeks):
        add_week(db, users, start + timedelta(weeks=w), args.per_user)

    model, scaler, thr, n_train, hold = train(db, RULES[rule_name])
    out = [{"retrain": 0, "threshold": thr, "n_train": n_train, "holdout": hold, "fpr": None, "recall": None}]
    for w in range(args.weeks):
        rows = add_week(db, users, start + timedelta(weeks=args.history_weeks + w), args.per_user)
        X = featurize(db, rows)
        scores = -model.score_samples(scaler.transform(X))
        y = np.array([r["label"] for r in rows])
        flagged = scores >= thr
        for row, score, flag in zip(rows, scores, flagged):
            verdict = None
            reviewed = review_rng.random() < args.review_rate
            if flag and reviewed:
                verdict = "confirmed_threat" if row["label"] else "false_positive"
            db.add(AnomalyAlert(session_id=row["session_id"], anomaly_score=float(score), is_anomaly=bool(flag),
                                threshold_used=thr, detection_reason="ml_model", review_verdict=verdict))
        db.commit()
        m = prf(y, flagged)
        model, scaler, thr, n_train, hold = train(db, RULES[rule_name])
        out.append({"retrain": w + 1, "threshold": thr, "n_train": n_train, "holdout": hold,
                    "fpr": m["fpr"], "recall": m["recall"], "n_normal": int((y == 0).sum()), "n_unusual": int(y.sum())})
    total = db.query(UserSession).filter(UserSession.session_duration.isnot(None)).count()
    db.close()
    return out, total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--history-weeks", type=int, default=4, help="weeks of history before the first model")
    parser.add_argument("--weeks", type=int, default=8, help="weekly score-then-retrain cycles")
    parser.add_argument("--per-user", type=int, default=5, help="sessions per user per week")
    parser.add_argument("--review-rate", type=float, default=0.0, help="share of each week's flags reviewed")
    parser.add_argument("--seeds", type=int, nargs="+", default=[42], help="one replay per seed (same data for both rules)")
    args = parser.parse_args()

    print(f"## Retraining stability (in-memory replay, seeds {', '.join(map(str, args.seeds))})\n")
    print(f"{args.users} synthetic users, {args.history_weeks} weeks of history, then {args.weeks} weekly cycles of "
          f"{args.per_user} sessions per user. Administrators review {args.review_rate:.0%} of each week's flags. "
          f"Threshold: {PERCENTILE}th percentile of the training scores (standard tier).\n")

    summary = {name: [] for name in RULES}
    for n, seed_value in enumerate(args.seeds):
        args.seed = seed_value
        results = {}
        for name in RULES:
            results[name], total = replay(name, args)
            r = results[name]
            fp = sum(round(x["fpr"] * x["n_normal"]) for x in r[1:])
            normal = sum(x["n_normal"] for x in r[1:])
            caught = sum(round(x["recall"] * x["n_unusual"]) for x in r[1:])
            unusual = sum(x["n_unusual"] for x in r[1:])
            last_half = r[1 + args.weeks // 2:]
            summary[name].append({
                "seed": seed_value, "first": r[0]["threshold"], "last": r[-1]["threshold"],
                "fpr": fp / normal, "fpr_late": sum(round(x["fpr"] * x["n_normal"]) for x in last_half)
                / sum(x["n_normal"] for x in last_half),
                "recall": caught / unusual, "holdout": float(np.mean([x["holdout"] for x in r[1:]])),
                "left_out": total - r[-1]["n_train"], "total": total,
            })
        if n == 0:
            print(f"### Week by week (seed {seed_value})\n")
            print("| Retrain | Rule | Training sessions | Threshold | Guardrail 3 (holdout flag rate) | "
                  "False alarms on the next week's normal sessions | Next week's unusual sessions caught |")
            print("|---|---|---|---|---|---|---|")
            for i in range(args.weeks + 1):
                for name in RULES:
                    r = results[name][i]
                    fpr = "" if r["fpr"] is None else f"{r['fpr']:.1%} of {r['n_normal']}"
                    rec = "" if r["recall"] is None else f"{r['recall']:.0%} of {r['n_unusual']}"
                    print(f"| {r['retrain']} | {name} | {r['n_train']} | {r['threshold']:.4f} | {r['holdout']:.1%} "
                          f"| {fpr} | {rec} |")

    print("\n### Summary per seed (false alarms and catches pooled over all weeks)\n")
    print("| Seed | Rule | Threshold change (first to last model) | False alarms, all weeks | False alarms, second half "
          "| Unusual sessions caught | Guardrail 3, mean | Left out of training at the end |")
    print("|---|---|---|---|---|---|---|---|")
    for i in range(len(args.seeds)):
        for name in RULES:
            s = summary[name][i]
            print(f"| {s['seed']} | {name} | {s['last'] - s['first']:+.4f} | {s['fpr']:.1%} | {s['fpr_late']:.1%} "
                  f"| {s['recall']:.0%} | {s['holdout']:.1%} | {s['left_out']} of {s['total']} |")
    print("\n### Mean over seeds\n")
    print("| Rule | Threshold change | False alarms, all weeks | False alarms, second half | Unusual sessions caught "
          "| Guardrail 3, mean |")
    print("|---|---|---|---|---|---|")
    for name in RULES:
        rows = summary[name]
        mean = lambda key: float(np.mean([s[key] for s in rows]))
        print(f"| {name} | {mean('last') - mean('first'):+.4f} | {mean('fpr'):.1%} | {mean('fpr_late'):.1%} "
              f"| {mean('recall'):.0%} | {mean('holdout'):.1%} |")
    print(f"\nAbout {100 - PERCENTILE}% false alarms is the design target. Guardrail 3 checks recent sessions from "
          "the SAME training set, so under the previous rule it cannot see a drift caused by the filter itself.")


if __name__ == "__main__":
    main()
