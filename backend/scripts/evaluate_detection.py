"""
Measures how well the live detection pipeline works, and checks how it treats brand-new users.

    docker compose exec backend python -m scripts.evaluate_detection
    docker compose exec backend python -m scripts.evaluate_detection --users 12 --runs 4 --seed 7

What it does:
  - Picks real users who already have history (at least 10 sessions, some older than a week).
  - For each, runs the three attack scenarios (the same ones the Simulate Attack page uses) and the
    same number of NORMAL-looking sessions copied from that user's own past behaviour, all through
    the real scoring pipeline.
  - Reports detection rate, false-positive rate, precision, F1 and AUC with confidence intervals,
    for the full pipeline and for the ML model alone.
  - Checks what z-scores look like for a user with no history and a user with one past session.

Safety:
  - Every temporary session is deleted straight after it is scored. Only sessions this script
    created are touched, and a final sweep removes any left behind if it is interrupted.
  - No emails or notifications are sent: they are switched off inside this process.

Prerequisites: backend code up to date, roles seeded, model trained (scripts.train_isolation_forest).
"""

import argparse
import json
import math
import random
import sys
import uuid
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sklearn.metrics import roc_auc_score
from sqlalchemy import func

from app.core.config import settings
from app.db.database import SessionLocal
from app.ml.feature_engineering import FEATURE_COLUMNS
from app.models.anomaly import AnomalyAlert
from app.models.notification import Notification
from app.models.session import AccessLog, UserSession
from app.models.user import User
from app.services import anomaly_service, attack_simulation_service, notification_service

# No emails or in-app notifications from the temporary sessions this script scores.
notification_service.notify_admins_of_anomaly = lambda *args, **kwargs: None

SCENARIOS = attack_simulation_service.SCENARIOS
NORMAL_TAG = "eval_normal"
MIN_HISTORY = 10      # sessions a user needs to be evaluated
MIN_AGE_DAYS = 7      # normal templates must be older than this, so they count as prior history
Z_COLUMNS = [c for c in FEATURE_COLUMNS if c.endswith("_zscore")]


# ---------------------------------------------------------------- small helpers

def wilson(successes, n, z=1.96):
    """95% confidence interval for a proportion."""
    if n == 0:
        return 0.0, 0.0
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def rate(successes, n):
    if n == 0:
        return "n/a"
    lo, hi = wilson(successes, n)
    return f"{100 * successes / n:.1f}% ({successes}/{n}, 95% CI {100 * lo:.0f}-{100 * hi:.0f}%)"


def delete_session(db, session_id):
    alert_ids = [a for (a,) in db.query(AnomalyAlert.alert_id).filter(AnomalyAlert.session_id == session_id).all()]
    if alert_ids:
        db.query(Notification).filter(Notification.alert_id.in_(alert_ids)).delete(synchronize_session=False)
        db.query(AnomalyAlert).filter(AnomalyAlert.alert_id.in_(alert_ids)).delete(synchronize_session=False)
    db.query(AccessLog).filter(AccessLog.session_id == session_id).delete(synchronize_session=False)
    db.query(UserSession).filter(UserSession.session_id == session_id).delete(synchronize_session=False)
    db.commit()


def eligible_users(db, how_many):
    rows = (
        db.query(UserSession.user_id, func.count(UserSession.session_id))
        .filter(UserSession.simulated_scenario.is_(None), UserSession.session_duration.isnot(None))
        .group_by(UserSession.user_id)
        .having(func.count(UserSession.session_id) >= MIN_HISTORY)
        .all()
    )
    ids = sorted(uid for uid, _ in rows)
    random.shuffle(ids)
    return ids[:how_many]


def record(kind, scenario, user_id, alert):
    score = float(alert.anomaly_score)
    return {
        "kind": kind,
        "scenario": scenario,
        "user_id": user_id,
        "score": score,
        "flagged": bool(alert.is_anomaly),                    # full pipeline (model + rules)
        "ml_flag": score >= anomaly_service._threshold,       # model alone
        "reason": alert.detection_reason,
        "features": json.loads(alert.features_json) if alert.features_json else {},
    }


# ---------------------------------------------------------------- normal-looking sessions

def run_normal_session(db, user_id):
    """
    A session that looks like this user's own past behaviour (same hour, similar length, activity and
    resources, same IP), placed on a recent weekday and scored through the real pipeline. The template
    is an older session that counts as normal, so every earlier session is 'prior' history.
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(days=MIN_AGE_DAYS)
    rows = (
        db.query(UserSession, AnomalyAlert)
        .outerjoin(AnomalyAlert, AnomalyAlert.session_id == UserSession.session_id)
        .filter(
            UserSession.user_id == user_id,
            UserSession.simulated_scenario.is_(None),
            UserSession.session_duration.isnot(None),
            UserSession.login_time < cutoff,
        )
        .all()
    )
    templates = [s for s, a in rows if a is None or (not a.is_anomaly and a.review_verdict != "confirmed_threat")]
    random.shuffle(templates)

    template, logs = None, []
    for candidate in templates:
        found = db.query(AccessLog).filter(AccessLog.session_id == candidate.session_id).all()
        if found:
            template, logs = candidate, found
            break
    if template is None:
        return None

    login = (now - timedelta(days=attack_simulation_service._pick_weekday_offset(now))).replace(
        hour=template.login_time.hour,
        minute=random.randint(0, 59),
        second=random.randint(0, 59),
        microsecond=0,
    )
    duration = max(60.0, template.session_duration * random.uniform(0.85, 1.15))
    session = UserSession(
        user_id=user_id,
        login_time=login,
        logout_time=login + timedelta(seconds=duration),
        session_duration=duration,
        access_location=template.access_location,
        terminated=False,
        simulated_scenario=NORMAL_TAG,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    n_events = max(1, round(len(logs) * random.uniform(0.8, 1.2)))
    for i, log in enumerate(random.choices(logs, k=n_events)):
        db.add(AccessLog(
            session_id=session.session_id,
            resource_name=log.resource_name,
            action_performed=log.action_performed,
            access_timestamp=login + timedelta(seconds=int(i / n_events * duration)),
        ))
    db.commit()

    alert = anomaly_service.score_session(db, session.session_id)
    return session.session_id, alert


# ---------------------------------------------------------------- cold-start check

def temp_user(db, label):
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"evalcold_{label}_{tag}", password="x",
        email=f"evalcold_{label}_{tag}@example.com", department="IT",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def add_closed_session(db, user, days_ago, n_events, hour=10, duration=1800.0, ip="10.0.0.5"):
    login = (datetime.utcnow() - timedelta(days=days_ago)).replace(hour=hour, minute=0, second=0, microsecond=0)
    session = UserSession(
        user_id=user.user_id, login_time=login, logout_time=login + timedelta(seconds=duration),
        session_duration=duration, access_location=ip, terminated=False,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    for i in range(n_events):
        db.add(AccessLog(session_id=session.session_id, resource_name="dashboard",
                         action_performed="read", access_timestamp=login + timedelta(seconds=i * 10)))
    db.commit()
    return session


def cold_start_check(db):
    """Ordinary sessions for users with no history, one past session, and twelve past sessions."""
    test_days = attack_simulation_service._pick_weekday_offset(datetime.utcnow())

    none_user = temp_user(db, "none")
    s_none = add_closed_session(db, none_user, test_days, n_events=6)

    one_user = temp_user(db, "one")
    add_closed_session(db, one_user, test_days + 6, n_events=6, duration=1800.0)
    s_one = add_closed_session(db, one_user, test_days, n_events=7, duration=1900.0)

    many_user = temp_user(db, "many")
    for i in range(12):
        add_closed_session(db, many_user, test_days + 2 + i,
                           n_events=random.randint(4, 9), duration=random.uniform(1500, 2200))
    s_many = add_closed_session(db, many_user, test_days, n_events=6, duration=1800.0)

    rows = []
    for label, session in (("No history", s_none), ("One past session", s_one), ("Twelve past sessions", s_many)):
        alert = anomaly_service.score_session(db, session.session_id)
        rows.append((label, json.loads(alert.features_json), alert))
    return rows


# ---------------------------------------------------------------- reporting

def confusion(records, key):
    tp = sum(1 for r in records if r["kind"] == "attack" and r[key])
    fn = sum(1 for r in records if r["kind"] == "attack" and not r[key])
    fp = sum(1 for r in records if r["kind"] == "normal" and r[key])
    tn = sum(1 for r in records if r["kind"] == "normal" and not r[key])
    return tp, fn, fp, tn


def precision_f1(tp, fn, fp):
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, f1


def print_report(records, cold_rows, threshold, args, n_users):
    attacks = [r for r in records if r["kind"] == "attack"]
    normals = [r for r in records if r["kind"] == "normal"]

    meta = {}
    path = Path(settings.ISOLATION_FOREST_THRESHOLD_PATH)
    if path.exists():
        meta = json.loads(path.read_text())

    print()
    print("## Detection evaluation")
    print(f"Model threshold {threshold:.4f} (percentile {meta.get('percentile', '?')}), "
          f"trained on {meta.get('trained_on_n_sessions', '?')} sessions.")
    print(f"Test set: {len(attacks)} simulated attack sessions and {len(normals)} normal-looking sessions "
          f"from {n_users} users (seed {args.seed}).")
    print()

    if not attacks or not normals:
        print("Not enough results to compute metrics (need both attack and normal sessions).")
        return

    f_tp, f_fn, f_fp, f_tn = confusion(records, "flagged")
    m_tp, m_fn, m_fp, m_tn = confusion(records, "ml_flag")
    f_prec, f_f1 = precision_f1(f_tp, f_fn, f_fp)
    m_prec, m_f1 = precision_f1(m_tp, m_fn, m_fp)
    auc = roc_auc_score([1 if r["kind"] == "attack" else 0 for r in records], [r["score"] for r in records])

    print("| Measure | Full pipeline (model + rules) | ML model alone |")
    print("|---|---|---|")
    print(f"| Attacks caught (recall) | {rate(f_tp, f_tp + f_fn)} | {rate(m_tp, m_tp + m_fn)} |")
    print(f"| Normal sessions wrongly flagged (FPR) | {rate(f_fp, f_fp + f_tn)} | {rate(m_fp, m_fp + m_tn)} |")
    print(f"| Precision at this test mix | {100 * f_prec:.1f}% | {100 * m_prec:.1f}% |")
    print(f"| F1 at this test mix | {f_f1:.2f} | {m_f1:.2f} |")
    print(f"| AUC-ROC (threshold-free) | {auc:.2f} | {auc:.2f} |")
    print()

    print("| Scenario | Caught (full pipeline) | Caught (model alone) | Mean score |")
    print("|---|---|---|---|")
    for key, cfg in SCENARIOS.items():
        group = [r for r in attacks if r["scenario"] == key]
        if not group:
            continue
        caught = sum(1 for r in group if r["flagged"])
        caught_ml = sum(1 for r in group if r["ml_flag"])
        mean_score = sum(r["score"] for r in group) / len(group)
        print(f"| {cfg['label']} | {rate(caught, len(group))} | {rate(caught_ml, len(group))} | {mean_score:.3f} |")
    print()

    reasons = Counter(r["reason"] for r in attacks if r["flagged"])
    if reasons:
        print("Flagged attacks by detection method: " + ", ".join(f"{k}: {v}" for k, v in reasons.items()))
        print()

    tpr = f_tp / (f_tp + f_fn)
    fpr = f_fp / (f_fp + f_tn)
    print("Projected precision (full pipeline) when attacks are rare, using the measured recall and false-positive rate:")
    print("| Share of sessions that are attacks | Precision |")
    print("|---|---|")
    for prevalence in (0.01, 0.05, 0.10):
        denom = tpr * prevalence + fpr * (1 - prevalence)
        value = f"{100 * tpr * prevalence / denom:.1f}%" if denom > 0 else "n/a"
        print(f"| {int(prevalence * 100)}% | {value} |")
    print()

    print("Z-scores on NORMAL-looking sessions (how far from the user's own history; ordinary sessions should stay small):")
    print("| Feature | Largest |z| | Sessions with |z| > 10 |")
    print("|---|---|---|")
    for col in Z_COLUMNS:
        values = [abs(r["features"].get(col, 0.0)) for r in normals if r["features"]]
        if values:
            print(f"| {col} | {max(values):.1f} | {sum(1 for v in values if v > 10)} of {len(values)} |")
    print()

    print("Cold-start check (an ordinary session for users with little history):")
    print("| Case | access z | duration z | largest |z| | score | flagged |")
    print("|---|---|---|---|---|---|")
    worst_early = 0.0
    for label, features, alert in cold_rows:
        largest = max(abs(features[c]) for c in Z_COLUMNS)
        if label != "Twelve past sessions":
            worst_early = max(worst_early, largest)
        print(f"| {label} | {features['n_access_events_zscore']:.1f} | {features['session_duration_sec_zscore']:.1f} | "
              f"{largest:.1f} | {alert.anomaly_score:.3f} | {'yes' if alert.is_anomaly else 'no'} |")
    print()
    if worst_early > 50:
        print("WARNING: users with little history get extreme z-scores (above 50). Cold-start hardening is recommended: "
              "floor the standard deviation, clamp z-scores, fall back to population statistics, then retrain.")
    else:
        print("OK: users with little history get moderate z-scores.")

    print()
    print("Reading these results:")
    print("- The attacks come from our own simulator, so 'recall' means: does the pipeline catch these behaviours. "
          "It is not a claim about real-world attackers.")
    print("- Precision and F1 depend on the test mix. The projection table shows precision at realistic attack rates.")
    print("- AUC does not depend on the threshold or the mix (the CERT notebook's AUC was 0.77, for comparison).")


# ---------------------------------------------------------------- cleanup and main

def sweep(db, start_id, user_ids):
    """Remove anything this script may have left behind (also runs after an interruption)."""
    db.rollback()
    if user_ids:
        stray = [s for (s,) in db.query(UserSession.session_id).filter(
            UserSession.session_id > start_id,
            UserSession.simulated_scenario.isnot(None),
            UserSession.user_id.in_(user_ids),
        ).all()]
        for session_id in stray:
            delete_session(db, session_id)
    for user in db.query(User).filter(User.username.like("evalcold_%")).all():
        for (session_id,) in db.query(UserSession.session_id).filter(UserSession.user_id == user.user_id).all():
            delete_session(db, session_id)
        db.delete(user)
        db.commit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=10, help="how many users to test")
    parser.add_argument("--runs", type=int, default=3, help="runs per scenario per user")
    parser.add_argument("--normals", type=int, default=None, help="normal sessions per user (default: runs x scenarios)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    random.seed(args.seed)

    if not anomaly_service._load_artifacts():
        sys.exit("No trained model found. Run: python -m scripts.train_isolation_forest (then restart the backend).")
    threshold = anomaly_service._threshold

    db = SessionLocal()
    start_id = db.query(func.max(UserSession.session_id)).scalar() or 0
    user_ids, records = [], []
    try:
        sweep(db, start_id, [])   # leftovers from an interrupted earlier run
        user_ids = eligible_users(db, args.users)
        if not user_ids:
            sys.exit(f"No user has {MIN_HISTORY}+ sessions yet. Run scripts.seed_synthetic_data first.")

        n_normals = args.normals or args.runs * len(SCENARIOS)
        print(f"Testing {len(user_ids)} users: {args.runs} run(s) of each of {len(SCENARIOS)} scenarios "
              f"and {n_normals} normal sessions per user. No emails are sent.")

        for user_id in user_ids:
            for key in SCENARIOS:
                for _ in range(args.runs):
                    result = attack_simulation_service.run_scenario(db, user_id, key)
                    alert = db.query(AnomalyAlert).filter(AnomalyAlert.alert_id == result["alert_id"]).first()
                    if alert is not None:
                        records.append(record("attack", key, user_id, alert))
                    delete_session(db, result["session_id"])

            made, attempts = 0, 0
            while made < n_normals and attempts < n_normals * 3:
                attempts += 1
                outcome = run_normal_session(db, user_id)
                if outcome is None:
                    break
                session_id, alert = outcome
                if alert is not None:
                    records.append(record("normal", "normal", user_id, alert))
                    made += 1
                delete_session(db, session_id)
            print(f"  user {user_id}: done")

        cold_rows = cold_start_check(db)
        print_report(records, cold_rows, threshold, args, len(user_ids))
    finally:
        sweep(db, start_id, user_ids)
        db.close()


if __name__ == "__main__":
    main()