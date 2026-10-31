"""
Measures what reading clock hours in local business time (instead of UTC) changes for REAL logins.

    docker compose exec backend python -m scripts.evaluate_timezone_effect \
        --before 20261031-095954 --after 20261031-100622

Real sessions are closed, non-simulated sessions of real accounts (synthetic 'synth_' users and the
synthetic address ranges are excluded). Each one is featurised twice:
  - UTC:   hours and weekdays read straight from the stored UTC timestamp (the old behaviour)
  - local: hours and weekdays read in settings.BUSINESS_TIMEZONE (the current behaviour)
The 'before' model version scores the UTC features and the 'after' version scores the local ones,
each with its own per-tier thresholds. Nothing is written to the database.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
from sqlalchemy import not_, or_

from app.core.business_time import tz_label
from app.core.config import settings
from app.core.dsfs_catalog import risk_tier_for_roles
from app.db.database import SessionLocal
from app.ml import feature_engineering as fe
from app.models.session import UserSession
from app.models.user import User
from scripts.seed_synthetic_data import NEW_SYNTHETIC_IP_PATTERNS, OLD_SYNTHETIC_IP_PATTERNS, SYNTH_USER_PREFIX

VERSIONS_DIR = Path(settings.ISOLATION_FOREST_MODEL_PATH).parent / "versions"


def load_version(version_id):
    folder = VERSIONS_DIR / version_id
    meta = json.loads((folder / "threshold.json").read_text())
    return joblib.load(folder / "isolation_forest.joblib"), joblib.load(folder / "scaler.joblib"), meta


def features(db, session, utc):
    """Production features; with utc=True the local-time conversion is switched off."""
    original = fe.to_local
    if utc:
        fe.to_local = lambda value: value
    try:
        return fe.build_session_feature_vector(db, session)
    finally:
        fe.to_local = original


def score(model, scaler, meta, vector, tier):
    value = float(-model.score_samples(scaler.transform([[vector[c] for c in fe.FEATURE_COLUMNS]]))[0])
    threshold = (meta.get("tier_thresholds") or {}).get(tier, meta["threshold"])
    return value, value >= threshold


def pct(n, total):
    return f"{100 * n / total:.1f}% ({n}/{total})" if total else "n/a"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", required=True, help="model version trained with UTC hours")
    parser.add_argument("--after", required=True, help="model version trained with local hours")
    args = parser.parse_args()

    before = load_version(args.before)
    after = load_version(args.after)
    zone = tz_label()

    db = SessionLocal()
    try:
        synthetic_ips = [UserSession.access_location.like(p) for p in OLD_SYNTHETIC_IP_PATTERNS + NEW_SYNTHETIC_IP_PATTERNS]
        sessions = (
            db.query(UserSession)
            .join(User, User.user_id == UserSession.user_id)
            .filter(
                UserSession.session_duration.isnot(None),
                UserSession.simulated_scenario.is_(None),
                not_(User.username.startswith(SYNTH_USER_PREFIX, autoescape=True)),
                not_(or_(*synthetic_ips)),
            )
            .all()
        )

        rows = []
        for s in sessions:
            tier = risk_tier_for_roles([r.role_name for r in s.user.roles])
            f_utc, f_local = features(db, s, utc=True), features(db, s, utc=False)
            _, flag_before = score(*before, f_utc, tier)
            _, flag_after = score(*after, f_local, tier)
            rows.append({"utc": f_utc, "local": f_local, "before": flag_before, "after": flag_after})
    finally:
        db.close()

    n = len(rows)
    print("## Effect of reading hours in local time on real logins\n")
    print(f"Real sessions: {n} (closed, not simulated, not synthetic). Local time zone: "
          f"{settings.BUSINESS_TIMEZONE} ({zone}).")
    print(f"Before: model {args.before} on UTC hours. After: model {args.after} on local hours.\n")

    print("| Measure | Before (UTC hours) | After (local hours) |")
    print("|---|---|---|")
    off_b = sum(r["utc"]["is_offhours"] for r in rows)
    off_a = sum(r["local"]["is_offhours"] for r in rows)
    wk_b = sum(r["utc"]["is_weekend"] for r in rows)
    wk_a = sum(r["local"]["is_weekend"] for r in rows)
    fl_b = sum(r["before"] for r in rows)
    fl_a = sum(r["after"] for r in rows)
    print(f"| Logins counted as off-hours | {pct(off_b, n)} | {pct(off_a, n)} |")
    print(f"| Logins counted as weekend | {pct(wk_b, n)} | {pct(wk_a, n)} |")
    print(f"| Sessions flagged by the model | {pct(fl_b, n)} | {pct(fl_a, n)} |")
    print()

    changed_off = sum(1 for r in rows if r["utc"]["is_offhours"] != r["local"]["is_offhours"])
    wrongly_off = sum(1 for r in rows if r["utc"]["is_offhours"] and not r["local"]["is_offhours"])
    wrongly_on = sum(1 for r in rows if not r["utc"]["is_offhours"] and r["local"]["is_offhours"])
    print(f"UTC misread the off-hours flag for {pct(changed_off, n)} of real sessions:")
    print(f"- {wrongly_off} business-hours logins in {zone} that UTC called off-hours (early mornings)")
    print(f"- {wrongly_on} off-hours logins in {zone} that UTC called business hours (evenings)\n")

    print(f"Login hour of real sessions (count), UTC vs local ({zone}):\n")
    utc_hours = Counter(int(r["utc"]["login_hour"]) for r in rows)
    local_hours = Counter(int(r["local"]["login_hour"]) for r in rows)
    print("| Hour | UTC | Local |")
    print("|---|---|---|")
    for h in range(24):
        if utc_hours[h] or local_hours[h]:
            print(f"| {h:02d}:00 | {utc_hours[h]} | {local_hours[h]} |")


if __name__ == "__main__":
    main()
