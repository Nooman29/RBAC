"""
A more realistic evaluation of the anomaly detector than the headline benchmark.

    docker compose exec backend python -m scripts.evaluate_realistic                 # full run, a few minutes
    docker compose exec backend python -m scripts.evaluate_realistic --quick         # smoke test
    docker compose exec backend python -m scripts.evaluate_realistic --json out.json # also save the numbers

Everything happens in a throwaway IN-MEMORY database; real data is never touched. It uses the same synthetic
users, the same leakage-safe split (each user's first 60% of sessions train, next 20% validate, last 20% test,
point-in-time baselines) and the PRODUCTION model: model_registry_service.MODEL_PARAMS, threshold at the 95th
percentile of the training scores (standard tier).

Why: the headline benchmark (scripts/model_experiments.py) gives F1 0.99, but its test set is 46% attacks and
95% of those come from the three fixed simulator scenarios, which were designed around the features the model
measures. This script asks the questions that number cannot answer:

  A. Headline check, with confidence intervals by USER (sessions of one user are not independent).
  B. Prevalence: precision, F1 and PR-AUC when attacks are 20%, 5%, 1% or 0.3% of sessions (CERT r4.2 has
     about 0.3% malicious user-days), for three kinds of attack.
  C. Attack strength: insiders who keep their routine (usual hours, a known address, weekdays) and only do
     MORE (1x to 6x their usual volume, more destructive, longer); and each unusual trait on its own.
  D. Leave one scenario out: choose the configuration and threshold on validation attacks that do NOT
     include a scenario, then test on that scenario (does tuning just learn the simulator?).
"""

import argparse
import json
import random
import sys
from datetime import timedelta
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.dsfs_catalog import TIER_PERCENTILES
from app.services import attack_simulation_service as sim
from app.services import model_registry_service as registry
from scripts import seed_synthetic_data as seed
from scripts.model_experiments import (
    best_f1_threshold, build_history, featurize, make_db, make_user, prf, split_for, weekday_in, with_day,
)

PERCENTILE = TIER_PERCENTILES["standard"]
SCENARIOS = list(sim.SCENARIOS)
PREVALENCES = [0.20, 0.05, 0.01, 0.003]
MULTIPLIERS = [1.0, 1.5, 2.0, 3.0, 4.0, 6.0]
SWEEPS = {
    "volume": "more actions than usual (usual mix of reads and writes)",
    "destructive": "more actions, 40% writes and 30% deletions",
    "long": "a longer session than usual",
    "combined": "all three at once",
}
TRAIT_LABELS = {
    "night": "night login (22:00-04:59)", "new_ip": "unfamiliar address", "volume": "3-6x the usual volume",
    "long": "2-4x the usual length", "destructive": "40% writes, 30% deletions", "wide": "all resources equally",
    "weekend": "weekend login",
}
LOSO_GRID = [(n, m) for n in (100, 200, 300) for m in (128, 256, 1.0)]


# ------------------------------------------------------------------ data

def routine(profile):
    """Session parameters inside the user's routine: usual hours, first known address, a weekday."""
    p = seed.normal_params(profile)
    p["hour"] = min(19, profile["typical_hour"] + random.randint(0, 3))
    p["ip"] = profile["ips"][0]
    p["weekend"] = False
    return p


def sweep_params(profile, family, m):
    p = routine(profile)
    if family in ("volume", "destructive", "combined"):
        p["events"] = max(1, round(profile["typical_events"] * m))
    if family in ("destructive", "combined"):
        p["action_weights"] = [0.3, 0.4, 0.3]
    if family in ("long", "combined"):
        p["duration"] = profile["typical_duration"] * m
    return p


def add_attack(db, user, params, day, tag):
    """A session for evaluation only: tagged like the simulator's attacks, so it never enters a baseline
    or the training set."""
    session = with_day(day, lambda: seed.add_session(db, user.user_id, params))
    session.simulated_scenario = tag
    db.commit()
    return session


def generate(db, n_users, attacks, per_cell, extra_normal):
    rows = []
    for i in range(n_users):
        user = make_user(db, f"bench_{i:03d}")
        profile, items = build_history(db, user, random.randint(*seed.SESSIONS_PER_USER))
        parts = dict(zip(("train", "val", "test"), split_for(items)))
        for name, part in parts.items():
            for session, label in part:
                rows.append({"session_id": session.session_id, "user": user.user_id, "split": name,
                             "label": label, "family": "unusual" if label else "normal"})
        for name in ("val", "test"):
            start, end = parts[name][0][0].login_time, parts[name][-1][0].login_time
            for key in SCENARIOS:
                for _ in range(attacks):
                    s = sim.create_scenario_session(db, user.user_id, key, day=weekday_in(start, end))
                    rows.append({"session_id": s.session_id, "user": user.user_id, "split": name, "label": 1,
                                 "family": key})
        start, end = parts["test"][0][0].login_time, parts["test"][-1][0].login_time
        for family in SWEEPS:
            for m in MULTIPLIERS:
                for _ in range(per_cell):
                    s = add_attack(db, user, sweep_params(profile, family, m), weekday_in(start, end), "sweep")
                    rows.append({"session_id": s.session_id, "user": user.user_id, "split": "sweep", "label": 1,
                                 "family": family, "mult": m})
        used = set()
        for trait in seed.TRAITS:
            for _ in range(per_cell):
                p = seed.apply_trait(routine(profile), trait, used)
                day = weekday_in(start, end)
                if trait == "weekend":            # move to the Saturday after the chosen weekday
                    day = day + timedelta(days=5 - day.weekday())
                s = add_attack(db, user, p, day, "trait")
                rows.append({"session_id": s.session_id, "user": user.user_id, "split": "trait", "label": 1,
                             "family": trait})
        # Extra ordinary sessions in the test window, only to measure the false-positive rate more precisely.
        # Kept out of baselines like the attacks, so they change nothing else in the benchmark.
        for _ in range(extra_normal):
            s = add_attack(db, user, seed.normal_params(profile), weekday_in(start, end), "extra_normal")
            rows.append({"session_id": s.session_id, "user": user.user_id, "split": "extra_normal", "label": 0,
                         "family": "normal"})
    return rows


# ------------------------------------------------------------------ metrics

def at_prevalence(recall, fpr, p):
    """Precision and F1 expected when a share p of sessions are attacks (recall and FPR do not depend on p)."""
    tp, fp = recall * p, fpr * (1 - p)
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, f1


def weighted_ap(scores_pos, scores_neg, p):
    """PR-AUC (average precision) re-weighted to prevalence p."""
    s = np.concatenate([scores_pos, scores_neg])
    y = np.concatenate([np.ones(len(scores_pos)), np.zeros(len(scores_neg))])
    w = np.concatenate([np.full(len(scores_pos), p / len(scores_pos)),
                        np.full(len(scores_neg), (1 - p) / len(scores_neg))])
    return float(average_precision_score(y, s, sample_weight=w))


def user_bootstrap(users_pos, users_neg, n_boot, rng):
    """Yields (pos_idx, neg_idx) for resamples of USERS with replacement (all of a user's sessions together)."""
    ids = sorted(set(users_pos.tolist()) | set(users_neg.tolist()))
    by_pos = {u: np.flatnonzero(users_pos == u) for u in ids}
    by_neg = {u: np.flatnonzero(users_neg == u) for u in ids}
    for _ in range(n_boot):
        pick = rng.choice(ids, size=len(ids), replace=True)
        pos = np.concatenate([by_pos[u] for u in pick])
        neg = np.concatenate([by_neg[u] for u in pick])
        if len(pos) and len(neg):
            yield pos, neg


def ci(values):
    return float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))


def wilson(k, n, z=1.96):
    """95% interval for a proportion k/n that stays honest at k = 0 (0 of 700 is not 'exactly 0%')."""
    if n == 0:
        return 0.0, 1.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return float(max(0.0, centre - half)), float(min(1.0, centre + half))


def table(headers, rows):
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join("---" for _ in headers) + "|")
    for r in rows:
        print("| " + " | ".join(str(c) for c in r) + " |")
    print()


def pc(x):
    return f"{100 * x:.1f}%"


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=24)
    parser.add_argument("--attacks", type=int, default=3, help="simulator attacks per scenario per user, val and test")
    parser.add_argument("--per-cell", type=int, default=3, help="sessions per user for each strength/trait cell")
    parser.add_argument("--extra-normal", type=int, default=20,
                        help="extra ordinary test sessions per user, to measure the false-positive rate")
    parser.add_argument("--boot", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--json", help="also write the results to this JSON file")
    args = parser.parse_args()
    if args.quick:
        args.users, args.attacks, args.per_cell, args.boot, args.extra_normal = 8, 2, 1, 100, 5
    random.seed(args.seed)
    rng = np.random.default_rng(args.seed)
    out = {"config": vars(args).copy()}

    db = make_db()
    rows = generate(db, args.users, args.attacks, args.per_cell, args.extra_normal)
    X = featurize(db, rows)
    split = np.array([r["split"] for r in rows])
    fam = np.array([r["family"] for r in rows])
    users = np.array([r["user"] for r in rows])
    mult = np.array([r.get("mult", 0.0) for r in rows])
    y = np.array([r["label"] for r in rows])

    train = split == "train"
    model, scaler, train_scores = registry._fit(X[train])
    thr = float(np.percentile(train_scores, PERCENTILE))
    scores = -model.score_samples(scaler.transform(X))
    flag = scores >= thr

    test_normal = (split == "test") & (fam == "normal")
    n_normal = int(test_normal.sum())
    # The false-positive rate is measured on every ordinary test-window session: the test set's own normal
    # sessions plus the extra ones generated for this purpose.
    all_normal = test_normal | (split == "extra_normal")
    n_all_normal, k_all_normal = int(all_normal.sum()), int(flag[all_normal].sum())
    fpr = k_all_normal / n_all_normal
    fpr_ci = wilson(k_all_normal, n_all_normal)

    print("## Realistic evaluation of the production model (isolated benchmark database, seed %d%s)\n"
          % (args.seed, ", quick mode" if args.quick else ""))
    print(f"Production configuration: {registry.MODEL_PARAMS['n_estimators']} trees, max_samples="
          f"{registry.MODEL_PARAMS['max_samples']}, threshold = {PERCENTILE}th percentile of the training scores "
          f"({thr:.4f}). {args.users} synthetic users; {int(train.sum())} training sessions (unlabeled, about 6% "
          f"unusual); {n_normal} normal sessions in the test set. Recall intervals: 95%, resampling USERS "
          f"({args.boot} resamples). False-positive rate: {k_all_normal} of {n_all_normal} ordinary test-window "
          f"sessions = {pc(fpr)}, 95% Wilson interval {pc(fpr_ci[0])}-{pc(fpr_ci[1])}.\n")

    # ---- A. headline check ------------------------------------------------------------------
    test = split == "test"
    m = prf(y[test], flag[test])
    f1_users = []
    idx_test = np.flatnonzero(test)
    for pos, neg in user_bootstrap(users[test & (y == 1)], users[test & (y == 0)], args.boot, rng):
        pos_i, neg_i = np.flatnonzero(test & (y == 1))[pos], np.flatnonzero(test & (y == 0))[neg]
        sel = np.concatenate([pos_i, neg_i])
        f1_users.append(prf(y[sel], flag[sel])["f1"])
    f1_sessions = []
    for _ in range(args.boot):
        sel = rng.choice(idx_test, size=len(idx_test), replace=True)
        f1_sessions.append(prf(y[sel], flag[sel])["f1"])
    print("### A. The headline test set, with honest confidence intervals\n")
    table(["Test set", "Attacks", "Normal", "Precision", "Recall", "False-positive rate", "F1",
           "F1 95% CI (resampling sessions)", "F1 95% CI (resampling users)"],
          [["normal + generic unusual + 3 simulator scenarios", int(y[test].sum()), n_normal, pc(m["precision"]),
            pc(m["recall"]), pc(m["fpr"]), f"{m['f1']:.2f}", "%.2f-%.2f" % ci(f1_sessions),
            "%.2f-%.2f" % ci(f1_users)]])
    share_sim = float(np.isin(fam[test & (y == 1)], SCENARIOS).mean())
    print(f"{share_sim:.0%} of the test attacks come from the three simulator scenarios; attacks are "
          f"{y[test].mean():.0%} of the test set.\n")
    out["A"] = {"precision": m["precision"], "recall": m["recall"], "fpr": m["fpr"], "f1": m["f1"],
                "f1_ci_sessions": ci(f1_sessions), "f1_ci_users": ci(f1_users), "attack_share": float(y[test].mean()),
                "simulator_share": share_sim, "threshold": thr}

    # ---- B. prevalence ----------------------------------------------------------------------
    groups = {
        "Simulator scenarios": test & np.isin(fam, SCENARIOS),
        "Generic unusual sessions": test & (fam == "unusual"),
        "Routine-hours insider, 2x activity (combined)": (split == "sweep") & (fam == "combined") & (mult == 2.0),
    }
    print("### B. What the same model gives at realistic attack rates\n")
    print("Recall and false-positive rate do not depend on how common attacks are; precision, F1 and PR-AUC do. "
          "Each attack group is scored against the same ordinary sessions, re-weighted to the attack rate. "
          "'Worst case' combines the low end of recall with the high end of the false-positive rate (both 95%).\n")
    out["B"] = {"fpr": fpr, "fpr_ci": fpr_ci, "n_normal": n_all_normal, "k_normal": k_all_normal, "groups": {}}
    neg_idx = np.flatnonzero(all_normal)
    brows = []
    for gname, gmask in groups.items():
        pos_idx = np.flatnonzero(gmask)
        recall = float(flag[pos_idx].mean())
        boots = list(user_bootstrap(users[pos_idx], users[neg_idx], args.boot, rng))
        rec_ci = ci([float(flag[pos_idx][p].mean()) for p, _ in boots])
        out["B"]["groups"][gname] = {"n": int(len(pos_idx)), "recall": recall, "recall_ci": rec_ci,
                                     "by_prevalence": {}}
        for p in PREVALENCES:
            prec, f1 = at_prevalence(recall, fpr, p)
            prec_worst, f1_worst = at_prevalence(rec_ci[0], fpr_ci[1], p)
            ap = weighted_ap(scores[pos_idx], scores[neg_idx], p)
            ap_b = [weighted_ap(scores[pos_idx][a], scores[neg_idx][b], p) for a, b in boots[:200]]
            out["B"]["groups"][gname]["by_prevalence"][str(p)] = {
                "precision": prec, "precision_worst": prec_worst, "f1": f1, "f1_worst": f1_worst,
                "pr_auc": ap, "pr_auc_ci": ci(ap_b)}
            brows.append([gname, len(pos_idx), "%s (%s-%s)" % (pc(recall), *map(pc, rec_ci)), pc(p),
                          pc(prec), pc(prec_worst), f"{f1:.2f}", f"{f1_worst:.2f}", "%.2f (%.2f-%.2f)" % (ap, *ci(ap_b))])
    table(["Attack group", "Attacks", "Recall (95% CI)", "Attack rate", "Precision", "Precision, worst case",
           "F1", "F1, worst case", "PR-AUC (95% CI)"], brows)

    # ---- C. strength ------------------------------------------------------------------------
    print("### C. Insiders who keep their routine: how much more must they do before they are caught?\n")
    print("Each session is inside the user's routine (usual hours, a known address, a weekday) and differs only "
          "as described. For volume and length, 1.0x is the user's usual amount, so its recall is close to the "
          "false-positive rate; destructive and combined also change the mix of actions at 1.0x.\n")
    out["C"] = {"sweep": {}, "traits": {}}
    crow = []
    for family, desc in SWEEPS.items():
        cells = []
        for mlt in MULTIPLIERS:
            sel = (split == "sweep") & (fam == family) & (mult == mlt)
            r = float(flag[sel].mean())
            cells.append(f"{r:.0%}")
            out["C"]["sweep"].setdefault(family, {})[str(mlt)] = {"recall": r, "n": int(sel.sum())}
        crow.append([f"{family}: {desc}"] + cells)
    n_cell = int(((split == "sweep") & (fam == "volume") & (mult == 1.0)).sum())
    table(["Change (n = %d sessions per cell)" % n_cell] + [f"{m_:g}x" for m_ in MULTIPLIERS], crow)

    print("One unusual trait on its own (everything else inside the routine):\n")
    trows = []
    for trait in seed.TRAITS:
        sel = (split == "trait") & (fam == trait)
        r = float(flag[sel].mean())
        out["C"]["traits"][trait] = {"recall": r, "n": int(sel.sum())}
        trows.append([TRAIT_LABELS[trait], int(sel.sum()), pc(r)])
    table(["Trait", "Sessions", "Caught"], trows)

    # ---- D. leave one scenario out ------------------------------------------------------------
    print("### D. Leave one scenario out: does tuning on attacks just learn the simulator?\n")
    print("For each scenario, the configuration (trees x max_samples) and the threshold are chosen on validation "
          "attacks WITHOUT that scenario (best F1), then the scenario is tested. 'Seen' repeats the selection with "
          "it included. The production rule needs no attacks at all (95th percentile).\n")
    scaler_t = StandardScaler().fit(X[train])
    Xs = scaler_t.transform(X)
    fitted = {cfg: IsolationForest(n_estimators=cfg[0], max_samples=cfg[1], random_state=42, n_jobs=-1).fit(Xs[train])
              for cfg in LOSO_GRID}
    cfg_scores = {cfg: -mdl.score_samples(Xs) for cfg, mdl in fitted.items()}
    val = split == "val"
    out["D"] = {}
    drows = []
    for held in SCENARIOS:
        result = {}
        for variant, keep in (("unseen", lambda f: f != held), ("seen", lambda f: True)):
            vmask = val & ((fam == "normal") | ((y == 1) & np.array([keep(f) for f in fam])))
            best = None
            for cfg in LOSO_GRID:
                t = best_f1_threshold(y[vmask], cfg_scores[cfg][vmask])
                f = prf(y[vmask], cfg_scores[cfg][vmask] >= t)["f1"]
                if best is None or f > best[0]:
                    best = (f, cfg, t)
            _, cfg, t = best
            held_mask = test & (fam == held)
            result[variant] = {"config": f"{cfg[0]} trees, max_samples={cfg[1]}",
                               "recall": float((cfg_scores[cfg][held_mask] >= t).mean()),
                               "fpr": float((cfg_scores[cfg][all_normal] >= t).mean())}
        result["production"] = {"recall": float(flag[test & (fam == held)].mean()), "fpr": fpr}
        out["D"][held] = result
        drows.append([sim.SCENARIOS[held]["label"], result["unseen"]["config"], pc(result["unseen"]["recall"]),
                      pc(result["unseen"]["fpr"]), pc(result["seen"]["recall"]), pc(result["seen"]["fpr"]),
                      pc(result["production"]["recall"])])
    table(["Held-out scenario", "Selected without it", "Recall (unseen)", "False-positive rate (unseen)",
           "Recall (seen)", "False-positive rate (seen)", "Recall (production rule)"], drows)

    print("Reading the results: all attacks are synthetic, so these are properties of the detector on simulated "
          "behaviour. Section B is the fair comparison with CERT r4.2, where malicious user-days are about 0.3%.")
    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"\n(Results also written to {args.json})")


if __name__ == "__main__":
    main()
