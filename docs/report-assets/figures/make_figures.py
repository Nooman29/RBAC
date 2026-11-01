"""
Builds the Chapter 5 figures from the recorded evaluation outputs (nothing is typed in by hand except the CERT
values, which are transcribed from the project handoff, section 12.1, because the notebook was saved without
outputs). Run from the repository root:

    python docs/report-assets/figures/make_figures.py

Needs matplotlib (not part of the application). Writes PNGs at 200 dpi next to this file.
"""
import json
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
EXPERIMENTS = ROOT / "docs/evaluation/2026-10-31-timezone-fix/after/04_model_experiments.md"
LIVE_RUN = OUT / "data/05_live_rules_run.json"

DPI = 200
BLUE, GREY, RED, GREEN, AMBER = "#2563eb", "#9ca3af", "#dc2626", "#16a34a", "#d97706"
plt.rcParams.update({"font.size": 11, "axes.titlesize": 12, "axes.titleweight": "bold",
                     "axes.spines.top": False, "axes.spines.right": False})


# ---------------------------------------------------------------- parsing helpers

def section(text, heading):
    """Text from a heading line up to the next heading of the same or higher level."""
    start = text.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    rest = text[start + len(heading):]
    m = re.search(r"\n#{1,%d} " % level, rest)
    return rest[: m.start()] if m else rest


def first_table(text):
    rows = []
    for line in text.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not all(re.fullmatch(r"-+", c) for c in cells):
                rows.append(cells)
        elif rows:
            break
    header, body = rows[0], rows[1:]
    return [dict(zip(header, r)) for r in body]


def num(cell):
    """'99.1%' -> 99.1, '0.99 (0.98-1.00)' -> 0.99, '1.00 (1.00-1.00)' -> 1.0"""
    return float(re.match(r"-?[\d.]+", cell).group())


def ci(cell):
    m = re.search(r"\(([\d.]+)-([\d.]+)\)", cell)
    return (float(m.group(1)), float(m.group(2))) if m else None


def bar_labels(ax, bars, fmt):
    for b in bars:
        ax.annotate(fmt(b.get_height()), (b.get_x() + b.get_width() / 2, b.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9)


def save(fig, name):
    fig.tight_layout()
    fig.savefig(OUT / name, dpi=DPI, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", name)


exp = EXPERIMENTS.read_text(encoding="utf-8")

# ---------------------------------------------------------------- 1. model comparison (tuned, test set)

tuned = first_table(section(exp, "### C. Tuned configurations (test set)"))
SHORT = {"Isolation Forest": "Isolation\nForest", "One-Class SVM": "One-Class\nSVM",
         "Local Outlier Factor": "LOF", "Autoencoder (MLP)": "Auto-\nencoder"}
names = [SHORT[r["Model"]] for r in tuned]
colors = [BLUE if r["Model"] == "Isolation Forest" else GREY for r in tuned]
f1 = [num(r["F1 (95% CI)"]) for r in tuned]
f1_err = [[v - ci(r["F1 (95% CI)"])[0] for v, r in zip(f1, tuned)], [ci(r["F1 (95% CI)"])[1] - v for v, r in zip(f1, tuned)]]
auc = [num(r["AUC-ROC (95% CI)"]) for r in tuned]
fpr = [num(r["False-positive rate"]) for r in tuned]
ms = [num(r["ms per session"]) for r in tuned]

fig, axes = plt.subplots(1, 4, figsize=(16, 4.6))
ax = axes[0]
b = ax.bar(names, f1, color=colors, yerr=f1_err, capsize=4)
ax.set_ylim(0.9, 1.02); ax.set_title("F1 (95% CI)")
for bar, v, r in zip(b, f1, tuned):   # label above the confidence interval, not on it
    ax.annotate(f"{v:.2f}", (bar.get_x() + bar.get_width() / 2, ci(r["F1 (95% CI)"])[1]), xytext=(0, 3),
                textcoords="offset points", ha="center", va="bottom", fontsize=9)
ax = axes[1]
b = ax.bar(names, auc, color=colors)
ax.set_ylim(0.9, 1.02); ax.set_title("AUC-ROC (rounded to 2 dp)"); bar_labels(ax, b, lambda v: f"{v:.2f}")
ax = axes[2]
b = ax.bar(names, fpr, color=colors)
ax.set_title("False-positive rate (%)"); ax.set_ylim(0, max(fpr) * 1.35 + 0.5); bar_labels(ax, b, lambda v: f"{v:.1f}%")
ax = axes[3]
b = ax.bar(names, ms, color=colors)
ax.set_title("Scoring time (ms per session)"); ax.set_ylim(0, max(ms) * 1.3); bar_labels(ax, b, lambda v: f"{v:.3f}")
for ax in axes:
    ax.tick_params(axis="x", labelsize=9.5)
fig.suptitle("Model comparison, tuned configurations, test set (495 sessions: 227 attacks or unusual, 268 normal)\n"
             "Isolation Forest highlighted; LOF = Local Outlier Factor", fontweight="bold")
save(fig, "01_model_comparison.png")

# ---------------------------------------------------------------- 2. threshold strategies

thr_text = section(exp, "### Threshold strategies (test set, tuned Isolation Forest)")
strategies = first_table(thr_text)
tiers = first_table(thr_text[thr_text.index("Role tiers"):])
labels = ["Static\n(95th for all)", "Role-tiered\n(90th / 95th / 97th)", "Per-user\nadaptive"]
s_f1 = [num(r["F1"]) for r in strategies]
s_fpr = [num(r["False-positive rate"]) for r in strategies]
high = next(r for r in tiers if r["Tier"] == "high")
high_recall = [num(high["Recall (static)"]), num(high["Recall (tiered)"]), None]

fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
ax = axes[0]
b = ax.bar(labels, s_f1, color=[GREY, BLUE, GREY]); ax.set_ylim(0.9, 1.02); ax.set_title("F1")
bar_labels(ax, b, lambda v: f"{v:.2f}")
for i, rec in enumerate(high_recall):
    text = f"high-tier\nrecall {rec:.0f}%" if rec is not None else "high-tier recall\nnot reported"
    ax.text(i, 0.912, text, ha="center", fontsize=9, color="white" if rec is not None else "black",
            fontweight="bold" if rec is not None else "normal")
ax = axes[1]
b = ax.bar(labels, s_fpr, color=[GREY, BLUE, GREY]); ax.set_ylim(0, max(s_fpr) * 1.4); ax.set_title("False-positive rate (%)")
bar_labels(ax, b, lambda v: f"{v:.1f}%")
fig.suptitle("Threshold strategies, tuned Isolation Forest (test set, 495 sessions)", fontweight="bold")
save(fig, "02_threshold_strategies.png")

# ---------------------------------------------------------------- 3. cold start

cold = first_table(section(exp, "### Cold start"))
est = next(r for r in tuned if r["Model"] == "Isolation Forest")
groups = [f"{r['Earlier sessions']} earlier\nsessions" for r in cold] + ["Established users\n(test set)"]
fa = [num(r["False-positive rate"]) for r in cold] + [num(est["False-positive rate"])]
caught = [num(r["Attacks caught"]) for r in cold] + [num(est["Recall"])]
x = range(len(groups))
w = 0.38
fig, ax = plt.subplots(figsize=(9.5, 4.8))
b1 = ax.bar([i - w / 2 for i in x], fa, w, color=RED, label="False alarms (% of normal sessions)")
b2 = ax.bar([i + w / 2 for i in x], caught, w, color=GREEN, label="Attacks caught (%)")
bar_labels(ax, b1, lambda v: f"{v:.1f}%"); bar_labels(ax, b2, lambda v: f"{v:.1f}%")
ax.set_xticks(list(x)); ax.set_xticklabels(groups); ax.set_ylim(0, 135); ax.set_ylabel("%")
ax.axvline(1.5, color="#d1d5db", linestyle="--")
ax.text(0.5, 108, "Learning period:\npersonal z-scores neutral (< 5 sessions)", ha="center", fontsize=9)
ax.legend(loc="upper right", fontsize=9, ncol=2)
ax.set_title("Cold start: new users, tuned Isolation Forest\n(20 normal and 20 attack episodes per history length; "
             "established users: 495-session test set)")
save(fig, "03_cold_start.png")

# ---------------------------------------------------------------- 4. CERT (transcribed from the handoff, section 12.1)

# (pipeline, F1 low, F1 high, AUC low, AUC high); "about 0.02" is shown as 0.02.
CERT = [("v1: user-day,\nwindow labels", 0.02, 0.02, 0.71, 0.71),
        ("v2: user-day,\nexact events", 0.02, 0.04, 0.82, 0.85),
        ("v3 (final):\nuser-level", 0.24, 0.28, 0.77, 0.77)]
fig, ax = plt.subplots(figsize=(10, 4.8))
x = range(len(CERT))
for i, (name, f_lo, f_hi, a_lo, a_hi) in enumerate(CERT):
    ax.bar(i - w / 2, f_hi, w, color=BLUE, label="F1" if i == 0 else None)
    ax.bar(i + w / 2, a_hi, w, color=GREY, label="AUC-ROC" if i == 0 else None)
    if f_hi > f_lo:
        ax.vlines(i - w / 2, f_lo, f_hi, color="black"); ax.hlines([f_lo, f_hi], i - w / 2 - 0.05, i - w / 2 + 0.05, color="black")
    if a_hi > a_lo:
        ax.vlines(i + w / 2, a_lo, a_hi, color="black"); ax.hlines([a_lo, a_hi], i + w / 2 - 0.05, i + w / 2 + 0.05, color="black")
    ax.text(i - w / 2, f_hi + 0.02, f"{f_lo:.2f}" if f_lo == f_hi else f"{f_lo:.2f}-{f_hi:.2f}", ha="center", fontsize=9)
    ax.text(i + w / 2, a_hi + 0.02, f"{a_lo:.2f}" if a_lo == a_hi else f"{a_lo:.2f}-{a_hi:.2f}", ha="center", fontsize=9)
ax.axhline(0.60, color=RED, linestyle="--", linewidth=1.5, label="Proposal target F1 = 0.60")
ax.set_xticks(list(x)); ax.set_xticklabels([c[0] for c in CERT]); ax.set_ylim(0, 1.0)
ax.legend(loc="upper left", fontsize=9)
ax.set_title("CERT r4.2 notebook: Isolation Forest pipelines (70:30 split; v3 about 1000 users, about 7% insiders)\n"
             "Source: project handoff, section 12.1 (notebook saved without outputs)")
save(fig, "04_cert_results.png")

# ---------------------------------------------------------------- 5. live rules timeline (from the recorded run)

run = json.loads(LIVE_RUN.read_text(encoding="utf-8"))["accounts"]
lanes = []   # (lane label, n actions, [(action index, rule label, colour)], action kinds)

staff = run["live_staff"]
n_refused = len(staff["refused_requests"])
lanes.append(("live_staff\n(Standard User)", n_refused, [(n_refused, "R1 action outside access", AMBER)],
              ["refused"] * n_refused))

night = run["live_night"]
lanes.append(("live_night\n(night-shift history)", len(night["allowed_actions"]),
              [(1, "R3 unusual hour", GREY)], ["read"] * len(night["allowed_actions"])))

op = run["live_operator"]
acts = op["allowed_actions"]
n = len(acts)
kinds = ["delete" if a["endpoint"].startswith("DELETE") else "read" for a in acts]
first_hit = {a["rule"]: n - a["hit_count"] + 1 for a in op["live_alerts"]}   # alerts update on every later action
first_hit["model_provisional"] = op["provisional_score"]["n_events"]          # scored once, at the warm-up
op_events = [(first_hit["confirmed_threat_pattern"], "R4 repeat of confirmed threat", RED),
             (first_hit["destructive_burst"], "R2 burst of deletions", RED),
             (first_hit["model_provisional"], f"R5 model {op['provisional_score']['score']:.3f} > "
                                              f"{op['provisional_score']['threshold']:.3f}", BLUE)]
lanes.append(("live_operator\n(read-only history,\nconfirmed write threat)", n, op_events, kinds))

fig, ax = plt.subplots(figsize=(13, 4.8))
marker = {"read": ("o", "#6b7280"), "delete": ("s", RED), "refused": ("X", AMBER)}
for y, (label, count, events, kinds_) in enumerate(reversed(lanes)):
    for i, k in enumerate(kinds_, start=1):
        m, c = marker[k]
        ax.scatter(i, y, marker=m, color=c, s=55, zorder=3)
    for j, (idx, text, colour) in enumerate(events):
        ax.annotate(text, (idx, y), xytext=(idx + 0.15, y + 0.28 + 0.0 * j), fontsize=9, color=colour,
                    fontweight="bold", arrowprops=dict(arrowstyle="-", color=colour), zorder=4)
        ax.scatter(idx, y, s=260, facecolors="none", edgecolors=colour, linewidths=2, zorder=4)
ax.set_yticks(range(len(lanes))); ax.set_yticklabels([l[0] for l in reversed(lanes)], fontsize=9)
ax.set_xticks(range(1, 12)); ax.set_xlim(0.5, 13.5); ax.set_ylim(-0.6, len(lanes) - 0.1)
ax.set_xlabel("Request number within the account's session")
for k, (m, c) in marker.items():
    ax.scatter([], [], marker=m, color=c, label={"read": "allowed request", "delete": "user deletion",
                                                 "refused": "refused request (403)"}[k])
ax.legend(loc="upper right", fontsize=9)
ax.set_title("Live rules during the recorded demo run (31 Oct 2026): the request on which each rule first fired")
save(fig, "05_live_rules_timeline.png")
