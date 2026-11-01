# Figures for Chapter 5

PNG, 200 dpi. Built by `make_figures.py` (run from the repository root; needs matplotlib, which is not part of
the application). Every number is read from the recorded outputs listed under "Source", except figure 4 (see its
note). Nothing was estimated or filled in.

| File | Caption (with test-set size) | What you can say | Source |
|---|---|---|---|
| `01_model_comparison.png` | Four unsupervised detectors in their tuned configurations, at the production operating point (threshold at a percentile of the training scores). Test set: 495 sessions, 227 attacks or unusual sessions and 268 normal. F1 with 95% bootstrap intervals, AUC-ROC, false-positive rate and scoring time per session. | "All four models separate the simulated attacks almost perfectly; Isolation Forest was chosen because it gives exact per-feature SHAP explanations and scores a session in a fraction of a millisecond, not because it won every metric." | `docs/evaluation/2026-10-31-timezone-fix/after/04_model_experiments.md`, section C |
| `02_threshold_strategies.png` | Static (95th percentile for everyone), role-tiered (high 90th, standard 95th, low 97th) and per-user adaptive thresholds for the tuned Isolation Forest. Test set: 495 sessions. High-tier recall is 100% under both static and tiered thresholds. | "Role-tiered thresholds trade a small rise in false alarms (0.7% to 1.5%) for a stricter watch on privileged roles; it is a risk-appetite policy, not a free accuracy gain." | same file, "Threshold strategies" and "Role tiers" |
| `03_cold_start.png` | New users with 0 or 3 earlier sessions (20 normal and 20 attack episodes per history length), next to established users on the 495-session test set. | "New users are never flagged by mistake in this test, and with no history at all the model still catches 70% of attacks from raw behaviour alone; after three sessions it caught all of them." | same file, "Cold start"; established users from section C |
| `04_cert_results.png` | CERT r4.2 notebook, Isolation Forest pipelines v1–v3, F1 and AUC-ROC, with the proposal's F1 target of 0.60. v3 is user-level (about 1000 users, about 7% insiders), 70:30 stratified split. Ranges are shown where a range was recorded. | "On the public CERT benchmark the target F1 of 0.60 was not met: with only about 7% insiders, catching most of them pulls precision down, although the ranking quality (AUC 0.77) is reasonable." | project handoff, section 12.1 (see note) |
| `05_live_rules_timeline.png` | Live rules during a recorded demo run on the running system (31 Oct 2026): for each demo account, every request in its session, and the request on which each rule R1–R5 first fired. | "Each live rule fires on the exact request that shows the warning sign; the model's provisional check waits for its warm-up of ten actions." | `data/05_live_rules_run.json` (see note) |

## Notes

**Figure 1.** AUC-ROC is 1.00 for every model when rounded to two decimals (all 95% intervals between 0.99 and
1.00), so that panel shows that the simulated attacks are almost perfectly separable rather than a difference
between models. In this run LOF and the autoencoder had lower false-positive rates (0.4% and 0.0%) than Isolation
Forest (0.7%), and Isolation Forest was the slowest to score (0.041 ms, still negligible). The attacks come from
the system's own simulator, so these are not accuracy figures against real attackers.

**Figure 2.** The role tiers in the benchmark are assumed (one in four users "high", one in four "low"). Recall
and false-positive rate per tier were recorded for static and tiered thresholds only. **Per-tier recall for the
per-user strategy is not in the output**, so the figure says "not reported" there instead of showing a number.

**Figure 3.** 20 episodes per group is a small sample: 70% is 14 of 20 attacks. Below 5 earlier sessions the
personal z-scores are neutral (0) by design, so the decision rests on raw behaviour.

**Figure 4: what is missing.** The requested comparison of CERT **default vs tuned Isolation Forest vs the
heuristic rule** comes from pipeline v4 in `Isolation_Forest_Final_leakage_fixed (1).ipynb` (cells 45–46 build
`res4` with "IsolationForest (default)", "IsolationForest (tuned)", "Heuristic (device/off-hours z)" and "Baseline:
flag everyone"). **That notebook was saved without outputs and no `isolation_forest_results.json` exists
locally, so those numbers are not available and are not shown.** The figure instead shows the pipelines whose
results were recorded in the project handoff (section 12.1, transcribed from earlier notebook runs): v1 F1 about
0.02, AUC 0.71; v2 F1 0.02–0.04, AUC 0.82–0.85; v3 F1 0.24–0.28, AUC 0.77. To add v4: run the notebook in Colab,
download `isolation_forest_results.json` (cell 53), place it in `figures/data/`, and extend `make_figures.py`.

**Caution on v2.** The notebook itself states that v2's figures were measured before a leakage fix (each user's
baseline used their full history, including test days) and must not be quoted. Caption v2 as superseded, or leave
it out. v1 and v3 are essentially unaffected by that fix. The decision was later made not to rerun CERT: it
evaluates the method, not the deployed model, and `docs/evaluation/2026-10-31-realistic-benchmark/` compares the
two at CERT's attack rarity.

**Figure 5.** The run was scripted through the real HTTP API, so all five rules fired within about two seconds
of each other (12:42:44–12:42:46 UTC). The x-axis is therefore the request number in each account's session, not
clock time. The request on which a rule first fired is derived from the recorded data: R1 fired on the 3rd
refused request (3 refused, 1 hit); R3 on live_night's only request; R4 and R2 keep counting on every later
request, so first fire = total requests (11) − hits + 1 (R4: 11 − 9 + 1 = 3, the first deletion; R2: 11 − 5 + 1 =
7, the fifth deletion); R5 was scored once, at its warm-up of 10 actions (provisional score 0.606 against the
standard-tier threshold 0.518). This is a separate run from the one in `docs/evaluation/2026-10-31-live-detection/`
(there the provisional score was 0.604); both fired all five rules.

## Data

| File | Contents |
|---|---|
| `data/05_live_rules_run.json` | Per demo account: allowed requests (time, endpoint), refused requests, live alerts (rule, first and last seen, hit count, summary) and the provisional score, exported from the database before the run's data was deleted |
| `make_figures.py` | Rebuilds all five PNGs from the files above |
