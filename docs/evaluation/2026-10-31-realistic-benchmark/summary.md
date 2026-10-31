# A realistic evaluation of the anomaly detector

Date: 31 October 2026. Why: the headline benchmark (`scripts/model_experiments.py`) reports F1 0.99, while the
same method reached F1 0.24-0.28 on the CERT r4.2 insider-threat dataset. This evaluation explains the gap and
gives numbers that can be compared honestly. No application code was changed; the model is the production one
(`MODEL_PARAMS`: 200 trees, `max_samples` 1.0; threshold at the 95th percentile of the training scores).

| File | What it is |
|---|---|
| `01_realistic_evaluation.md` / `.json` | `scripts/evaluate_realistic.py`: synthetic benchmark, sections A-D below (seed 42) |
| `02_real_sessions.md` | `scripts/evaluate_real_sessions.py`: false alarms on real use of the system (read only) |
| `figures/01_prevalence.png` | F1 and PR-AUC as attacks become rarer |
| `figures/02_attack_strength.png` | How much an insider inside their routine must change before being caught; single traits |
| `figures/03_real_vs_synthetic_false_alarms.png` | False alarms on synthetic vs real sessions, and what caused them |

## Findings

### 1. Why 0.99: an easy, balanced test set

The headline test set is 47% attacks, and 94% of those come from the three simulator scenarios, which combine
several signals the model measures (a 2 AM login with 40 actions; an unfamiliar address with wide browsing; a
burst of deletions). They are caught 100% of the time, whether or not tuning ever saw them (section D: leaving a
scenario out of tuning changes nothing). Confidence intervals that resample users rather than sessions are no
wider (F1 0.97-0.99), so the result is stable; it is the task that is easy.

### 2. F1 depends on how rare attacks are (figure 1)

Recall and the false-positive rate (0.4%: 3 of 735 ordinary sessions, 95% interval 0.1-1.2%) do not depend on
how common attacks are; precision and F1 do.

| Attack kind (recall) | F1 at 20% attacks | 5% | 1% | 0.3% (CERT user-days) |
|---|---|---|---|---|
| Simulator scenarios (100%) | 0.99 | 0.96 | 0.83 | 0.60 |
| Insider inside their routine, 2x activity (65%) | 0.78 | 0.75 | 0.63 | 0.43 |
| Generic unusual sessions (50%, only 14 test sessions) | 0.66 | 0.63 | 0.53 | 0.35 |

Worst-case values (low end of recall, high end of the false-positive rate) are in `01_realistic_evaluation.md`;
at 0.3% they fall to 0.10-0.34. At CERT's rarity the same detector scores F1 0.35-0.60 on synthetic attacks,
the same region as the 0.24-0.28 measured on CERT. The two results are consistent: the gap is mostly how rare and
how subtle the attacks are, not a broken model.

### 3. What an insider can get away with (figure 2)

For a user who keeps their routine (usual hours, a known address, a weekday):

- Doing more is caught only when it is a lot more: 2x the usual volume is caught 1% of the time, 4x 65%, 6x 89%.
- A destructive mix is caught much sooner (42% at 2x, 86% at 3x); all three changes together 65% at 2x, 100% at 3x.
- One unusual trait on its own is mostly missed: an unfamiliar address 3%, a weekend login 1%, using all
  resources 0%, a night login 19%. Only a large volume jump (3-6x) is reliably caught (85%).

Isolation Forest isolates unusual combinations; one changed signal inside an otherwise normal session rarely
crosses the threshold. This is why the live rules exist: R1 (refused requests), R2 (destructive burst), R3
(unusual hour) and R4 (repeat of a confirmed pattern) each react to a single signal immediately.

### 4. False alarms on real use are far higher than on synthetic data (figure 3)

A model trained exactly as production does on everything before 8 October 2026 flagged **10 of the next 50 real
sessions (20%, 95% interval 11-33%)**, against 0.4% of synthetic normal sessions. The live models, as recorded,
flagged 10 of 151 real sessions (6.6%), none reviewed yet. SHAP shows why: weekend work was the strongest push in
5 of the 10 and among the top three in 8; high action counts in 6. The synthetic users the model mostly learned
from (311 of its 428 training sessions) almost never work weekends and do 3-9 actions per session; real use of
this system (building, testing and demonstrating it) is long, busy and often at weekends. 4 of the 10 flagged
sessions also carry the made-up 1800 s duration of a stale-closed session, fixed since by the pipeline fixes.

The sample is small (50 sessions, mostly the developer's own) and not a school's daily use, so the 20% is
indicative, not a deployment figure. The direction is clear: synthetic training data does not represent real
behaviour, and in deployment the model would need real usage history before its thresholds mean what they say.

## What to say in Chapter 5

- Quote F1 0.99 only together with its test set: 47% attacks, mostly from the system's own simulator.
- The comparable figure for CERT is the 0.3% row: F1 0.35-0.60 on synthetic attacks vs 0.24-0.28 on CERT.
- The model catches combinations and large changes, not single subtle signals; the live rules cover those.
- On real use the false-alarm rate was about 20% because the training data was mostly synthetic. Retraining on
  real history (weekly, with guardrails) is how the system is meant to correct this, and administrator
  verdicts on these alerts feed that loop.

## Method notes

- Leakage-safe as in the headline benchmark: chronological 60/20/20 split per user, point-in-time baselines,
  scaler and model fitted on training rows only; tuning (section D only) on validation rows only.
- Evaluation-only sessions (strength sweep, single traits, extra ordinary sessions) are tagged so they never enter
  a baseline or the training set; they change nothing else in the benchmark.
- Recall intervals resample users (1000 resamples); the false-positive rate uses a Wilson interval, which stays
  honest when few or no false alarms are seen.
- `evaluate_real_sessions.py` writes nothing: no alerts, no model versions. Accounts are shown as User A, B, ...
