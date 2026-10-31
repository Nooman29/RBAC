# Detection pipeline fixes: training set, familiar addresses, stale-session duration

Date: 31 October 2026. Three leaks found in the code review of the detection pipeline, fixed, and measured.

## What changed

| # | Problem | Fix | Where |
|---|---|---|---|
| 1 | The global model trained only on sessions it had **not** flagged itself (unless an administrator cleared them). The threshold is the 95th percentile of the training scores, so each retrain cut off the top of the distribution and lowered the threshold again. Guardrail 3 (recent false alarms) checks sessions from the same filtered set, so it could not see this. | Train on every closed, real session except simulated attacks and **known** threats (confirmed by an administrator, or flagged for repeating a confirmed threat's pattern and not cleared since). Unreviewed flags stay in; Isolation Forest tolerates a few unusual sessions. Per-user baselines are unchanged and stay strict. | `model_registry_service._training_sessions_query` |
| 2 | `new_ip` treated every earlier address as familiar, including addresses from simulated attacks, confirmed threats and flagged sessions, so an attacker's second visit from the same address looked familiar. | Familiar addresses come only from sessions that count as normal behaviour (the same rule as the z-score baseline and live rule R3, now one shared function). Any earlier session still proves the user has history, so a first-ever login is still never a "new" address. | `feature_engineering.counts_as_normal_behaviour`, `build_raw_session_features` |
| 3 | A session left open (browser closed without signing out) was closed with duration = 1800 s exactly (login + token lifetime). 53 of the 587 closed real sessions in the database have this made-up value, which distorts `session_duration_sec` and its z-score. | The session ends at its last recorded activity (latest access log), never later than the token's expiry; no activity means 0 s. Existing rows are not rewritten. | `session_service.close_stale_sessions` |
| 4 | The `MODEL_PARAMS` comment said the configuration was "selected on validation", but the benchmark's top configuration used 500 trees and the code uses 200. | Comment corrected: `max_samples=1.0` was selected; tree count made almost no difference (validation F1 0.955-0.960 for 100-500), so 200 keeps retraining and SHAP fast. Behaviour unchanged. | `model_registry_service.py` |

The repeat-pattern override (an unreviewed flag makes later sessions with the same indicators flag too) no longer
shrinks the training set, because unreviewed flags now stay in it (fix 1).

## Evidence for fix 1: retraining stability

`scripts/evaluate_retrain_stability.py` replays the production loop in an in-memory database: 20 synthetic users,
4 weeks of history, then 8 weeks in which new sessions arrive, the live model scores them (writing alerts) and the
model is retrained. Identical data is replayed under the previous and the current training rule; 5 random seeds.
Raw output: `01_retrain_stability_no_reviews.md`, `02_retrain_stability_half_reviewed.md`.
Figure: `figures/01_retrain_stability.png`.

| Mean over 5 seeds | Threshold change over 8 retrains | False alarms on new normal sessions, all weeks | Same, second half | Unusual sessions caught | What guardrail 3 reported |
|---|---|---|---|---|---|
| Previous rule, no reviews | -0.042 | 2.8% | **3.8%** | 73% | **0.3%** |
| Current rule, no reviews | -0.018 | 1.0% | 1.1% | 61% | 4.3% |
| Previous rule, half of flags reviewed | -0.036 | 2.2% | 2.9% | 72% | 1.2% |
| Current rule, half of flags reviewed | -0.025 | 1.1% | 1.3% | 66% | 3.3% |

Reading the results:

- Under the previous rule the threshold kept falling and false alarms rose over time (2.8% overall, 3.8% in the
  second half). Under the current rule the false-alarm rate stays flat at about 1%.
- Guardrail 3 reported 0.3% under the previous rule while real false alarms were rising: it was blind to the
  drift. Under the current rule it reports 3-4%, close to the 5% the 95th percentile is designed for.
- **Trade-off, stated plainly:** the previous rule caught more unusual sessions (72-73% vs 61-66%), because its
  threshold drifted lower and the system became more sensitive without anyone deciding it. With the fix the
  operating point is the one configured in the risk tiers (`TIER_PERCENTILES`: high p90, standard p95, low p97).
  If more sensitivity is wanted, it should be a deliberate change of those percentiles, which guardrail 3 can then
  check honestly.
- Approximation: a week's sessions are scored together against the history before that week.

## Effect on the benchmark (fix 2)

`scripts/model_experiments.py` (seed 42) re-run after the change: `03_model_experiments_after.md`. Compared with
`2026-10-31-timezone-fix/after/04_model_experiments.md`, every accuracy figure is identical (F1, precision,
recall, AUC and false-positive rate for all four models, default and tuned, threshold strategies and role tiers);
only timings differ. One cold-start cell changed (users with 3 earlier sessions: 0 of 20 false alarms before, 1 of
20 now). That part of the benchmark picks its test days from the current clock, so a run in the evening draws
different days than the morning run; in that test no user has a simulated or flagged earlier session, so the
`new_ip` change cannot affect it.

## Verification

- pytest: 214 passed (203 before plus 11 in `tests/test_detection_pipeline.py`), also with OpenCV and DeepFace
  blocked as in CI.
- `verify_feedback` 31/31 (feedback loop and per-user baselines unchanged), `verify_audit` 32/32,
  `verify_events` 26/26, `verify_pass2` 52/52, `verify_pass1` 44/44.

## After deploying

Retrain once from the Detection Model page (or `python -m scripts.train_isolation_forest`) so the live model is
trained under the new rule. The 53 existing sessions with the made-up 1800 s duration are left as they are.
