# Evaluation results

Each folder is one evaluation run with its raw outputs, a written summary and image files for the report.

| Folder | What it measures | Start with |
|---|---|---|
| `2026-10-31-timezone-fix/` | Reading clock hours in Nairobi time instead of UTC: effect on real logins, and detection quality before vs after | `summary.md`, `figures/` |
| `2026-10-31-live-detection/` | Live (mid-session) detection: each rule triggered on the running system, provisional vs final score | `results.md`, `screenshots/` |
| `2026-10-31-pipeline-fixes/` | Training-set rule (threshold drift over weekly retrains), familiar addresses, stale-session duration | `summary.md`, `figures/` |

`2026-10-31-timezone-fix/results.html` shows every table in one page (open it in a browser).

## Figures

| File | Use for |
|---|---|
| `2026-10-31-timezone-fix/figures/01_real_logins_utc_vs_local.png` | The problem and its size: 27% of real logins misread under UTC |
| `2026-10-31-timezone-fix/figures/02_login_hours_utc_vs_local.png` | Hour distribution of real logins, UTC vs EAT |
| `2026-10-31-timezone-fix/figures/03_detection_before_after.png` | Recall, false-positive rate, F1, AUC before vs after |
| `2026-10-31-timezone-fix/figures/04_scenarios_before_after.png` | Detection per attack scenario |
| `2026-10-31-timezone-fix/figures/05_training_guardrails_before_after.png` | Thresholds per risk tier and the four retraining guardrails |
| `2026-10-31-timezone-fix/figures/06_model_benchmark_before_after.png` | Isolation Forest vs One-Class SVM, LOF, autoencoder |
| `2026-10-31-timezone-fix/figures/07_verify_feedback_after.png` | Feedback-loop verification, 31/31 |
| `2026-10-31-live-detection/screenshots/01_in_progress_panel.png` | All five live rules in the administrator's panel |
| `2026-10-31-live-detection/screenshots/02_alerts_page.png` | Alerts page with the live panel |
| `2026-10-31-live-detection/screenshots/03_sessions_live_badges.png` | Active sessions with live alert badges |
| `2026-10-31-live-detection/screenshots/04_alert_detail_provisional_vs_final.png` | Provisional vs official score after termination |
| `2026-10-31-live-detection/screenshots/05_live_rules_summary.png` | Table of what each rule caught |
| `2026-10-31-pipeline-fixes/figures/01_retrain_stability.png` | Threshold and false alarms over 8 weekly retrains, previous vs current training rule |

The live demo script for the presentation is in `docs/LIVE_DETECTION_DEMO.md`.
