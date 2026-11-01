# Report assets

Material for the final report (Chapter 5) and a backup for the live demo, produced on 31 October 2026 from the
running system and the recorded evaluation outputs. Documentation only: no application code was changed.

| Part | Folder or file | Index |
|---|---|---|
| A. Figures for Chapter 5 | `figures/` | `figures/README.md`: caption, test-set size, a sentence to say, and the source of every number |
| B. Key code segments | `code_segments.md` | below |
| C. Full system screenshots | `screenshots/` | `screenshots/README.md`: what each screen shows and a sentence to say |

## A. Figures (`figures/`)

`01_model_comparison.png`, `02_threshold_strategies.png`, `03_cold_start.png`, `04_cert_results.png`,
`05_live_rules_timeline.png`, plus `make_figures.py` (rebuilds them) and `data/05_live_rules_run.json` (the live
run behind figure 5). One gap is stated rather than filled: the CERT default vs tuned vs heuristic comparison
(notebook pipeline v4) has no recorded numbers, so figure 4 shows the recorded pipelines v1–v3 instead. See the
figures README for how to add v4.

## B. Code segments (`code_segments.md`)

Five excerpts copied verbatim from the repository (checked line by line against the source), each with its file,
line numbers and a short explanation.

| # | Segment | What you can say |
|---|---|---|
| 1 | Point-in-time comparison features (`feature_engineering.py`) | "Each session is compared only with the same user's earlier sessions, needs five of them before personal comparisons count, and every z-score is clipped at plus or minus ten." |
| 2 | Training and per-tier thresholds (`model_registry_service.py`) | "The model trains on normal sessions only, and each risk tier gets its own threshold as a percentile of the training scores: 90th, 95th or 97th." |
| 3 | Scoring a session (`anomaly_service.py`) | "At the end of a session the user's tier picks the threshold, the score decides the flag, and the SHAP explanation is stored with the alert." |
| 4 | Live provisional scoring R5 (`live_detection_service.py`) | "While a session is running, the same model scores it after a warm-up of ten actions or five minutes, at most once a minute." |
| 5 | A retraining guardrail (`model_registry_service.py`) | "A retrained model only goes live if it raises few false alarms on recent sessions and catches known attacks at least as well as the live model." |

## C. Screenshots (`screenshots/`)

31 screens in demo order, 1440 x 900, numbered `01_` to `31_`: sign-in (password, Face ID or email code), the
dashboard for an Administrator and a department-scoped Manager, a Teacher's view, users, roles (grant, revoke,
delete), Compare Roles, My Access, a refused page (R1), sessions, the live In progress panel, alerts, the audit log
with change details, detection outcomes, the Detection Model page (versions, guardrails, drift), Simulate Attack,
Integrations, the attendance module allowed and denied, the module's calls as recorded centrally, and an alert's
provisional vs final score with its SHAP explanation.

## How they were produced

- **Figures:** `figures/make_figures.py` reads `docs/evaluation/2026-10-31-timezone-fix/after/04_model_experiments.md`
  and `figures/data/05_live_rules_run.json`; CERT values are transcribed from the project handoff, section 12.1.
- **Screenshots:** Playwright with the local Chrome, against the running system. Demo data came from
  `backend/scripts/setup_live_demo.py` (`live_` accounts), plus a temporary Manager and two temporary roles; sign-in
  used the real password step and test session tokens from a backend script (details in the screenshots README).
  Afterwards every account, role, session and row the run created was deleted; real accounts and `synth_` users
  were not touched. The helper scripts lived outside the repository.
