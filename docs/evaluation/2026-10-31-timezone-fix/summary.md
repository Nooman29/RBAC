# Local business time for detection features: before vs after

Date: 31 October 2026. Change: clock hours and weekdays in the detection features are read in
`settings.BUSINESS_TIMEZONE` (Africa/Nairobi, EAT, UTC+3) instead of UTC. Timestamps are still stored in UTC.

## The problem

Sessions are stored with `datetime.utcnow()`. The features `login_hour`, `is_offhours` (before 07:00 or after
19:00) and `is_weekend` were read straight from that UTC value, while the synthetic training data wrote intended
local hours (e.g. 9) directly as UTC. So the model learned "09:00 UTC is normal", and a Nairobi user who started
work at 08:00 EAT (05:00 UTC) was treated as an off-hours login, while evening work at 21:00 EAT (18:00 UTC)
looked like the afternoon.

## What changed

- `app/core/business_time.py`: `to_local` / `to_utc` helpers; `BUSINESS_TIMEZONE` setting (default Africa/Nairobi).
- Feature engineering reads `login_hour`, `is_offhours` and `is_weekend` in local time.
- Live rule R3 (unusual hour) compares local hours and reports them as EAT.
- The attack simulator and the synthetic seed data treat their hours as local time and store UTC.
- The dashboard's "alerts today" and daily charts use local calendar days.
- Evaluation and verification scripts place their test sessions in local time.

## Method

1. **Before:** freshly seeded synthetic data (seed 42, 8 users, 421 sessions) plus the existing real history
   (166 sessions); model trained and evaluated with the old (UTC) code.
2. **After:** the same synthetic data regenerated with the same seed (now stored as local-time-to-UTC), model
   retrained and evaluated with the new code.
3. Real logins scored both ways with `scripts/evaluate_timezone_effect.py`.

Raw outputs: `before/` and `after/`. Figures: `figures/`. All tables in one page: `results.html`.

## Results

### Real logins (where the fix matters) - `figures/01_real_logins_utc_vs_local.png`, `02_login_hours_utc_vs_local.png`

| Measure | Before (UTC hours) | After (local hours) |
|---|---|---|
| Logins counted as off-hours | 9.7% (16/165) | 20.0% (33/165) |
| Logins counted as weekend | 18.2% (30/165) | 18.2% (30/165) |
| Sessions flagged by the model | 10.9% (18/165) | 12.1% (20/165) |

UTC misread the off-hours flag for **27.3% (45/165)** of real sessions, in both directions: 14 early-morning
business-hours logins were called off-hours, and 31 evening logins (19:00-22:00 EAT, much of it development and
testing work) were called business hours. The higher off-hours share after the fix is the correct reading of
when these sessions actually happened.

### Detection quality (no regression) - `figures/03` to `06`

| Measure (full pipeline) | Before | After |
|---|---|---|
| Attacks caught (recall), 120 simulated attacks | 99.2% (95% CI 95-100%) | 99.2% (95% CI 95-100%) |
| Normal sessions wrongly flagged, 120 sessions | 2.5% (95% CI 1-7%) | 2.5% (95% CI 1-7%) |
| F1 at this test mix | 0.98 | 0.98 |
| AUC-ROC | 1.00 | 1.00 |
| Retraining guardrails passed | 4 of 4 | 4 of 4 |
| Recent false-alarm check (guardrail) | 4.3% | 3.5% |
| Isolated benchmark, Isolation Forest F1 / FPR | 0.99 / 0.7% | 0.99 / 0.7% |

The detection numbers are unchanged because the synthetic and simulated data were always internally consistent
(both written and read in the same clock). The fix changes how **real** logins are read, which the simulated
benchmarks cannot measure; that is what the real-login table shows.

`scripts/verify_feedback.py`: 31 of 31 checks pass after the change (`figures/07_verify_feedback_after.png`).
Test suite: 169 tests pass.

## Notes for the write-up

- Before = committed `main` code for the isolated benchmark; the detection evaluation "before" ran the same
  code with UTC features on the same data.
- The "known attacks caught" guardrail (60.9% before and after) uses the 23 simulated attack sessions already in
  the database, created before the change; they were not regenerated.
- Kenya has no daylight saving time, so the conversion is a fixed +3 hours, but the code uses the IANA zone so
  another deployment only changes the setting (then retrains).

## Reproduce

```powershell
docker compose exec backend python -m scripts.seed_synthetic_data --remove-synthetic-users --yes
docker compose exec backend python -m scripts.seed_synthetic_data --reset-synthetic --yes --create-users 8 --synthetic-users-only --seed 42
docker compose exec backend python -m scripts.train_isolation_forest
docker compose restart backend
docker compose exec backend python -m scripts.evaluate_detection --users 12 --runs 4 --seed 7
docker compose exec backend python -m scripts.model_experiments --seed 42
docker compose exec backend python -m scripts.evaluate_timezone_effect --before <utc version> --after <local version>
docker compose exec backend python -m scripts.verify_feedback
```

Always pass `--synthetic-users-only` with `--reset-synthetic`: without it the seed script also adds synthetic
history to every real account with fewer than 40 sessions.
