# Live (mid-session) detection: results on the running system

Date: Saturday 31 October 2026, 13:13 EAT. Model version `20261031-100622` (local-time features).
Accounts: the `live_` demo accounts from `scripts/setup_live_demo.py`, each with its own prepared history.
Every action below was a real HTTP request to the running backend; nothing was injected into the database
during the run.

## Each rule, triggered on purpose

| Rule | Account | What the account did | Live alert raised | Severity |
|---|---|---|---|---|
| R1 Action outside the user's access | live_staff (Standard User) | Requested `/api/users/` three times (403 each) | 3 refused requests in 10 min | medium |
| R3 Unusual hour for this user | live_night (night-shift history, 22:00-01:00) | Opened the dashboard at 13:00 | Active at 13:00 EAT, outside this user's usual hours | low |
| R4 Repeat of a confirmed threat pattern | live_operator (confirmed threat: "many writes") | First user deletion (a write) | Repeats a pattern confirmed as a threat: highwrite | high |
| R2 Burst of deletions/exports | live_operator | Deleted the 5 live_victim accounts in under a minute | 5 deletion(s) and 0 export(s) in 2 min (limit 5, standard tier) | high |
| R5 Model (provisional) | live_operator | 10 actions after the warm-up | Model score 0.604 above the standard-tier threshold 0.518 (provisional) | high |

All five appeared in the administrator's **In progress** panel within the 10-second refresh
(`screenshots/01_in_progress_panel.png`), each with **Terminate** and **Dismiss**.

## Provisional score vs the official verdict

| | Score | Threshold | Flagged |
|---|---|---|---|
| Provisional (live, after 10 actions) | 0.604 | 0.518 (standard tier) | yes |
| Same session with `is_weekend = 0` (weekday check) | 0.558 | 0.518 | yes |
| Final, at termination (official verdict) | 0.610 | 0.518 | yes (ML model) |

Terminating the session marked its three live alerts as `terminated`, rejected the user's token on the next
request, and scored the session as usual. The alert page shows the provisional and final scores together
(`screenshots/04_alert_detail_provisional_vs_final.png`).

Top SHAP factors for the provisional score: write volume vs usual (z = 10, clipped), access volume vs usual
(z = 7.9) and weekend login. The run fell on a Saturday; on a weekday the same session still scores above the
threshold, with a smaller margin (0.558).

## Screenshots

| File | Shows |
|---|---|
| `screenshots/01_in_progress_panel.png` | The In progress panel with all five live alerts |
| `screenshots/02_alerts_page.png` | Full Alerts page: live panel above the scored sessions |
| `screenshots/03_sessions_live_badges.png` | Active sessions with "Live alert" badges |
| `screenshots/04_alert_detail_provisional_vs_final.png` | Alert detail after termination: provisional vs final score, live alerts, SHAP |

## Limits to state in the defence

- R1 counts **refused** requests. Ordinary use of the UI cannot produce them, because the menu hides what a role
  cannot open; R1 is aimed at someone going around the UI (typing hidden URLs, replaying a token against the API,
  a module reporting an action the user had no permission for).
- R5 is an early warning on a partial session. It only starts after 10 actions or 5 minutes and runs at most once
  a minute per session; the end-of-session score stays the official verdict.
- The attacks are scripted demonstrations of each rule, not a measured detection rate. Detection rates for the
  model are in `../2026-10-31-timezone-fix/`.
