## False alarms on real sessions (read only)

167 real sessions from 10 accounts, 11 Aug 2026 to 31 Oct 2026 (UTC). Synthetic and test accounts are excluded.

### 1. Out of time: trained on the past, tested on later real sessions

Model trained as production does on the 428 sessions before 08 Oct 2026 09:22 UTC (117 real, the rest synthetic), thresholds per risk tier: high p90 = 0.4891, standard p95 = 0.5263, low p97 = 0.5626. Tested on the latest 50 real sessions (08 Oct to 31 Oct 2026).

| Real sessions tested | Confirmed threats among them | Flagged (not confirmed threats) | False-alarm rate (95% Wilson interval) | Confirmed threats flagged |
|---|---|---|---|---|
| 50 | 0 | 10 | 20.0% (11.2%-33.0%) | none |

By risk tier (the high tier uses a lower threshold on purpose):

| Risk tier | Threshold | Sessions | Flagged | Rate |
|---|---|---|---|---|
| standard | p95 | 50 | 10 | 20.0% |

By account:

| Account | Risk tier | Sessions tested | Flagged |
|---|---|---|---|
| User A | standard | 31 | 6 |
| User B | standard | 10 | 2 |
| User C | standard | 7 | 2 |
| User I | standard | 2 | 0 |

4 of the flagged sessions have the made-up 1800 s duration of a session closed as stale before the pipeline fix (it now ends at the last recorded activity).

What pushed the flagged real sessions over the threshold (SHAP, strongest feature first):

| Feature | Strongest push in | Among the top 3 in |
|---|---|---|
| is_weekend | 5 of 10 | 8 of 10 |
| n_access_events | 3 of 10 | 6 of 10 |
| n_read | 0 of 10 | 4 of 10 |
| n_write | 0 of 10 | 2 of 10 |
| new_ip | 2 of 10 | 2 of 10 |
| is_offhours | 0 of 10 | 2 of 10 |
| distinct_resources | 0 of 10 | 2 of 10 |
| distinct_actions | 0 of 10 | 2 of 10 |
| n_access_events_zscore | 0 of 10 | 1 of 10 |
| n_write_zscore | 0 of 10 | 1 of 10 |

### 2. As recorded: what the live models said when each real session ended

| Real sessions | Scored | Flagged | Flag rate | Confirmed threat | False positive | Authorised exception | Unreviewed | Not flagged but later confirmed |
|---|---|---|---|---|---|---|---|---|
| 167 | 151 | 10 | 6.6% | 0 | 0 | 0 | 10 | 0 |

Flagged by: ml_model 10.

Caveats: the real sessions are mostly development and demonstration use of this system by a few people (signing in to build, test and demonstrate it), so they are few and not representative of a school's daily use, and most of the training data is synthetic. Read the rates with the small sample and its wide interval in mind.
