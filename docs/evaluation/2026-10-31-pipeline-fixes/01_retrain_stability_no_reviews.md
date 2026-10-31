## Retraining stability (in-memory replay, seeds 42, 1, 2, 3, 4)

20 synthetic users, 4 weeks of history, then 8 weekly cycles of 5 sessions per user. Administrators review 0% of each week's flags. Threshold: 95th percentile of the training scores (standard tier).

### Week by week (seed 42)

| Retrain | Rule | Training sessions | Threshold | Guardrail 3 (holdout flag rate) | False alarms on the next week's normal sessions | Next week's unusual sessions caught |
|---|---|---|---|---|---|---|
| 0 | previous | 400 | 0.5211 | 12.5% |  |  |
| 0 | current | 400 | 0.5211 | 12.5% |  |  |
| 1 | previous | 497 | 0.5211 | 0.0% | 0.0% of 94 | 50% of 6 |
| 1 | current | 500 | 0.5204 | 3.0% | 0.0% of 94 | 50% of 6 |
| 2 | previous | 593 | 0.5129 | 2.5% | 2.2% of 91 | 22% of 9 |
| 2 | current | 600 | 0.5123 | 6.7% | 2.2% of 91 | 22% of 9 |
| 3 | previous | 686 | 0.5127 | 0.7% | 2.1% of 95 | 100% of 5 |
| 3 | current | 700 | 0.5110 | 5.7% | 1.1% of 95 | 100% of 5 |
| 4 | previous | 781 | 0.5030 | 0.0% | 0.0% of 94 | 83% of 6 |
| 4 | current | 800 | 0.5112 | 5.0% | 0.0% of 94 | 83% of 6 |
| 5 | previous | 880 | 0.5005 | 0.0% | 0.0% of 98 | 50% of 2 |
| 5 | current | 900 | 0.5079 | 2.2% | 0.0% of 98 | 50% of 2 |
| 6 | previous | 972 | 0.4946 | 0.0% | 2.2% of 92 | 75% of 8 |
| 6 | current | 1000 | 0.5077 | 3.5% | 0.0% of 92 | 75% of 8 |
| 7 | previous | 1064 | 0.4987 | 0.0% | 4.2% of 96 | 100% of 4 |
| 7 | current | 1100 | 0.5093 | 4.1% | 0.0% of 96 | 75% of 4 |
| 8 | previous | 1155 | 0.4935 | 0.0% | 4.2% of 95 | 100% of 5 |
| 8 | current | 1200 | 0.5117 | 4.6% | 0.0% of 95 | 80% of 5 |

### Summary per seed (false alarms and catches pooled over all weeks)

| Seed | Rule | Threshold change (first to last model) | False alarms, all weeks | False alarms, second half | Unusual sessions caught | Guardrail 3, mean | Left out of training at the end |
|---|---|---|---|---|---|---|---|
| 42 | previous | -0.0277 | 1.9% | 2.6% | 69% | 0.4% | 45 of 1200 |
| 42 | current | -0.0094 | 0.4% | 0.0% | 64% | 4.3% | 0 of 1200 |
| 1 | previous | -0.0490 | 3.2% | 5.0% | 81% | 0.1% | 59 of 1200 |
| 1 | current | -0.0200 | 0.8% | 1.6% | 63% | 3.3% | 0 of 1200 |
| 2 | previous | -0.0600 | 0.9% | 1.6% | 57% | 0.5% | 30 of 1200 |
| 2 | current | -0.0413 | 0.5% | 0.8% | 55% | 3.4% | 0 of 1200 |
| 3 | previous | -0.0382 | 3.9% | 5.1% | 74% | 0.2% | 72 of 1200 |
| 3 | current | -0.0021 | 0.8% | 0.8% | 55% | 5.0% | 0 of 1200 |
| 4 | previous | -0.0333 | 3.9% | 4.5% | 82% | 0.2% | 62 of 1200 |
| 4 | current | -0.0145 | 2.2% | 2.1% | 69% | 5.2% | 0 of 1200 |

### Mean over seeds

| Rule | Threshold change | False alarms, all weeks | False alarms, second half | Unusual sessions caught | Guardrail 3, mean |
|---|---|---|---|---|---|
| previous | -0.0416 | 2.8% | 3.8% | 73% | 0.3% |
| current | -0.0175 | 1.0% | 1.1% | 61% | 4.3% |

About 5% false alarms is the design target. Guardrail 3 checks recent sessions from the SAME training set, so under the previous rule it cannot see a drift caused by the filter itself.
