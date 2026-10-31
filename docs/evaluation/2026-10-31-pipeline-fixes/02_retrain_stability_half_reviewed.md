## Retraining stability (in-memory replay, seeds 42, 1, 2, 3, 4)

20 synthetic users, 4 weeks of history, then 8 weekly cycles of 5 sessions per user. Administrators review 50% of each week's flags. Threshold: 95th percentile of the training scores (standard tier).

### Week by week (seed 42)

| Retrain | Rule | Training sessions | Threshold | Guardrail 3 (holdout flag rate) | False alarms on the next week's normal sessions | Next week's unusual sessions caught |
|---|---|---|---|---|---|---|
| 0 | previous | 400 | 0.5211 | 12.5% |  |  |
| 0 | current | 400 | 0.5211 | 12.5% |  |  |
| 1 | previous | 497 | 0.5211 | 0.0% | 0.0% of 94 | 50% of 6 |
| 1 | current | 499 | 0.5219 | 2.0% | 0.0% of 94 | 50% of 6 |
| 2 | previous | 594 | 0.5176 | 3.4% | 2.2% of 91 | 22% of 9 |
| 2 | current | 598 | 0.5180 | 5.8% | 2.2% of 91 | 22% of 9 |
| 3 | previous | 688 | 0.5119 | 1.4% | 2.1% of 95 | 100% of 5 |
| 3 | current | 695 | 0.5121 | 2.9% | 2.1% of 95 | 100% of 5 |
| 4 | previous | 783 | 0.5043 | 0.0% | 0.0% of 94 | 83% of 6 |
| 4 | current | 793 | 0.5089 | 3.8% | 0.0% of 94 | 83% of 6 |
| 5 | previous | 882 | 0.5031 | 0.0% | 0.0% of 98 | 50% of 2 |
| 5 | current | 892 | 0.5065 | 1.7% | 0.0% of 98 | 50% of 2 |
| 6 | previous | 975 | 0.5013 | 0.0% | 2.2% of 92 | 75% of 8 |
| 6 | current | 989 | 0.5019 | 1.5% | 0.0% of 92 | 75% of 8 |
| 7 | previous | 1068 | 0.5005 | 0.5% | 3.1% of 96 | 100% of 4 |
| 7 | current | 1087 | 0.5044 | 2.3% | 0.0% of 96 | 100% of 4 |
| 8 | previous | 1162 | 0.4982 | 0.9% | 3.2% of 95 | 100% of 5 |
| 8 | current | 1184 | 0.4969 | 3.0% | 1.1% of 95 | 100% of 5 |

### Summary per seed (false alarms and catches pooled over all weeks)

| Seed | Rule | Threshold change (first to last model) | False alarms, all weeks | False alarms, second half | Unusual sessions caught | Guardrail 3, mean | Left out of training at the end |
|---|---|---|---|---|---|---|---|
| 42 | previous | -0.0229 | 1.6% | 2.1% | 69% | 0.8% | 38 of 1200 |
| 42 | current | -0.0242 | 0.7% | 0.3% | 69% | 2.9% | 16 of 1200 |
| 1 | previous | -0.0437 | 2.6% | 3.9% | 81% | 1.2% | 46 of 1200 |
| 1 | current | -0.0268 | 1.2% | 1.8% | 70% | 3.1% | 12 of 1200 |
| 2 | previous | -0.0590 | 0.9% | 1.6% | 57% | 0.9% | 27 of 1200 |
| 2 | current | -0.0470 | 0.5% | 0.8% | 55% | 2.3% | 11 of 1200 |
| 3 | previous | -0.0333 | 3.2% | 3.8% | 71% | 1.4% | 54 of 1200 |
| 3 | current | -0.0076 | 0.9% | 1.1% | 60% | 3.9% | 14 of 1200 |
| 4 | previous | -0.0209 | 2.8% | 2.9% | 79% | 1.5% | 42 of 1200 |
| 4 | current | -0.0198 | 2.4% | 2.4% | 77% | 4.1% | 12 of 1200 |

### Mean over seeds

| Rule | Threshold change | False alarms, all weeks | False alarms, second half | Unusual sessions caught | Guardrail 3, mean |
|---|---|---|---|---|---|
| previous | -0.0360 | 2.2% | 2.9% | 72% | 1.2% |
| current | -0.0251 | 1.1% | 1.3% | 66% | 3.3% |

About 5% false alarms is the design target. Guardrail 3 checks recent sessions from the SAME training set, so under the previous rule it cannot see a drift caused by the filter itself.
