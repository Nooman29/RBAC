Testing 10 users: 4 run(s) of each of 3 scenarios and 12 normal sessions per user. No emails are sent.
  user 474: done
  user 469: done
  user 9: done
  user 470: done
  user 473: done
  user 1: done
  user 475: done
  user 472: done
  user 468: done
  user 471: done

## Detection evaluation
Model threshold 0.5184 (percentile 95), trained on 577 sessions.
Test set: 120 simulated attack sessions and 120 normal-looking sessions from 10 users (seed 7).

| Measure | Full pipeline (model + rules) | ML model alone |
|---|---|---|
| Attacks caught (recall) | 99.2% (119/120, 95% CI 95-100%) | 99.2% (119/120, 95% CI 95-100%) |
| Normal sessions wrongly flagged (FPR) | 2.5% (3/120, 95% CI 1-7%) | 2.5% (3/120, 95% CI 1-7%) |
| Precision at this test mix | 97.5% | 97.5% |
| F1 at this test mix | 0.98 | 0.98 |
| AUC-ROC (threshold-free) | 1.00 | 1.00 |

| Scenario | Caught (full pipeline) | Caught (model alone) | Mean score |
|---|---|---|---|
| Unusual Login Time + High Activity | 100.0% (40/40, 95% CI 91-100%) | 100.0% (40/40, 95% CI 91-100%) | 0.767 |
| Login From an Unrecognized Location | 97.5% (39/40, 95% CI 87-100%) | 97.5% (39/40, 95% CI 87-100%) | 0.579 |
| Sudden Spike in Deletions | 100.0% (40/40, 95% CI 91-100%) | 100.0% (40/40, 95% CI 91-100%) | 0.666 |

Flagged attacks by detection method: ml_model: 119

Projected precision (full pipeline) when attacks are rare, using the measured recall and false-positive rate:
| Share of sessions that are attacks | Precision |
|---|---|
| 1% | 28.6% |
| 5% | 67.6% |
| 10% | 81.5% |

Z-scores on NORMAL-looking sessions (how far from the user's own history; ordinary sessions should stay small):
| Feature | Largest |z| | Sessions with |z| > 10 |
|---|---|---|
| session_duration_sec_zscore | 4.3 | 0 of 120 |
| n_access_events_zscore | 5.9 | 0 of 120 |
| distinct_resources_zscore | 2.3 | 0 of 120 |
| n_write_zscore | 6.1 | 0 of 120 |
| n_delete_zscore | 4.7 | 0 of 120 |

Cold-start check (an ordinary session for users with little history):
| Case | access z | duration z | largest |z| | score | flagged |
|---|---|---|---|---|---|
| No history | 0.0 | 0.0 | 0.0 | 0.351 | no |
| One past session | 0.0 | 0.0 | 0.0 | 0.357 | no |
| Twelve past sessions | -0.4 | -0.3 | 0.4 | 0.353 | no |

OK: users with little history get moderate z-scores.

Reading these results:
- The attacks come from our own simulator, so 'recall' means: does the pipeline catch these behaviours. It is not a claim about real-world attackers.
- Precision and F1 depend on the test mix. The projection table shows precision at realistic attack rates.
- AUC does not depend on the threshold or the mix (the CERT notebook's AUC was 0.77, for comparison).
