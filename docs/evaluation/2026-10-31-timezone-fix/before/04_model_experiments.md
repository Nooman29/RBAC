## Model experiments (isolated benchmark database, seed 42)

### Data and leakage audit

| Partition | Sessions | Attacks and unusual sessions (label 1) | Normal sessions (label 0) |
|---|---|---|---|
| Training (unlabeled, as in production) | 803 | not used | not used |
| Validation | 491 | 238 | 253 |
| Test | 495 | 227 | 268 |

| Check | Result |
|---|---|
| Scaler fitted on training rows only | yes (803 rows; validation and test only transformed) |
| Per-user baselines are point-in-time | verified on 60 sampled sessions (only strictly earlier sessions used) |
| Hyper-parameter search | one fold: fit on the training partition, scored on the validation partition |
| Test partition | evaluated once per model, after selection |
| Training labels | never used (unsupervised); about 6% of training sessions are unusual, as in production |
| Attacks | only in validation and test windows; random draws differ between the two |


### A. Default configurations (test set)

Operating point: the production rule (threshold at a percentile of the TRAINING scores).

| Model | Configuration | AUC-ROC (95% CI) | Precision | Recall | F1 (95% CI) | False-positive rate | Train s | ms per session |
|---|---|---|---|---|---|---|---|---|
| Isolation Forest | 300 trees, max_samples=auto | 1.00 (1.00-1.00) | 99.1% | 98.7% | 0.99 (0.98-1.00) | 0.7% | 0.26 | 0.014 |
| One-Class SVM | RBF, nu=0.05, gamma=scale | 1.00 (0.99-1.00) | 97.0% | 99.1% | 0.98 (0.97-0.99) | 2.6% | 0.00 | 0.003 |
| Local Outlier Factor | 20 neighbours | 1.00 (1.00-1.00) | 97.4% | 98.2% | 0.98 (0.96-0.99) | 2.2% | 0.02 | 0.004 |
| Autoencoder (MLP) | hidden (12, 6, 12) | 1.00 (0.99-1.00) | 96.9% | 95.6% | 0.96 (0.94-0.98) | 2.6% | 0.44 | 0.000 |

Best case: the threshold is chosen on the validation set (not available in production).

| Model | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Isolation Forest | 97.8% | 98.7% | 0.98 | 1.9% |
| One-Class SVM | 100.0% | 99.1% | 1.00 | 0.0% |
| Local Outlier Factor | 97.4% | 98.2% | 0.98 | 2.2% |
| Autoencoder (MLP) | 96.5% | 97.4% | 0.97 | 3.0% |

Recall by attack type at the production operating point:

| Model | Generic unusual sessions | Unusual Login Time + High Activity | Login From an Unrecognized Location | Sudden Spike in Deletions |
|---|---|---|---|---|
| Isolation Forest | 72.7% | 100.0% | 100.0% | 100.0% |
| One-Class SVM | 81.8% | 100.0% | 100.0% | 100.0% |
| Local Outlier Factor | 63.6% | 100.0% | 100.0% | 100.0% |
| Autoencoder (MLP) | 81.8% | 100.0% | 88.9% | 100.0% |


### B. Tuning on the validation set (GridSearchCV)


### Isolation Forest grid search (validation set, mean over random seeds)

| n_estimators | max_samples | contamination | Validation F1 (mean, sd) | Validation AUC (mean, sd) |
|---|---|---|---|---|
| 500 | 1.0 | 0.05 | 0.985 (0.000) | 0.995 (0.000) |
| 300 | 256 | 0.05 | 0.985 (0.000) | 0.995 (0.000) |
| 500 | 256 | 0.05 | 0.985 (0.000) | 0.995 (0.000) |
| 300 | 1.0 | 0.05 | 0.984 (0.001) | 0.995 (0.000) |
| 200 | 1.0 | auto | 0.984 (0.001) | 0.995 (0.000) |
| 200 | 256 | 0.05 | 0.984 (0.001) | 0.995 (0.000) |
| 100 | 1.0 | 0.05 | 0.984 (0.001) | 0.995 (0.001) |
| 500 | 1.0 | auto | 0.984 (0.001) | 0.995 (0.000) |

Effect of n_estimators (average over the other parameters):

| n_estimators | Validation F1 | Validation AUC |
|---|---|---|
| 500 | 0.958 | 0.995 |
| 300 | 0.960 | 0.995 |
| 200 | 0.959 | 0.995 |
| 100 | 0.955 | 0.995 |

Effect of max_samples (average over the other parameters):

| max_samples | Validation F1 | Validation AUC |
|---|---|---|
| 1.0 | 0.972 | 0.995 |
| 256 | 0.969 | 0.995 |
| 128 | 0.957 | 0.995 |
| 64 | 0.933 | 0.995 |

Effect of contamination (average over the other parameters):

| contamination | Validation F1 | Validation AUC |
|---|---|---|
| 0.05 | 0.981 | 0.995 |
| auto | 0.969 | 0.995 |
| 0.1 | 0.966 | 0.995 |
| 0.02 | 0.916 | 0.995 |

Note: contamination only moves the score threshold (it does not change the scores), so it affects F1 but not AUC.


### C. Tuned configurations (test set)

Operating point: the production rule (threshold at a percentile of the TRAINING scores).

| Model | Configuration | AUC-ROC (95% CI) | Precision | Recall | F1 (95% CI) | False-positive rate | Train s | ms per session |
|---|---|---|---|---|---|---|---|---|
| Isolation Forest | 500 trees, max_samples=1.0, contamination=0.05 | 1.00 (1.00-1.00) | 99.1% | 98.7% | 0.99 (0.98-1.00) | 0.7% | 0.46 | 0.038 |
| One-Class SVM | gamma=scale, nu=0.02 | 1.00 (0.99-1.00) | 97.0% | 99.1% | 0.98 (0.97-0.99) | 2.6% | 0.00 | 0.004 |
| Local Outlier Factor | n_neighbors=50 | 1.00 (1.00-1.00) | 99.6% | 99.1% | 0.99 (0.98-1.00) | 0.4% | 0.01 | 0.011 |
| Autoencoder (MLP) | alpha=0.0001, hidden=(8, 4, 8) | 1.00 (1.00-1.00) | 100.0% | 98.2% | 0.99 (0.98-1.00) | 0.0% | 0.51 | 0.000 |

Best case: the threshold is chosen on the validation set (not available in production).

| Model | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Isolation Forest | 99.1% | 98.2% | 0.99 | 0.7% |
| One-Class SVM | 100.0% | 99.1% | 1.00 | 0.0% |
| Local Outlier Factor | 95.0% | 100.0% | 0.97 | 4.5% |
| Autoencoder (MLP) | 100.0% | 98.2% | 0.99 | 0.0% |

Recall by attack type at the production operating point:

| Model | Generic unusual sessions | Unusual Login Time + High Activity | Login From an Unrecognized Location | Sudden Spike in Deletions |
|---|---|---|---|---|
| Isolation Forest | 72.7% | 100.0% | 100.0% | 100.0% |
| One-Class SVM | 81.8% | 100.0% | 100.0% | 100.0% |
| Local Outlier Factor | 81.8% | 100.0% | 100.0% | 100.0% |
| Autoencoder (MLP) | 63.6% | 100.0% | 100.0% | 100.0% |


### Threshold strategies (test set, tuned Isolation Forest)

| Strategy | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Static (95th percentile for everyone) | 99.1% | 98.7% | 0.99 | 0.7% |
| Role-tiered (high 90th, standard 95th, low 97th) | 98.2% | 98.2% | 0.98 | 1.5% |
| Per-user adaptive (own 95th, within +/-0.05 of static) | 97.4% | 99.1% | 0.98 | 2.2% |

Role tiers (assumed for the benchmark: one in four users 'high', one in four 'low'):

| Tier | Test sessions | Recall (static) | False-positive rate (static) | Recall (tiered) | False-positive rate (tiered) |
|---|---|---|---|---|---|
| high | 122 | 100.0% | 0.0% | 100.0% | 3.0% |
| standard | 251 | 98.2% | 1.4% | 98.2% | 1.4% |
| low | 122 | 98.3% | 0.0% | 96.6% | 0.0% |

Tiering is a risk-appetite policy: it trades more false alarms for higher recall on privileged roles.


### Cold start: users with little or no history (tuned Isolation Forest, trained on established users)

| Earlier sessions | Normal episodes | False-positive rate | Attack episodes | Attacks caught | Personal z-scores neutral |
|---|---|---|---|---|---|
| 0 | 20 | 0.0% | 20 | 70.0% | 40 of 40 |
| 3 | 20 | 0.0% | 20 | 100.0% | 40 of 40 |

With fewer than 5 earlier sessions the personal z-scores are neutral (0), so the decision rests on the raw behaviour alone.

### Computational cost (why Isolation Forest suits this system)

| Model | Training | Scoring one session | Needs labels | Explanations |
|---|---|---|---|---|
| Isolation Forest | O(t * psi * log psi) (t trees, psi sub-sample size) | O(t * log psi) | no | exact per-feature (SHAP TreeExplainer) |
| One-Class SVM | between O(n^2) and O(n^3) | O(support vectors * d) | no | model-agnostic approximations only |
| Local Outlier Factor | O(n log n) with an index | O(k * log n) neighbour search | no | none built in |
| Autoencoder | O(epochs * n * parameters) | O(parameters) | no | reconstruction error per feature only |

Reading the results: the attacks come from the system's own simulator, so all figures show how the models rank and separate simulated behaviour, not accuracy against real attackers. Quote the test-set tables, and say which configuration was selected on validation.
