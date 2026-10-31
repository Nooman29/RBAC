## Realistic evaluation of the production model (isolated benchmark database, seed 42)

Production configuration: 200 trees, max_samples=1.0, threshold = 95th percentile of the training scores (0.5264). 24 synthetic users; 772 training sessions (unlabeled, about 6% unusual); 255 normal sessions in the test set. Recall intervals: 95%, resampling USERS (1000 resamples). False-positive rate: 3 of 735 ordinary test-window sessions = 0.4%, 95% Wilson interval 0.1%-1.2%.

### A. The headline test set, with honest confidence intervals

| Test set | Attacks | Normal | Precision | Recall | False-positive rate | F1 | F1 95% CI (resampling sessions) | F1 95% CI (resampling users) |
|---|---|---|---|---|---|---|---|---|
| normal + generic unusual + 3 simulator scenarios | 230 | 255 | 99.1% | 97.0% | 0.8% | 0.98 | 0.97-0.99 | 0.97-0.99 |

94% of the test attacks come from the three simulator scenarios; attacks are 47% of the test set.

### B. What the same model gives at realistic attack rates

Recall and false-positive rate do not depend on how common attacks are; precision, F1 and PR-AUC do. Each attack group is scored against the same ordinary sessions, re-weighted to the attack rate. 'Worst case' combines the low end of recall with the high end of the false-positive rate (both 95%).

| Attack group | Attacks | Recall (95% CI) | Attack rate | Precision | Precision, worst case | F1 | F1, worst case | PR-AUC (95% CI) |
|---|---|---|---|---|---|---|---|---|
| Simulator scenarios | 216 | 100.0% (100.0%-100.0%) | 20.0% | 98.4% | 95.4% | 0.99 | 0.98 | 1.00 (1.00-1.00) |
| Simulator scenarios | 216 | 100.0% (100.0%-100.0%) | 5.0% | 92.8% | 81.5% | 0.96 | 0.90 | 1.00 (1.00-1.00) |
| Simulator scenarios | 216 | 100.0% (100.0%-100.0%) | 1.0% | 71.2% | 45.8% | 0.83 | 0.63 | 1.00 (0.99-1.00) |
| Simulator scenarios | 216 | 100.0% (100.0%-100.0%) | 0.3% | 42.4% | 20.1% | 0.60 | 0.34 | 0.99 (0.99-1.00) |
| Generic unusual sessions | 14 | 50.0% (25.0%-76.9%) | 20.0% | 96.8% | 84.0% | 0.66 | 0.39 | 0.93 (0.88-0.98) |
| Generic unusual sessions | 14 | 50.0% (25.0%-76.9%) | 5.0% | 86.6% | 52.4% | 0.63 | 0.34 | 0.80 (0.67-0.91) |
| Generic unusual sessions | 14 | 50.0% (25.0%-76.9%) | 1.0% | 55.3% | 17.5% | 0.53 | 0.21 | 0.59 (0.41-0.80) |
| Generic unusual sessions | 14 | 50.0% (25.0%-76.9%) | 0.3% | 26.9% | 5.9% | 0.35 | 0.10 | 0.50 (0.29-0.72) |
| Routine-hours insider, 2x activity (combined) | 72 | 65.3% (50.0%-80.6%) | 20.0% | 97.6% | 91.3% | 0.78 | 0.65 | 0.96 (0.93-0.99) |
| Routine-hours insider, 2x activity (combined) | 72 | 65.3% (50.0%-80.6%) | 5.0% | 89.4% | 68.8% | 0.75 | 0.58 | 0.87 (0.78-0.96) |
| Routine-hours insider, 2x activity (combined) | 72 | 65.3% (50.0%-80.6%) | 1.0% | 61.8% | 29.7% | 0.63 | 0.37 | 0.70 (0.52-0.88) |
| Routine-hours insider, 2x activity (combined) | 72 | 65.3% (50.0%-80.6%) | 0.3% | 32.5% | 11.2% | 0.43 | 0.18 | 0.58 (0.41-0.81) |

### C. Insiders who keep their routine: how much more must they do before they are caught?

Each session is inside the user's routine (usual hours, a known address, a weekday) and differs only as described. For volume and length, 1.0x is the user's usual amount, so its recall is close to the false-positive rate; destructive and combined also change the mix of actions at 1.0x.

| Change (n = 72 sessions per cell) | 1x | 1.5x | 2x | 3x | 4x | 6x |
|---|---|---|---|---|---|---|
| volume: more actions than usual (usual mix of reads and writes) | 0% | 0% | 1% | 26% | 65% | 89% |
| destructive: more actions, 40% writes and 30% deletions | 0% | 14% | 42% | 86% | 97% | 100% |
| long: a longer session than usual | 0% | 0% | 1% | 10% | 33% | 67% |
| combined: all three at once | 0% | 22% | 65% | 100% | 100% | 100% |

One unusual trait on its own (everything else inside the routine):

| Trait | Sessions | Caught |
|---|---|---|
| night login (22:00-04:59) | 72 | 19.4% |
| unfamiliar address | 72 | 2.8% |
| 3-6x the usual volume | 72 | 84.7% |
| 2-4x the usual length | 72 | 13.9% |
| 40% writes, 30% deletions | 72 | 2.8% |
| all resources equally | 72 | 0.0% |
| weekend login | 72 | 1.4% |

### D. Leave one scenario out: does tuning on attacks just learn the simulator?

For each scenario, the configuration (trees x max_samples) and the threshold are chosen on validation attacks WITHOUT that scenario (best F1), then the scenario is tested. 'Seen' repeats the selection with it included. The production rule needs no attacks at all (95th percentile).

| Held-out scenario | Selected without it | Recall (unseen) | False-positive rate (unseen) | Recall (seen) | False-positive rate (seen) | Recall (production rule) |
|---|---|---|---|---|---|---|
| Unusual Login Time + High Activity | 100 trees, max_samples=256 | 100.0% | 0.4% | 100.0% | 0.4% | 100.0% |
| Login From an Unrecognized Location | 100 trees, max_samples=256 | 100.0% | 0.4% | 100.0% | 0.4% | 100.0% |
| Sudden Spike in Deletions | 100 trees, max_samples=256 | 100.0% | 0.4% | 100.0% | 0.4% | 100.0% |

Reading the results: all attacks are synthetic, so these are properties of the detector on simulated behaviour. Section B is the fair comparison with CERT r4.2, where malicious user-days are about 0.3%.

(Results also written to /tmp/realistic.json)
