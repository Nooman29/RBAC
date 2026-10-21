from datetime import datetime, timedelta
from types import SimpleNamespace

import numpy as np

from scripts import model_experiments as me


def _item(day, label=0):
    return SimpleNamespace(login_time=datetime(2026, 1, 1) + timedelta(days=day)), label


def test_split_is_chronological_disjoint_and_complete():
    items = [_item(d) for d in (9, 3, 7, 1, 5, 2, 8, 4, 6, 0)]      # shuffled on purpose

    train, val, test = me.split_for(items)

    assert len(train) + len(val) + len(test) == 10
    assert (len(train), len(val), len(test)) == (6, 2, 2)
    assert max(s.login_time for s, _ in train) < min(s.login_time for s, _ in val)
    assert max(s.login_time for s, _ in val) < min(s.login_time for s, _ in test)


def test_prf_counts_and_rates():
    y = np.array([1, 1, 1, 0, 0, 0, 0])
    flag = np.array([1, 1, 0, 1, 0, 0, 0])

    m = me.prf(y, flag)

    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (2, 1, 1, 3)
    assert m["precision"] == 2 / 3
    assert m["recall"] == 2 / 3
    assert m["fpr"] == 1 / 4


def test_best_f1_threshold_separates_clean_classes():
    y = np.array([0, 0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.3, 0.8, 0.9])

    threshold = me.best_f1_threshold(y, scores)

    assert 0.3 < threshold <= 0.8
    assert me.prf(y, scores >= threshold)["f1"] == 1.0


def test_autoencoder_scores_an_outlier_above_typical_points():
    rng = np.random.default_rng(0)
    typical = rng.normal(0, 1, size=(300, 6))
    model = me.ReconstructionAutoencoder(random_state=0).fit(typical)

    typical_score = -model.score_samples(np.zeros((1, 6)))[0]
    outlier_score = -model.score_samples(np.full((1, 6), 9.0))[0]

    assert outlier_score > typical_score


def test_bootstrap_interval_contains_the_point_estimate():
    rng = np.random.default_rng(1)
    y = np.array([0] * 60 + [1] * 60)
    scores = np.concatenate([rng.normal(0.3, 0.1, 60), rng.normal(0.7, 0.1, 60)])

    (auc_lo, auc_hi), _ = me.bootstrap_ci(y, scores, 0.5, 200, rng)

    assert auc_lo <= me.roc_auc_score(y, scores) <= auc_hi