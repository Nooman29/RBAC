import numpy as np
import pytest

from scripts import evaluate_realistic as er
from scripts import seed_synthetic_data as seed


def test_precision_falls_with_prevalence_while_recall_and_fpr_stay_fixed():
    # recall 1.0, 1% false alarms: at 50% attacks precision is high, at 1% it is about one half
    high, _ = er.at_prevalence(1.0, 0.01, 0.5)
    even, _ = er.at_prevalence(1.0, 0.01, 0.01)
    assert high == pytest.approx(1 / 1.01)
    assert even == pytest.approx(0.01 / (0.01 + 0.0099))
    assert high > even


def test_f1_at_prevalence_matches_counting():
    # 1000 sessions, 50 attacks; recall 0.8 -> 40 caught; fpr 0.02 -> 19 false alarms
    precision, f1 = er.at_prevalence(0.8, 0.02, 0.05)
    assert precision == pytest.approx(40 / 59)
    assert f1 == pytest.approx(2 * (40 / 59) * 0.8 / ((40 / 59) + 0.8))


def test_no_catches_gives_zero_not_an_error():
    assert er.at_prevalence(0.0, 0.0, 0.01) == (0.0, 0.0)


def test_wilson_interval_is_honest_at_zero():
    lo, hi = er.wilson(0, 300)
    assert lo == 0.0
    assert 0.005 < hi < 0.02          # 0 of 300 still allows roughly a 1% rate


def test_wilson_interval_contains_the_rate():
    lo, hi = er.wilson(10, 50)
    assert lo < 0.2 < hi


def test_weighted_pr_auc_is_one_for_perfect_ranking_at_any_prevalence():
    pos, neg = np.array([0.9, 0.8]), np.array([0.1, 0.2, 0.3])
    for p in (0.5, 0.01):
        assert er.weighted_ap(pos, neg, p) == pytest.approx(1.0)


def test_weighted_pr_auc_drops_with_prevalence_when_ranking_is_imperfect():
    pos, neg = np.array([0.9, 0.4]), np.array([0.5, 0.2, 0.1])
    assert er.weighted_ap(pos, neg, 0.01) < er.weighted_ap(pos, neg, 0.5)


def test_user_bootstrap_keeps_each_users_sessions_together():
    users_pos = np.array([1, 1, 2])
    users_neg = np.array([1, 2, 2, 2])
    rng = np.random.default_rng(0)
    for pos, neg in er.user_bootstrap(users_pos, users_neg, 20, rng):
        # a resample is a multiset of whole users: user 1 always brings 2 positives and 1 negative
        n1 = (pos == 0).sum()
        assert (pos == 1).sum() == n1 and (neg == 0).sum() == n1


def test_routine_sessions_stay_inside_the_routine():
    profile = {"typical_hour": 9, "typical_events": 5, "typical_duration": 900.0, "ips": ["10.77.1.1", "10.77.1.2"]}
    for _ in range(50):
        p = er.routine(profile)
        assert 9 <= p["hour"] <= 12 and p["ip"] == "10.77.1.1" and p["weekend"] is False


def test_sweep_scales_only_what_it_says():
    profile = {"typical_hour": 9, "typical_events": 5, "typical_duration": 900.0, "ips": ["10.77.1.1"]}
    assert er.sweep_params(profile, "volume", 3.0)["events"] == 15
    assert er.sweep_params(profile, "long", 2.0)["duration"] == pytest.approx(1800.0)
    assert er.sweep_params(profile, "destructive", 1.0)["action_weights"] == [0.3, 0.4, 0.3]
    assert er.sweep_params(profile, "volume", 3.0)["action_weights"] == seed.NORMAL_ACTION_WEIGHTS


def test_apply_trait_changes_one_thing():
    profile = {"typical_hour": 9, "typical_events": 5, "typical_duration": 900.0, "ips": ["10.77.1.1"]}
    base = er.routine(profile)
    night = seed.apply_trait(dict(base), "night", set())
    assert night["hour"] in (0, 1, 2, 3, 4, 22, 23)
    assert {k: v for k, v in night.items() if k != "hour"} == {k: v for k, v in base.items() if k != "hour"}
    assert seed.apply_trait(dict(base), "new_ip", set())["ip"].startswith(seed.UNUSUAL_IP_PREFIX)
