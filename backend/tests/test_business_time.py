"""Generated sessions (attack simulator, synthetic seed data) mean LOCAL hours and are stored in UTC."""
import random
from datetime import date

from app.core.business_time import to_local
from app.ml import feature_engineering as fe
from app.services import attack_simulation_service as sim
from scripts import seed_synthetic_data as seed


def test_simulated_2am_attack_is_2am_local_and_off_hours(db, make_user):
    random.seed(1)
    user = make_user()

    session = sim.create_scenario_session(db, user.user_id, "offhours_exfil", day=date(2026, 10, 28))

    local = to_local(session.login_time)
    assert local.date() == date(2026, 10, 28)
    assert local.hour in (1, 2, 3)                               # 2 AM +- the simulator's jitter
    assert session.login_time.hour == (local.hour - 3) % 24      # stored as UTC (Nairobi is UTC+3)
    assert fe.build_raw_session_features(db, session)["is_offhours"] == 1


def test_simulated_daytime_scenario_is_business_hours_locally(db, make_user):
    random.seed(2)
    user = make_user()

    session = sim.create_scenario_session(db, user.user_id, "snooping", day=date(2026, 10, 28))

    assert to_local(session.login_time).hour in (9, 10, 11)
    assert fe.build_raw_session_features(db, session)["is_offhours"] == 0


def test_seeded_routine_hours_are_local(db, make_user):
    random.seed(3)
    user = make_user()
    profile = seed.make_profile()
    params = seed.normal_params(profile)
    params.update(hour=9, weekend=False)

    session = seed.add_session(db, user.user_id, params)

    local = to_local(session.login_time)
    assert local.hour == 9 and local.weekday() < 5
    assert session.login_time.hour == 6                          # 09:00 EAT is saved as 06:00 UTC
