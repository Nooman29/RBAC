"""Alert notifications go to whoever can act on the alert (permission + scope), never by role name."""
import pytest

from app.models.anomaly import AnomalyAlert
from app.models.notification import Notification
from app.models.session import UserSession
from app.services import notification_service


@pytest.fixture(autouse=True)
def no_email(monkeypatch):
    sent = []
    monkeypatch.setattr(notification_service, "_send_alert_email", lambda user, alert: sent.append(user.user_id) or True)
    return sent


def _flagged_alert(db, user):
    session = UserSession(user_id=user.user_id, session_duration=60.0)
    db.add(session)
    db.commit()
    alert = AnomalyAlert(session_id=session.session_id, anomaly_score=0.9, is_anomaly=True)
    db.add(alert)
    db.commit()
    return alert


def test_end_of_session_alert_reaches_in_scope_users_with_dashboard_write(db, make_role, make_user, no_email):
    flagged = make_user(roles=[make_role("Standard User", [("dashboard", "read")])], department="Finance")
    admin = make_user(roles=[make_role("Administrator", [("dashboard", "write")])], department="IT")
    manager_role = make_role("Manager", [("dashboard", "write")])
    same_dept = make_user(roles=[manager_role], department="Finance")
    make_user(roles=[manager_role], department="HR")                        # out of scope
    make_user(roles=[make_role("Auditor", [("dashboard", "read")])])        # can see, cannot act

    notification_service.notify_admins_of_anomaly(db, _flagged_alert(db, flagged))

    expected = {admin.user_id, same_dept.user_id}
    assert {n.user_id for n in db.query(Notification).all()} == expected
    assert set(no_email) == expected


def test_a_custom_role_with_the_permission_is_notified_without_being_named(db, make_role, make_user):
    lead_role = make_role("Security Lead", [("dashboard", "write")])
    lead_role.scope = "global"
    db.commit()
    lead = make_user(roles=[lead_role])
    flagged = make_user()

    notification_service.notify_admins_of_anomaly(db, _flagged_alert(db, flagged))

    assert [n.user_id for n in db.query(Notification).all()] == [lead.user_id]


def test_the_flagged_user_is_never_told_about_their_own_alert(db, make_role, make_user):
    admin_role = make_role("Administrator", [("dashboard", "write")])
    flagged_admin = make_user(roles=[admin_role])
    other_admin = make_user(roles=[admin_role])

    notification_service.notify_admins_of_anomaly(db, _flagged_alert(db, flagged_admin))

    assert [n.user_id for n in db.query(Notification).all()] == [other_admin.user_id]


def test_nobody_able_to_act_means_no_notification(db, make_role, make_user):
    flagged = make_user(roles=[make_role("Administrator", [("dashboard", "write")])])

    notification_service.notify_admins_of_anomaly(db, _flagged_alert(db, flagged))

    assert db.query(Notification).count() == 0
