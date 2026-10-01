import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core import rbac
from app.core.security import create_access_token
from app.models.session import UserSession
from app.services import rbac_service


def _bearer(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def test_user_without_roles_has_no_permissions(make_user):
    user = make_user()

    assert not rbac_service.user_has_permission(user, "users", "read")


def test_permission_granted_only_for_exact_resource_and_action(make_role, make_user):
    analyst = make_role("Analyst", [("sessions", "read")])
    user = make_user(roles=[analyst])

    assert rbac_service.user_has_permission(user, "sessions", "read")
    assert not rbac_service.user_has_permission(user, "sessions", "delete")
    assert not rbac_service.user_has_permission(user, "users", "read")


def test_permissions_are_union_of_all_roles(make_role, make_user):
    reader = make_role("Reader", [("audit", "read")])
    editor = make_role("Editor", [("users", "write")])
    user = make_user(roles=[reader, editor])

    assert rbac_service.user_has_permission(user, "audit", "read")
    assert rbac_service.user_has_permission(user, "users", "write")


def test_assign_role_is_idempotent_and_remove_revokes_access(db, make_role, make_user):
    admin = make_role("Admin", [("users", "delete")])
    user = make_user()

    rbac_service.assign_role(db, user, admin)
    rbac_service.assign_role(db, user, admin)
    assert [r.role_name for r in user.roles] == ["Admin"]
    assert rbac_service.user_has_permission(user, "users", "delete")

    rbac_service.remove_role(db, user, admin)
    assert user.roles == []
    assert not rbac_service.user_has_permission(user, "users", "delete")


def test_require_permission_allows_and_audits_authorised_user(db, make_role, make_user, monkeypatch):
    user = make_user(roles=[make_role("Admin", [("users", "read")])])
    logged = []
    monkeypatch.setattr(rbac.session_service, "log_access", lambda db, **kw: logged.append(kw))

    guard = rbac.require_permission("users", "read")
    result = guard(current=(user, 99), db=db)

    assert result is user
    assert logged == [{"session_id": 99, "resource_name": "users", "action_type": "read"}]


def test_require_permission_denies_with_403_and_does_not_audit(db, make_role, make_user, monkeypatch):
    user = make_user(roles=[make_role("Viewer", [("users", "read")])])
    logged = []
    monkeypatch.setattr(rbac.session_service, "log_access", lambda db, **kw: logged.append(kw))

    guard = rbac.require_permission("users", "delete")
    with pytest.raises(HTTPException) as exc:
        guard(current=(user, 99), db=db)

    assert exc.value.status_code == 403
    assert logged == []


def test_valid_token_resolves_user_and_session(db, make_user):
    user = make_user()
    session = UserSession(user_id=user.user_id)
    db.add(session)
    db.commit()
    token = create_access_token({"sub": str(user.user_id), "sid": str(session.session_id)})

    resolved_user, session_id = rbac.get_current_user_and_session(_bearer(token), db)

    assert resolved_user.user_id == user.user_id
    assert session_id == session.session_id


def test_token_without_session_id_is_rejected(db, make_user):
    user = make_user()
    token = create_access_token({"sub": str(user.user_id)})

    with pytest.raises(HTTPException) as exc:
        rbac.get_current_user_and_session(_bearer(token), db)

    assert exc.value.status_code == 401


def test_terminated_session_is_rejected(db, make_user):
    user = make_user()
    session = UserSession(user_id=user.user_id, terminated=True)
    db.add(session)
    db.commit()
    token = create_access_token({"sub": str(user.user_id), "sid": str(session.session_id)})

    with pytest.raises(HTTPException) as exc:
        rbac.get_current_user_and_session(_bearer(token), db)

    assert exc.value.status_code == 401
    assert "terminated" in exc.value.detail
