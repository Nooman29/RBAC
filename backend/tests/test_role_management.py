"""Issue #87: deleting roles, revoking permissions, and recording both in the audit log."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.routes import audit, roles
from app.core import rbac
from app.models.associations import role_permissions
from app.models.role import Permission, Role
from app.models.session import AccessLog, UserSession


def _request(method, path):
    return SimpleNamespace(method=method, url=SimpleNamespace(path=path), state=SimpleNamespace())


@pytest.fixture
def admin(db, make_role, make_user):
    """An administrator with an open session, as a real request would have."""
    user = make_user(roles=[make_role("Administrator", [("role", "read"), ("role", "write"), ("dashboard", "read")])],
                     department="IT")
    session = UserSession(user_id=user.user_id, access_location="10.0.0.1")
    db.add(session)
    db.commit()
    return user, session


def _as(db, actor, method, path, resource="role", action="write"):
    """Runs the permission guard for a request (writing its audit row) and returns the request."""
    user, session = actor
    request = _request(method, path)
    rbac.require_permission(resource, action)(current=(user, session.session_id), db=db, request=request)
    return request


# --- deleting roles ------------------------------------------------------------------------------

def test_unused_custom_role_is_deleted_with_its_permission_links(db, admin, make_role):
    developer = make_role("Developer", [("dashboard", "read")])
    role_id = developer.role_id

    req = _as(db, admin, "DELETE", f"/api/roles/{role_id}")
    roles.delete_role(role_id, request=req, db=db)

    assert db.query(Role).filter(Role.role_id == role_id).first() is None
    assert db.query(role_permissions).filter(role_permissions.c.role_id == role_id).count() == 0
    assert db.query(Permission).filter_by(resource_name="dashboard", action_type="read").count() >= 1  # shared, kept


def test_role_still_held_by_users_cannot_be_deleted(db, admin, make_role, make_user):
    support = make_role("Support Desk")
    for _ in range(2):
        make_user(roles=[support])

    with pytest.raises(HTTPException) as exc:
        roles.delete_role(support.role_id, request=None, db=db)

    assert exc.value.status_code == 409
    assert "2 user(s) still hold this role" in exc.value.detail
    assert "user" in exc.value.detail and "Assign them another role first" in exc.value.detail
    assert db.query(Role).filter(Role.role_id == support.role_id).first() is not None


@pytest.mark.parametrize("name", ["Administrator", "Manager", "Standard User", "Teacher", "Auditor"])
def test_built_in_roles_cannot_be_deleted_even_when_unused(db, make_role, name):
    role = make_role(name)

    with pytest.raises(HTTPException) as exc:
        roles.delete_role(role.role_id, request=None, db=db)

    assert exc.value.status_code == 400
    assert "built-in" in exc.value.detail


def test_deleting_a_missing_role_is_404(db):
    with pytest.raises(HTTPException) as exc:
        roles.delete_role(9999, request=None, db=db)
    assert exc.value.status_code == 404


def test_role_list_shows_user_count_and_built_in_flag(db, admin, make_role, make_user):
    developer = make_role("Developer")
    make_user(roles=[developer])

    listed = {r.role_name: r for r in roles.list_roles(db=db)}

    assert (listed["Developer"].user_count, listed["Developer"].is_builtin) == (1, False)
    assert (listed["Administrator"].user_count, listed["Administrator"].is_builtin) == (1, True)


def test_permission_catalog_offers_real_resources_and_actions():
    catalog = roles.permission_catalog()

    assert "payment" in catalog.resources and "dashboard" in catalog.resources
    assert catalog.actions == ["read", "write", "approve", "export"]


# --- revoking permissions ------------------------------------------------------------------------

def _perm(db, resource, action):
    return db.query(Permission).filter_by(resource_name=resource, action_type=action).one()


def test_revoke_unlinks_the_permission_but_keeps_it_for_other_roles(db, admin, make_role):
    manager = make_role("Team Lead", [("user", "read")])
    other = make_role("Reviewer")
    perm = _perm(db, "user", "read")
    other.permissions.append(perm)
    db.commit()

    roles.revoke_permission(manager.role_id, perm.permission_id, request=None, db=db)

    db.refresh(manager)
    db.refresh(other)
    assert perm not in manager.permissions
    assert perm in other.permissions


def test_revoking_a_permission_the_role_does_not_hold_is_404(db, make_role):
    holder = make_role("Holder", [("user", "read")])
    empty = make_role("Empty")

    with pytest.raises(HTTPException) as exc:
        roles.revoke_permission(empty.role_id, _perm(db, "user", "read").permission_id, request=None, db=db)

    assert exc.value.status_code == 404
    assert "does not have read on user" in exc.value.detail


def test_revoked_permission_is_denied_on_the_next_request(db, make_role, make_user):
    clerk_role = make_role("Clerk", [("user", "read")])
    clerk = make_user(roles=[clerk_role])
    guard = rbac.require_permission("user", "read")
    assert guard(current=(clerk, 0), db=db) is clerk

    roles.revoke_permission(clerk_role.role_id, _perm(db, "user", "read").permission_id, request=None, db=db)

    db.expire_all()   # a new request loads the user and roles fresh from the database
    with pytest.raises(HTTPException) as exc:
        guard(current=(clerk, 0), db=db)
    assert exc.value.status_code == 403


def test_last_role_holding_role_write_cannot_lose_it(db, admin):
    user, _ = admin
    admin_role = user.roles[0]

    with pytest.raises(HTTPException) as exc:
        roles.revoke_permission(admin_role.role_id, _perm(db, "role", "write").permission_id, request=None, db=db)

    assert exc.value.status_code == 400
    assert "nobody else could manage roles" in exc.value.detail
    db.refresh(admin_role)
    assert _perm(db, "role", "write") in admin_role.permissions


def test_role_write_can_be_revoked_when_another_role_still_grants_it(db, admin, make_role, make_user):
    user, _ = admin
    deputy_role = make_role("Deputy")
    deputy_role.permissions.append(_perm(db, "role", "write"))
    make_user(roles=[deputy_role])
    db.commit()

    roles.revoke_permission(user.roles[0].role_id, _perm(db, "role", "write").permission_id, request=None, db=db)

    db.refresh(user.roles[0])
    assert _perm(db, "role", "write") not in user.roles[0].permissions


# --- audit log -----------------------------------------------------------------------------------

def test_grant_revoke_and_delete_are_described_in_the_audit_log(db, admin, make_role):
    developer = make_role("Developer")

    req = _as(db, admin, "POST", f"/api/roles/{developer.role_id}/permissions")
    roles.grant_permission(developer.role_id, "payment", "export", request=req, db=db)
    perm = _perm(db, "payment", "export")
    req = _as(db, admin, "DELETE", f"/api/roles/{developer.role_id}/permissions/{perm.permission_id}")
    roles.revoke_permission(developer.role_id, perm.permission_id, request=req, db=db)
    req = _as(db, admin, "DELETE", f"/api/roles/{developer.role_id}")
    roles.delete_role(developer.role_id, request=req, db=db)

    details = [d for (d,) in db.query(AccessLog.details).order_by(AccessLog.log_id).all()]
    assert details == [
        "Granted export on payment to Developer",
        "Revoked export on payment from Developer",
        "Deleted role 'Developer'",
    ]

    entries = audit._collect(db, {"level": "all"}, None, None, None, None, "api", 50)
    assert {e.details for e in entries} == set(details)
    assert all(e.component == "Roles" for e in entries)


def test_audit_rows_without_a_change_have_no_details(db, admin):
    _as(db, admin, "GET", "/api/roles/", action="read")

    assert db.query(AccessLog).one().details is None
