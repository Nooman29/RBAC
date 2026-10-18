from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core import rbac
from app.core.components import component_for


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/api/dashboard/summary", "Dashboard"),
        ("/api/dashboard/charts/alerts-over-time", "Dashboard"),
        ("/api/dashboard/alerts", "Alerts"),
        ("/api/dashboard/alerts/12", "Alerts"),
        ("/api/dashboard/sessions", "Sessions"),
        ("/api/dashboard/sessions/5/terminate", "Sessions"),
        ("/api/dashboard/detection-outcomes", "Detection Outcomes"),
        ("/api/dashboard/simulate-attack/scenarios", "Simulate Attack"),
        ("/api/dashboard/audit-log/preview", "Audit Log"),
        ("/api/audit/preview", "Audit Log"),
        ("/api/users", "Users"),
        ("/api/users/", "Users"),
        ("/api/users/7/role", "Users"),
        ("/api/roles/3", "Roles"),
        ("/api/service-clients/", "Integrations"),
        ("/api/service-clients/3/rotate-secret", "Integrations"),
        ("/api/module-events/", "Integrations"),
        ("/api/usersextra", "Other"),
        ("/api/something-else", "Other"),
    ],
)
def test_component_for(path, expected):
    assert component_for(path) == expected


def _request(method, path):
    return SimpleNamespace(method=method, url=SimpleNamespace(path=path))


def test_require_permission_records_component_and_endpoint(db, make_role, make_user, monkeypatch):
    user = make_user(roles=[make_role("Admin", [("users", "read")])])
    logged = []
    monkeypatch.setattr(rbac.session_service, "log_access", lambda db, **kw: logged.append(kw))

    guard = rbac.require_permission("users", "read")
    result = guard(current=(user, 99), db=db, request=_request("GET", "/api/users/"))

    assert result is user
    assert logged == [{
        "session_id": 99,
        "resource_name": "users",
        "action_type": "read",
        "component": "Users",
        "endpoint": "GET /api/users/",
    }]


def test_require_permission_without_request_logs_the_original_fields_only(db, make_role, make_user, monkeypatch):
    user = make_user(roles=[make_role("Admin", [("users", "read")])])
    logged = []
    monkeypatch.setattr(rbac.session_service, "log_access", lambda db, **kw: logged.append(kw))

    guard = rbac.require_permission("users", "read")
    assert guard(current=(user, 99), db=db) is user
    assert logged == [{"session_id": 99, "resource_name": "users", "action_type": "read"}]


def test_denied_request_is_not_audited(db, make_role, make_user, monkeypatch):
    user = make_user(roles=[make_role("Viewer", [("users", "read")])])
    logged = []
    monkeypatch.setattr(rbac.session_service, "log_access", lambda db, **kw: logged.append(kw))

    guard = rbac.require_permission("users", "delete")
    with pytest.raises(HTTPException) as exc:
        guard(current=(user, 99), db=db, request=_request("DELETE", "/api/users/7"))

    assert exc.value.status_code == 403
    assert logged == []