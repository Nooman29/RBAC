"""
Verifies DSFS Pass 2 against the RUNNING backend (default http://127.0.0.1:8000).
Prints PASS/FAIL per check; exit code 1 on any failure.

    docker compose exec backend python -m scripts.verify_pass2

Prerequisites: backend restarted with the Pass 2 code, and the roles seeded.
Creates temporary service clients, users and sessions, and removes them at the end.
"""

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.rate_limit import SlidingWindowLimiter
from app.core.security import create_pending_token, create_access_token
from app.core.service_scopes import SERVICE_SCOPES
from app.db.database import SessionLocal
from app.models.guardian import GuardianLink
from app.models.role import Role
from app.models.service_client import AuthzAuditLog, ServiceClient
from app.models.session import AccessLog, UserSession
from app.models.user import User
from app.services import session_service
from app.services.service_client_service import (
    generate_client_id,
    generate_client_secret,
    hash_client_secret,
)

BASE = os.getenv("VERIFY_BASE_URL", "http://127.0.0.1:8000")
TAG = uuid.uuid4().hex[:8]
failures = []


def check(name, condition, detail=""):
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not condition) else ""))
    if not condition:
        failures.append(name)


def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    request = urllib.request.Request(BASE + path, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(request, timeout=20) as resp:
            raw, status, rh = resp.read(), resp.status, dict(resp.headers)
    except urllib.error.HTTPError as err:
        raw, status, rh = err.read(), err.code, dict(err.headers)
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    return status, parsed, rh


def err_code(body):
    return ((body or {}).get("error") or {}).get("code")


def make_client(db, name_suffix, scopes, active=True):
    secret = generate_client_secret()
    client = ServiceClient(
        client_id=generate_client_id(),
        name=f"verify2-{TAG}-{name_suffix}",
        secret_hash=hash_client_secret(secret),
        scopes=",".join(scopes),
        is_active=active,
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    return client, {"X-Client-Id": client.client_id, "X-Client-Secret": secret}


def make_user(db, role, **fields):
    tag = uuid.uuid4().hex[:8]
    user = User(username=f"verify2_{tag}", password="x", email=f"verify2_{tag}@example.com", **fields)
    user.roles = [role]
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def login_token(db, user):
    session = session_service.create_session(db, user_id=user.user_id, access_location="verify2")
    token = create_access_token({"sub": str(user.user_id), "sid": session.session_id})
    return token, session


def cleanup(db):
    db.rollback()
    users = db.query(User).filter(User.username.like("verify2_%")).all()
    user_ids = [u.user_id for u in users]
    if user_ids:
        session_ids = [s.session_id for s in db.query(UserSession.session_id).filter(UserSession.user_id.in_(user_ids)).all()]
        if session_ids:
            db.query(AccessLog).filter(AccessLog.session_id.in_(session_ids)).delete(synchronize_session=False)
            db.query(UserSession).filter(UserSession.session_id.in_(session_ids)).delete(synchronize_session=False)
        db.query(GuardianLink).filter(GuardianLink.guardian_user_id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
        for user in users:
            db.delete(user)
        db.commit()
    clients = db.query(ServiceClient).filter(ServiceClient.name.like("verify2-%")).all()
    ids = [c.id for c in clients]
    if ids:
        db.query(AuthzAuditLog).filter(AuthzAuditLog.service_client_id.in_(ids)).delete(synchronize_session=False)
        db.commit()
        for client in clients:
            db.delete(client)
        db.commit()


def main():
    db = SessionLocal()
    try:
        cleanup(db)   # leftovers from a crashed earlier run

        roles = {r.role_name: r for r in db.query(Role).all()}
        needed = ["Teacher", "Parent/Guardian", "Supplier", "Administrator", "Standard User"]
        if not all(n in roles for n in needed):
            print("Roles missing. Run: python -m scripts.seed_roles_and_permissions")
            sys.exit(1)

        # ---- 1. API surface and error format --------------------------------
        status, body, _ = call("GET", "/api/v1/health")
        check("v1 health is reachable without credentials", status == 200 and body and body.get("status") == "ok")
        status, body, _ = call("GET", "/api/v1/openapi.json")
        check("v1 OpenAPI lists /auth/introspect", status == 200 and "/auth/introspect" in (body or {}).get("paths", {}))

        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": "x"})
        check("no client credentials -> 401 invalid_client", status == 401 and err_code(body) == "invalid_client", f"{status} {body}")

        full, full_h = make_client(db, "full", list(SERVICE_SCOPES))
        limited, limited_h = make_client(db, "limited", ["authz:check"])
        revoked, revoked_h = make_client(db, "revoked", list(SERVICE_SCOPES), active=False)

        bad_h = {"X-Client-Id": full.client_id, "X-Client-Secret": "wrong"}
        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": "x"}, bad_h)
        check("wrong secret -> 401 invalid_client", status == 401 and err_code(body) == "invalid_client", f"{status} {body}")
        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": "x"}, revoked_h)
        check("revoked client -> 401 invalid_client", status == 401 and err_code(body) == "invalid_client", f"{status} {body}")
        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": "x"}, limited_h)
        check("client without scope -> 403 insufficient_scope", status == 403 and err_code(body) == "insufficient_scope", f"{status} {body}")
        status, body, _ = call("POST", "/api/v1/auth/introspect", {}, full_h)
        check("empty body -> 422 validation_error", status == 422 and err_code(body) == "validation_error", f"{status} {body}")

        status, body, _ = call("GET", "/health")
        check("existing /health unchanged", status == 200 and body and body.get("status") == "ok")
        status, body, _ = call("GET", "/api/users/")
        check("existing routes keep their error shape ({'detail': ...})",
              status in (401, 403) and body and "detail" in body and "error" not in body, f"{status} {body}")

        # ---- 2. Introspection ----------------------------------------------
        teacher = make_user(db, roles["Teacher"], school_id="SCH-1")
        parent = make_user(db, roles["Parent/Guardian"])
        supplier = make_user(db, roles["Supplier"], organization_id="ORG-1")
        admin_user = make_user(db, roles["Administrator"])
        db.add(GuardianLink(guardian_user_id=parent.user_id, external_student_id="STU-1"))
        db.commit()

        t_token, t_session = login_token(db, teacher)
        p_token, _ = login_token(db, parent)
        s_token, _ = login_token(db, supplier)

        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": t_token}, full_h)
        perms = {(p["resource_name"], p["action_type"]) for p in (body or {}).get("permissions", [])}
        check("introspect: valid token is active with user details",
              status == 200 and body.get("active") is True and body.get("user_id") == teacher.user_id
              and body.get("school_id") == "SCH-1", f"{status} {body}")
        check("introspect: roles and permissions returned",
              [r["role_name"] for r in body.get("roles", [])] == ["Teacher"] and ("attendance", "write") in perms)

        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": "garbage"}, full_h)
        check("introspect: garbage token inactive (invalid_token)",
              status == 200 and body == {"active": False, "reason": "invalid_token"}, f"{status} {body}")

        pending = create_pending_token(teacher.user_id, scope="pending_2fa")
        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": pending}, full_h)
        check("introspect: pending-2FA token is not accepted", status == 200 and body.get("active") is False, f"{status} {body}")

        ended_token, ended_session = login_token(db, teacher)
        ended_session.logout_time = datetime.utcnow()
        db.commit()
        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": ended_token}, full_h)
        check("introspect: logged-out session inactive (session_ended)",
              status == 200 and body.get("active") is False and body.get("reason") == "session_ended", f"{status} {body}")

        term_token, term_session = login_token(db, teacher)
        term_session.terminated = True
        db.commit()
        status, body, _ = call("POST", "/api/v1/auth/introspect", {"token": term_token}, full_h)
        check("introspect: terminated session inactive (session_terminated)",
              status == 200 and body.get("active") is False and body.get("reason") == "session_terminated", f"{status} {body}")

        # ---- 3. Authorization checks ---------------------------------------
        def authz(token, resource, action, context=None, headers=full_h):
            return call("POST", "/api/v1/authz/check",
                        {"token": token, "resource": resource, "action": action, "context": context or {}}, headers)

        status, body, _ = authz(t_token, "attendance", "write", {"school_id": "SCH-1"})
        check("authz: teacher allowed in own school", status == 200 and body.get("allowed") is True, f"{status} {body}")
        status, body, _ = authz(t_token, "attendance", "write", {"school_id": "SCH-2"})
        check("authz: teacher denied in another school (school_mismatch)",
              status == 200 and body.get("allowed") is False and body.get("reason") == "school_mismatch", f"{status} {body}")
        status, body, _ = authz(t_token, "attendance", "write")
        check("authz: no context -> context_required", body and body.get("reason") == "context_required", f"{status} {body}")
        status, body, _ = authz(t_token, "payment", "read", {"school_id": "SCH-1"})
        check("authz: missing permission denied", body and body.get("reason") == "missing_permission", f"{status} {body}")
        status, body, _ = authz(p_token, "attendance", "read", {"student_id": "STU-1"})
        check("authz: parent allowed for linked student", status == 200 and body.get("allowed") is True, f"{status} {body}")
        status, body, _ = authz(p_token, "attendance", "read", {"student_id": "STU-9"})
        check("authz: parent denied for unlinked student", body and body.get("allowed") is False and body.get("reason") == "not_owner", f"{status} {body}")
        status, body, _ = authz(s_token, "supply", "read", {"organization_id": "ORG-1"})
        check("authz: supplier allowed for own organisation", status == 200 and body.get("allowed") is True, f"{status} {body}")
        status, body, _ = authz(s_token, "supply", "read", {"organization_id": "ORG-2"})
        check("authz: supplier denied for another organisation", body and body.get("allowed") is False, f"{status} {body}")
        status, body, _ = authz(t_token, "warp_drive", "read")
        check("authz: unknown resource -> 422 invalid_resource", status == 422 and err_code(body) == "invalid_resource", f"{status} {body}")
        status, body, _ = authz(t_token, "attendance", "read", {"school_id": "SCH-1", "bogus": 1})
        check("authz: unknown context field -> 422", status == 422, f"{status} {body}")
        status, body, _ = authz("garbage", "attendance", "read", {"school_id": "SCH-1"})
        check("authz: inactive token -> 401 token_inactive", status == 401 and err_code(body) == "token_inactive", f"{status} {body}")
        status, body, _ = authz(term_token, "attendance", "read", {"school_id": "SCH-1"})
        check("authz: terminated session -> 401 token_inactive", status == 401 and err_code(body) == "token_inactive", f"{status} {body}")
        status, body, _ = authz(t_token, "attendance", "write", {"school_id": "SCH-1"}, headers=limited_h)
        check("authz: client with authz:check scope may call it", status == 200, f"{status} {body}")

        db.expire_all()
        rows = db.query(AuthzAuditLog).filter(AuthzAuditLog.service_client_id.in_([full.id, limited.id])).all()
        check("audit: decisions were recorded", len(rows) >= 10, f"{len(rows)} rows")
        check("audit: a denial with its reason was recorded",
              any((not r.allowed) and r.reason == "school_mismatch" for r in rows))
        check("audit: inactive-token attempt recorded",
              any((not r.allowed) and r.reason == "token_inactive" for r in rows))

        # ---- 4. Roles and users ---------------------------------------------
        status, body, _ = call("GET", "/api/v1/roles", headers=full_h)
        names = {r["role_name"] for r in (body or [])} if status == 200 else set()
        check("roles: all 12 roles listed with scope", status == 200 and len(names) >= 12 and all("scope" in r for r in body), f"{status}")
        status, body, _ = call("GET", "/api/v1/roles", headers=limited_h)
        check("roles: client without roles:read -> 403", status == 403, f"{status}")

        status, body, _ = call("GET", f"/api/v1/users/{teacher.user_id}", headers=full_h)
        check("users: get one", status == 200 and body.get("username") == teacher.username, f"{status} {body}")
        status, body, _ = call("GET", "/api/v1/users?school_id=SCH-1&limit=5", headers=full_h)
        check("users: list filtered by school", status == 200 and body.get("total", 0) >= 1
              and all(u["school_id"] == "SCH-1" for u in body.get("items", [])), f"{status} {body}")
        status, body, _ = call("GET", "/api/v1/users/999999999", headers=full_h)
        check("users: unknown id -> 404 user_not_found", status == 404 and err_code(body) == "user_not_found", f"{status} {body}")

        base_new = {"username": f"verify2_new_{TAG}", "email": f"verify2_new_{TAG}@example.com"}
        status, body, _ = call("POST", "/api/v1/users", {**base_new, "role_id": roles["Administrator"].role_id}, full_h)
        check("users: cannot create an Administrator via API", status == 403 and err_code(body) == "forbidden_role", f"{status} {body}")
        status, body, _ = call("POST", "/api/v1/users", {**base_new, "role_id": roles["Teacher"].role_id}, full_h)
        check("users: school-scoped role requires school_id", status == 422 and err_code(body) == "school_id_required", f"{status} {body}")
        status, body, _ = call("POST", "/api/v1/users",
                               {"username": f"verify2_dup_{TAG}", "email": teacher.email,
                                "role_id": roles["Standard User"].role_id}, full_h)
        check("users: duplicate email -> 409", status == 409 and err_code(body) == "email_taken", f"{status} {body}")
        status, body, _ = call("POST", "/api/v1/users", {**base_new, "role_id": roles["Standard User"].role_id}, limited_h)
        check("users: create needs users:write scope", status == 403, f"{status} {body}")

        status, body, _ = call("PATCH", f"/api/v1/users/{teacher.user_id}", {"school_id": "SCH-7"}, full_h)
        check("users: PATCH updates school_id", status == 200 and body.get("school_id") == "SCH-7", f"{status} {body}")
        status, body, _ = call("PATCH", f"/api/v1/users/{teacher.user_id}", {"school_id": None}, full_h)
        check("users: cannot clear school_id of a school-scoped role", status == 422, f"{status} {body}")
        status, body, _ = call("PUT", f"/api/v1/users/{teacher.user_id}/role", {"role_id": roles["Administrator"].role_id}, full_h)
        check("users: cannot promote to Administrator via API", status == 403 and err_code(body) == "forbidden_role", f"{status} {body}")
        status, body, _ = call("PUT", f"/api/v1/users/{admin_user.user_id}/role", {"role_id": roles["Standard User"].role_id}, full_h)
        check("users: cannot modify an Administrator via API", status == 403, f"{status} {body}")

        status, body, _ = call("POST", f"/api/v1/users/{parent.user_id}/guardian-links", {"external_student_id": "STU-2"}, full_h)
        link_id = (body or {}).get("id")
        check("guardian: link created (201)", status == 201 and link_id is not None, f"{status} {body}")
        status, body, _ = call("POST", f"/api/v1/users/{parent.user_id}/guardian-links", {"external_student_id": "STU-2"}, full_h)
        check("guardian: duplicate link -> 409", status == 409 and err_code(body) == "link_exists", f"{status} {body}")
        status, body, _ = call("GET", f"/api/v1/users/{parent.user_id}/guardian-links", headers=full_h)
        check("guardian: list shows both links", status == 200 and {l["external_student_id"] for l in body} == {"STU-1", "STU-2"}, f"{status} {body}")
        status, body, _ = authz(p_token, "attendance", "read", {"student_id": "STU-2"})
        check("guardian: new link takes effect in authz", body and body.get("allowed") is True, f"{status} {body}")
        status, body, _ = call("DELETE", f"/api/v1/users/{parent.user_id}/guardian-links/{link_id}", headers=full_h)
        check("guardian: link removed", status == 200, f"{status} {body}")
        status, body, _ = authz(p_token, "attendance", "read", {"student_id": "STU-2"})
        check("guardian: removed link no longer allows access", body and body.get("allowed") is False, f"{status} {body}")

        # ---- 5. Rate limiting -----------------------------------------------
        mini = SlidingWindowLimiter()
        results = [mini.hit("k", 3)[0] for _ in range(5)]
        check("rate limiter: allows 3 then blocks", results == [True, True, True, False, False], str(results))

        statuses = []
        retry = None
        for _ in range(12):
            st, _b, h = call("POST", "/api/auth/forgot-password", {"email": f"nobody-{TAG}@example.com"})
            statuses.append(st)
            if st == 429:
                print('429 response header:', h)
                retry = {k.lower(): v for k, v in h.items()}.get("retry-after")
        check("auth endpoint rate-limited per IP (429 with Retry-After)",
              statuses[:10] == [200] * 10 and 429 in statuses and retry is not None, f"statuses={statuses}, Retry-After={retry}")
    finally:
        cleanup(db)
        db.close()

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED:")
        for name in failures:
            print(f"  - {name}")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()