"""
Verifies DSFS Pass 2 part 2: events ingestion, against the RUNNING backend.
Prints PASS/FAIL per check; exit code 1 on any failure.

    docker compose exec backend python -m scripts.verify_events

Prerequisites: backend restarted with the new code, roles seeded.
Creates temporary clients, users and sessions, and removes them at the end.
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

from app.core.security import create_access_token
from app.db.database import SessionLocal
from app.ml.feature_engineering import build_session_feature_vector
from app.models.anomaly import AnomalyAlert
from app.models.module_event import ModuleEvent
from app.models.role import Role
from app.models.service_client import ServiceClient
from app.models.session import AccessLog, UserSession
from app.models.user import User
from app.services import live_detection_service, session_service
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
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as err:
        raw, status = err.read(), err.code
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    return status, parsed


def err_code(body):
    return ((body or {}).get("error") or {}).get("code")


def make_client(db, suffix, scopes):
    secret = generate_client_secret()
    client = ServiceClient(
        client_id=generate_client_id(),
        name=f"verify3-{TAG}-{suffix}",
        secret_hash=hash_client_secret(secret),
        scopes=",".join(scopes),
        is_active=True,
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    return client, {"X-Client-Id": client.client_id, "X-Client-Secret": secret}


def make_user(db, role, **fields):
    tag = uuid.uuid4().hex[:8]
    user = User(username=f"verify3_{tag}", password="x", email=f"verify3_{tag}@example.com", **fields)
    user.roles = [role]
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def login_token(db, user):
    session = session_service.create_session(db, user_id=user.user_id, access_location="verify3")
    return create_access_token({"sub": str(user.user_id), "sid": session.session_id}), session


def cleanup(db):
    db.rollback()
    users = db.query(User).filter(User.username.like("verify3_%")).all()
    user_ids = [u.user_id for u in users]
    if user_ids:
        db.query(ModuleEvent).filter(ModuleEvent.user_id.in_(user_ids)).delete(synchronize_session=False)
        session_ids = [s.session_id for s in db.query(UserSession.session_id).filter(UserSession.user_id.in_(user_ids)).all()]
        if session_ids:
            live_detection_service.delete_for_sessions(db, session_ids)   # live alerts reference sessions
            db.query(AnomalyAlert).filter(AnomalyAlert.session_id.in_(session_ids)).delete(synchronize_session=False)
            db.query(AccessLog).filter(AccessLog.session_id.in_(session_ids)).delete(synchronize_session=False)
            db.query(UserSession).filter(UserSession.session_id.in_(session_ids)).delete(synchronize_session=False)
        db.commit()
        for user in users:
            db.delete(user)
        db.commit()
    clients = db.query(ServiceClient).filter(ServiceClient.name.like("verify3-%")).all()
    for client in clients:
        db.query(ModuleEvent).filter(ModuleEvent.service_client_id == client.id).delete(synchronize_session=False)
    db.commit()
    for client in clients:
        db.delete(client)
    db.commit()


def main():
    db = SessionLocal()
    try:
        cleanup(db)
        roles = {r.role_name: r for r in db.query(Role).all()}
        if "Teacher" not in roles or "Administrator" not in roles:
            print("Roles missing. Run: python -m scripts.seed_roles_and_permissions")
            sys.exit(1)

        writer, writer_h = make_client(db, "writer", ["events:write"])
        reader, reader_h = make_client(db, "reader", ["events:read"])

        teacher = make_user(db, roles["Teacher"], school_id="SCH-1")
        admin_user = make_user(db, roles["Administrator"])
        t_token, t_session = login_token(db, teacher)
        a_token, _ = login_token(db, admin_user)
        t_session_id = t_session.session_id

        # ---- 1. Recording events ---------------------------------------------
        events = [
            {"resource": "attendance", "action": "write", "entity_ref": "att-1"},
            {"resource": "payment", "action": "approve", "entity_ref": "pay-9", "details": {"amount": 5000}},
            {"resource": "supply", "action": "export"},
        ]
        status, body = call("POST", "/api/v1/events", {"token": t_token, "events": events}, writer_h)
        check("events: recorded (201) for the right user and session",
              status == 201 and body and body.get("recorded") == 3 and body.get("user_id") == teacher.user_id
              and body.get("session_id") == t_session_id, f"{status} {body}")
        check("events: actions the user lacks permission for are counted (not_permitted = 2)",
              body and body.get("not_permitted") == 2, f"{body}")

        db.expire_all()
        logs = db.query(AccessLog).filter(AccessLog.session_id == t_session_id).all()
        check("pipeline: one access_log row per event in the user's session", len(logs) == 3, f"{len(logs)}")
        check("pipeline: approve stored as write, export stored as read",
              sorted(l.action_performed for l in logs) == ["read", "write", "write"],
              str(sorted(l.action_performed for l in logs)))
        check("pipeline: resource names carried over",
              {l.resource_name for l in logs} == {"attendance", "payment", "supply"})

        rows = db.query(ModuleEvent).filter(ModuleEvent.user_id == teacher.user_id).order_by(ModuleEvent.id).all()
        check("module_events: raw actions preserved", [r.action_type for r in rows] == ["write", "approve", "export"],
              str([r.action_type for r in rows]))
        check("module_events: permitted flag computed per event", [r.permitted for r in rows] == [True, False, False],
              str([r.permitted for r in rows]))
        check("module_events: details and entity reference stored",
              rows and rows[1].entity_ref == "pay-9" and json.loads(rows[1].details_json) == {"amount": 5000})
        check("ingestion alone creates no anomaly alert",
              db.query(AnomalyAlert).filter(AnomalyAlert.session_id == t_session_id).count() == 0)

        # Do the events show up in what the model actually sees? (no scoring, no email)
        t_session = db.query(UserSession).filter(UserSession.session_id == t_session_id).first()
        t_session.logout_time = datetime.utcnow()
        t_session.session_duration = 60.0
        db.commit()
        try:
            features = build_session_feature_vector(db, t_session)
            n = features.get("n_access_events")
            check("pipeline: events are counted in the session feature vector", n == 3,
                  f"n_access_events={n}; available keys: {sorted(features)[:14]}")
        except Exception as exc:  # noqa: BLE001
            check("pipeline: events are counted in the session feature vector", False, repr(exc))
        db.rollback()

        # ---- 2. Validation (rejected as a whole) -------------------------------
        def post(events_list, token=t_token, headers=writer_h):
            return call("POST", "/api/v1/events", {"token": token, "events": events_list}, headers)

        status, body = post([{"resource": "warp_drive", "action": "read"}])
        check("validation: unknown resource -> 422", status == 422 and err_code(body) == "validation_error", f"{status} {body}")
        status, body = post([{"resource": "user", "action": "read"}])
        check("validation: core resource not accepted as a module event -> 422", status == 422, f"{status} {body}")
        status, body = post([{"resource": "attendance", "action": "delete"}])
        check("validation: unknown action -> 422", status == 422, f"{status} {body}")
        status, body = post([])
        check("validation: empty list -> 422", status == 422, f"{status} {body}")
        status, body = post([{"resource": "attendance", "action": "read"}] * 101)
        check("validation: more than 100 events -> 422", status == 422, f"{status}")
        status, body = post([{"resource": "attendance", "action": "read", "details": {"blob": "x" * 3000}}])
        check("validation: oversized details -> 422", status == 422, f"{status}")
        status, body = post([{"resource": "attendance", "action": "read"}, {"resource": "nope", "action": "read"}])
        db.expire_all()
        check("validation: a bad event rejects the whole batch (nothing recorded)",
              status == 422 and db.query(ModuleEvent).filter(ModuleEvent.user_id == teacher.user_id).count() == 3)

        # ---- 3. Tokens and scopes ---------------------------------------------
        status, body = post([{"resource": "attendance", "action": "read"}], token="garbage")
        check("tokens: garbage token -> 401 token_inactive", status == 401 and err_code(body) == "token_inactive", f"{status} {body}")
        term_token, term_session = login_token(db, teacher)
        term_session.terminated = True
        db.commit()
        status, body = post([{"resource": "attendance", "action": "read"}], token=term_token)
        check("tokens: terminated session -> 401 token_inactive", status == 401 and err_code(body) == "token_inactive", f"{status} {body}")
        status, body = post([{"resource": "attendance", "action": "read"}], headers=reader_h)
        check("scopes: events:read client cannot write events -> 403", status == 403 and err_code(body) == "insufficient_scope", f"{status} {body}")
        status, body = call("GET", "/api/v1/events", headers=writer_h)
        check("scopes: events:write client cannot read events -> 403", status == 403, f"{status} {body}")

        # ---- 4. Reading events ---------------------------------------------------
        status, body = call("GET", f"/api/v1/events?user_id={teacher.user_id}", headers=reader_h)
        check("read: events for the user are returned", status == 200 and body and body.get("total") == 3, f"{status} {body}")
        status, body = call("GET", f"/api/v1/events?user_id={teacher.user_id}&permitted=false", headers=reader_h)
        check("read: filter by permitted=false", status == 200 and body.get("total") == 2, f"{status} {body}")
        status, body = call("GET", f"/api/v1/events?user_id={teacher.user_id}&resource=payment", headers=reader_h)
        item = (body or {}).get("items", [{}])[0] if status == 200 else {}
        check("read: filter by resource returns details and source client",
              status == 200 and body.get("total") == 1 and item.get("details") == {"amount": 5000}
              and item.get("source_client") == writer.name, f"{status} {body}")

        # ---- 5. Administrator view (normal user login) ----------------------------
        admin_h = {"Authorization": f"Bearer {a_token}"}
        status, body = call("GET", f"/api/module-events/?user_id={teacher.user_id}", headers=admin_h)
        check("dashboard: Administrator can read module events (fraud:read)",
              status == 200 and body and body.get("total") == 3, f"{status} {body}")
        status, body = call("GET", "/api/module-events/", headers={"Authorization": f"Bearer {t_token}"})
        check("dashboard: Teacher cannot read module events -> 403", status == 403, f"{status} {body}")
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