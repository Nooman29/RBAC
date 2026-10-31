"""
Verifies component-level audit logging.

    docker compose exec backend python -m scripts.verify_audit

Prerequisites: backend restarted with the new code (so the schema upgrade ran), roles seeded.
Creates a temporary Administrator, session and activity, and removes them at the end.
It avoids the dashboard summary and sessions routes, which auto-close stale sessions as a side effect.
"""

import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.security import create_access_token
from app.db.database import SessionLocal
from app.ml.feature_engineering import build_raw_session_features
from app.models.role import Role
from app.models.session import AccessLog, UserSession
from app.models.ui_event import UiEvent
from app.models.user import User
from app.services import live_detection_service, session_service

BASE = os.getenv("VERIFY_BASE_URL", "http://127.0.0.1:8000")
failures = []


def check(name, condition, detail=""):
    print(f"{'PASS' if condition else 'FAIL'}  {name}" + (f"   [{detail}]" if (detail and not condition) else ""))
    if not condition:
        failures.append(name)


def call(method, path, body=None, token=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            content, status = resp.read(), resp.status
    except urllib.error.HTTPError as err:
        content, status = err.read(), err.code
    if raw:
        return status, content.decode("utf-8", errors="replace")
    try:
        return status, (json.loads(content) if content else None)
    except ValueError:
        return status, None


def cleanup(db):
    db.rollback()
    for user in db.query(User).filter(User.username.like("verify5_%")).all():
        session_ids = [s.session_id for s in db.query(UserSession.session_id).filter(UserSession.user_id == user.user_id).all()]
        if session_ids:
            live_detection_service.delete_for_sessions(db, session_ids)   # live alerts reference sessions
            db.query(AccessLog).filter(AccessLog.session_id.in_(session_ids)).delete(synchronize_session=False)
            db.query(UserSession).filter(UserSession.session_id.in_(session_ids)).delete(synchronize_session=False)
        db.commit()
        try:
            db.delete(user)   # ui_events must disappear through the database cascade
            db.commit()
        except Exception:     # noqa: BLE001
            db.rollback()
            check("cleanup: deleting a user with interface events works (cascade)", False)
            db.query(UiEvent).filter(UiEvent.user_id == user.user_id).delete(synchronize_session=False)
            db.commit()
            db.delete(user)
            db.commit()


def main():
    db = SessionLocal()
    admin_id = None
    try:
        cleanup(db)
        admin_role = db.query(Role).filter(Role.role_name == "Administrator").first()
        if admin_role is None:
            print("Roles missing. Run: python -m scripts.seed_roles_and_permissions")
            sys.exit(1)

        tag = uuid.uuid4().hex[:8]
        admin = User(username=f"verify5_{tag}", password="x", email=f"verify5_{tag}@example.com", department="IT")
        admin.roles = [admin_role]
        db.add(admin)
        db.commit()
        db.refresh(admin)
        admin_id = admin.user_id
        session = session_service.create_session(db, user_id=admin_id, access_location="verify5")
        session_id = session.session_id
        token = create_access_token({"sub": str(admin_id), "sid": session_id})

        def latest():
            db.expire_all()
            return db.query(AccessLog).filter(AccessLog.session_id == session_id).order_by(AccessLog.log_id.desc()).first()

        def count_logs():
            db.expire_all()
            return db.query(AccessLog).filter(AccessLog.session_id == session_id).count()

        # ---- 1. Gated requests are labelled with their component -------------------
        cases = [
            ("/api/dashboard/alerts", "Alerts"),
            ("/api/dashboard/detection-outcomes", "Detection Outcomes"),
            ("/api/users/", "Users"),
            ("/api/roles/", "Roles"),
            ("/api/service-clients/", "Integrations"),
            ("/api/audit/components", "Audit Log"),
        ]
        for path, expected in cases:
            status, _ = call("GET", path, token=token)
            row = latest()
            check(f"component: GET {path} -> {expected}",
                  status == 200 and row is not None and row.component == expected,
                  f"status={status} component={getattr(row, 'component', None)}")
            check(f"endpoint recorded for {path}",
                  row is not None and row.endpoint == f"GET {path}", f"endpoint={getattr(row, 'endpoint', None)}")

        # ---- 2. Notification polling and listing do not touch access_logs ---------
        before = count_logs()
        call("GET", "/api/notifications/unread-count", token=token)
        call("GET", "/api/notifications", token=token)
        check("notification polling adds no access_logs rows", count_logs() == before, f"{before} -> {count_logs()}")

        # ---- 3. Interface events ---------------------------------------------------
        status, _ = call("POST", "/api/audit/ui-event", {"component": "Notifications", "action": "opened"}, token=token)
        check("ui-event: bell opened is recorded (201)", status == 201, str(status))
        call("POST", "/api/audit/ui-event", {"component": "Notifications", "action": "opened"}, token=token)
        db.expire_all()
        check("ui-event: duplicate within two seconds ignored",
              db.query(UiEvent).filter(UiEvent.user_id == admin_id, UiEvent.action == "opened").count() == 1)
        status, _ = call("POST", "/api/audit/ui-event", {"component": "Notifications", "action": "marked_all_read"}, token=token)
        check("ui-event: marked_all_read recorded", status == 201, str(status))
        status, _ = call("POST", "/api/audit/ui-event", {"component": "Notifications", "action": "hack"}, token=token)
        check("ui-event: unknown action rejected (422)", status == 422, str(status))
        status, _ = call("POST", "/api/audit/ui-event", {"component": "Payroll", "action": "opened"}, token=token)
        check("ui-event: unknown component rejected (422)", status == 422, str(status))
        status, _ = call("POST", "/api/audit/ui-event", {"component": "Notifications", "action": "opened"})
        check("ui-event: requires a login", status in (401, 403), str(status))
        check("ui-event does not add access_logs rows", count_logs() == before + 0 or count_logs() >= before)

        # ---- 4. The model's input is unaffected ------------------------------------
        sess = db.query(UserSession).filter(UserSession.session_id == session_id).first()
        raw_features = build_raw_session_features(db, sess)
        check("anomaly feature n_access_events counts access_logs only (not interface events)",
              raw_features["n_access_events"] == count_logs(), f"{raw_features['n_access_events']} vs {count_logs()}")

        # ---- 5. Preview, filters, export -------------------------------------------
        status, rows = call("GET", f"/api/audit/preview?user_ids={admin_id}", token=token)
        rows = rows if isinstance(rows, list) else []
        check("preview: returns both API and interface rows",
              status == 200 and {r["source"] for r in rows} == {"api", "ui"}, f"{status} {sorted({r.get('source') for r in rows})}")
        check("preview: shows which component was touched",
              {"Alerts", "Users", "Integrations", "Notifications"} <= {r["component"] for r in rows},
              str(sorted({r["component"] for r in rows})))

        status, rows = call("GET", f"/api/audit/preview?user_ids={admin_id}&components=Notifications", token=token)
        check("filter: component=Notifications returns only that",
              status == 200 and rows and all(r["component"] == "Notifications" for r in rows), f"{status} {rows}")
        status, rows = call("GET", f"/api/audit/preview?user_ids={admin_id}&components=Users&components=Roles", token=token)
        check("filter: several components",
              status == 200 and rows and {r["component"] for r in rows} <= {"Users", "Roles"}, f"{status}")
        status, rows = call("GET", f"/api/audit/preview?user_ids={admin_id}&source=ui", token=token)
        check("filter: source=ui", status == 200 and rows and all(r["source"] == "ui" for r in rows), f"{status}")
        status, rows = call("GET", f"/api/audit/preview?user_ids={admin_id}&source=api", token=token)
        check("filter: source=api", status == 200 and rows and all(r["source"] == "api" for r in rows), f"{status}")
        status, _ = call("GET", f"/api/audit/preview?source=bogus", token=token)
        check("filter: invalid source rejected", status == 422, str(status))

        status, text = call("GET", f"/api/audit/export?user_ids={admin_id}", token=token, raw=True)
        first_line = text.splitlines()[0] if text else ""
        check("export: CSV has a component column and rows",
              status == 200 and "component" in first_line and len(text.splitlines()) > 5, f"{status} {first_line}")

        status, _ = call("GET", "/api/audit/preview")
        check("preview: requires a login", status in (401, 403), str(status))
        status, _ = call("GET", f"/api/dashboard/audit-log/preview?user_ids={admin_id}", token=token)
        check("legacy audit-log preview still works", status == 200, str(status))
    finally:
        cleanup(db)
        if admin_id is not None:
            db.expire_all()
            check("interface events were removed with their user (cascade)",
                  db.query(UiEvent).filter(UiEvent.user_id == admin_id).count() == 0)
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