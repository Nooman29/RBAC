# Demo module: School Meal Attendance

A small separate service that integrates with the RBAC central auth service the way another student's module would.
It has no accounts or permission rules of its own: it relays sign-in, asks `POST /api/v1/authz/check` before every
action, and reports activity to `POST /api/v1/events`.

## One-time setup

1. Create demo users (codes go to your inbox through plus-addressing):
   `docker compose exec backend python -m scripts.create_demo_users --email-base you@gmail.com`
2. Register the module (skip if "Attendance demo" already exists under Integrations):
   `docker compose exec backend python -m scripts.create_service_client --name "Attendance demo" --scopes auth:introspect,authz:check,events:write`
3. Create `demo/.env` (git-ignored, never commit it) with the client ID and secret:
   ```
   DSFS_CLIENT_ID=dsfs_cl_...
   DSFS_CLIENT_SECRET=dsfs_sk_...
   ```
   Lost the secret? Integrations -> Attendance demo -> Rotate secret, then update `demo/.env`.

## Run

From the repository root, with the main system running (`docker compose up -d`):

```
powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1
```

The script checks the backend, starts the module, waits until it answers and opens http://127.0.0.1:9000.
Sign in as `demo_teacher`, `demo_teacher_b`, `demo_parent` or `demo_finance`.

Stop it with `powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1 -Stop`.

Then open the RBAC dashboard at http://127.0.0.1:5173: **Integrations -> Authorization audit** and
**Reported events** show every call the module made.
Remove the demo users: `docker compose exec backend python -m scripts.create_demo_users --remove --yes`.

Use 127.0.0.1 rather than localhost on Windows: localhost can resolve to IPv6 (::1), which the Docker ports do not answer on.