# Demo module: School Meal Attendance

A small separate service that integrates with the RBAC central auth service the way another student's module would.
It has no accounts or permission rules of its own: it relays sign-in, asks `POST /api/v1/authz/check` before every
action, and reports activity to `POST /api/v1/events`.

1. Create demo users (codes go to your inbox through plus-addressing):
   `docker compose exec backend python -m scripts.create_demo_users --email-base you@gmail.com`
2. Register the module: `docker compose exec backend python -m scripts.create_service_client --name "Attendance demo" --scopes auth:introspect,authz:check,events:write`
3. Start it (PowerShell, from the repository root):
```
   $env:DSFS_CLIENT_ID = "dsfs_cl_..."; $env:DSFS_CLIENT_SECRET = "dsfs_sk_..."
   docker compose -f demo/docker-compose.yml up
```
4. Open http://localhost:9000 and sign in as `demo_teacher`, `demo_teacher_b`, `demo_parent` or `demo_finance`.

Then open the RBAC dashboard: **Integrations -> Authorization audit** and **Reported events** show every call the module made.
Remove the demo users: `docker compose exec backend python -m scripts.create_demo_users --remove --yes`.