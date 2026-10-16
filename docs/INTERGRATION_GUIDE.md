# Integration Guide: using the RBAC service from your module

This service is the single place for **who the user is** (login) and **what they may do** (permissions).
Your module (attendance, payments, logistics, ...) does not store passwords or decide permissions itself. It
asks this service.

Interactive reference: `https://<host>/api/v1/docs` (locally `http://localhost:8000/api/v1/docs`).

## 1. The model in one picture

```
 User ── login ──► RBAC service ──► access token
   │                                      │
   └─ sends token to your module ◄────────┘
                    │
   your backend ── X-Client-Id/Secret + token ──► POST /api/v1/authz/check ──► allowed / denied
```

- **Users** log in at the RBAC service (password, then Face ID or email code) and receive an **access token**.
- **Your backend** is registered as a **service client** with its own credentials. It forwards the user's token
  and asks questions. Keep the client secret on the server, never in browser code.
- Every decision is made by the RBAC service and **audit-logged** against your module.

## 2. Get credentials

An administrator registers your module under **Integrations → Service clients** and gives you:

- `client_id` (looks like `dsfs_cl_...`) and `client_secret` (`dsfs_sk_...`, shown only once)

Send them on every `/api/v1` request:

```
X-Client-Id: dsfs_cl_...
X-Client-Secret: dsfs_sk_...
```

Ask for only the scopes you need:

| Scope | Lets you |
|---|---|
| `auth:introspect` | Validate a user's token and read their roles and permissions |
| `authz:check` | Ask whether a user may do an action on a resource |
| `roles:read` | List roles and their permissions |
| `users:read` | List and read users and their guardian links |
| `users:write` | Create users, set school/organisation, set role, manage guardian links |
| `events:write` | Report user activity (feeds anomaly detection) |
| `events:read` | Read reported activity (for fraud detection and reporting) |

`users:write` can never assign or modify the Administrator role, and there is no user deletion in the API.

## 3. How a user gets a token

All of these are on the main API (`/api/auth/...`), not `/api/v1`.

```bash
BASE=https://rbac.example.com

# 1. Password (form-encoded)
curl -X POST $BASE/api/auth/login -d "username=teacher1&password=SECRET"
# -> {"status":"2fa_required","pending_token":"...","has_face_option":false}
#    or {"status":"first_time_setup_required", ...}  (new user: finish setup in the RBAC portal first)

# 2. Email code
curl -X POST $BASE/api/auth/request-otp -H "Content-Type: application/json" \
     -d '{"pending_token":"..."}'
curl -X POST "$BASE/api/auth/verify-otp?code=123456" -H "Content-Type: application/json" \
     -d '{"pending_token":"..."}'
# -> {"access_token":"eyJ...","token_type":"bearer"}

# Face ID alternative: POST /api/auth/verify-face  {"pending_token": "...", "image_base64": "..."}
```

Notes:

- The code is a **query parameter** on `verify-otp`; the body holds only `pending_token`.
- Tokens last **30 minutes** and there is **no refresh**. When a call returns `token_inactive`, send the user
  back to sign in.
- Logout is `POST /api/auth/logout` with `Authorization: Bearer <token>`. After logout or an administrator
  terminating the session, the token stops working immediately.
- A browser app on another origin can only call these endpoints if its origin is listed in the server's
  `CORS_EXTRA_ORIGINS`. Otherwise, call them from your backend and relay the result.
- Easiest option: send users to the RBAC portal to sign in and have your app receive the token from there,
  or call the endpoints above from your own login screen.

The user then sends the token to **your** backend as `Authorization: Bearer <token>`.

## 4. Validate a token: `POST /api/v1/auth/introspect` (scope `auth:introspect`)

```bash
curl -X POST $BASE/api/v1/auth/introspect \
  -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" -H "Content-Type: application/json" \
  -d '{"token":"eyJ..."}'
```

Active user:

```json
{ "active": true, "user_id": 7, "username": "teacher1", "department": "Unassigned",
  "school_id": "SCH-1", "organization_id": null, "session_id": 412, "expires_at": 1792000000,
  "roles": [{"role_id": 6, "role_name": "Teacher", "scope": "school"}],
  "permissions": [{"resource_name": "attendance", "action_type": "write"}] }
```

Inactive: `{"active": false, "reason": "session_ended"}`. Reasons: `invalid_token`, `token_expired`,
`user_not_found`, `session_not_found`, `session_terminated`, `session_ended`.

## 5. Ask for a decision: `POST /api/v1/authz/check` (scope `authz:check`)

```bash
curl -X POST $BASE/api/v1/authz/check \
  -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" -H "Content-Type: application/json" \
  -d '{"token":"eyJ...","resource":"attendance","action":"write","context":{"school_id":"SCH-1"}}'
# -> {"allowed":true,"reason":"allowed","user_id":7,"roles":["Teacher"]}
```

`resource` and `action` must come from `GET /api/v1/catalog`. Decisions are **deny by default**: the user needs
a role that grants the permission **and** whose scope matches the `context` you send.

| Role scope | Roles | Send in `context` |
|---|---|---|
| `global` | Administrator, Programme Administrator, Finance Officer, Logistics Officer, Auditor | nothing |
| `school` | School Administrator, Teacher, School Staff | `school_id` of the record |
| `department` | Manager | `department` of the record |
| `organization` | Supplier | `organization_id` of the record |
| `own` | Parent/Guardian, Standard User | `owner_id` (user id of the owner) or `student_id` |

For a Parent/Guardian, `student_id` is allowed only if the guardian is linked to that student (see section 8).
Identifiers are strings and belong to your module; this service only compares them.

Reasons when denied: `missing_permission`, `context_required`, `school_mismatch`, `user_has_no_school`,
`department_mismatch`, `organization_mismatch`, `user_has_no_organization`, `not_owner`. A token that is not
active returns HTTP 401 with code `token_inactive`.

## 6. Which resource is yours

| Module | `resource` | Typical actions |
|---|---|---|
| Student Beneficiary Management | `beneficiary` | read, write |
| Meal Attendance and Tracking | `attendance` | read, write |
| School Feeding Payments | `payment` | read, write, approve, export |
| Supply Chain Management | `supply` | read, write, export |
| Logistics Tracking | `logistics` | read, write, export |
| Analytics Dashboard | `analytics` | read, export |
| Fraud Detection | `fraud` | read, write |
| Offline Data Sync | `sync` | read, write |
| SMS Notifications | `sms` | read, write |

Who holds what:

| Role | Scope | Permissions |
|---|---|---|
| Administrator | global | everything |
| Programme Administrator | global | beneficiary, attendance, payment, supply, logistics read; analytics read+export; fraud read+write; sms read+write |
| School Administrator | school | beneficiary read+write; attendance read+write; supply, analytics read; sync read+write; sms read+write |
| Teacher | school | beneficiary read; attendance read+write; sync write |
| School Staff | school | beneficiary read; attendance read+write; supply read+write; sync write |
| Finance Officer | global | payment read+write+approve+export; beneficiary, analytics, fraud read |
| Logistics Officer | global | supply and logistics read+write; sync write |
| Supplier | organization | supply read+write; logistics read |
| Parent/Guardian | own | beneficiary, attendance, payment read |
| Auditor | global | read on all modules plus export on beneficiary, attendance, payment, supply, logistics, analytics |

If your module needs a permission that does not exist yet, ask the administrator; the matrix is data, not code.

## 7. Report activity: `POST /api/v1/events` (scope `events:write`)

Tell the service what users do so unusual behaviour can be detected. Activity joins the user's live session and
is scored when the session ends.

```bash
curl -X POST $BASE/api/v1/events \
  -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" -H "Content-Type: application/json" \
  -d '{"token":"eyJ...","events":[
        {"resource":"payment","action":"approve","entity_ref":"pay-8841","details":{"amount":5000}}]}'
# -> {"recorded":1,"not_permitted":0,"user_id":7,"session_id":412,"event_ids":[93]}
```

- 1 to 100 events per call; the whole batch is rejected if any event is invalid
- `resource` must be a module resource (not `dashboard`, `role`, `user`, `service_client`)
- Report **meaningful business actions** ("attendance batch submitted", "payment approved"), not one event per
  database row, or normal work looks like unusual volume
- `not_permitted` counts actions the user's role does not allow, which is a useful fraud signal
- A fraud-detection module reads events back with `GET /api/v1/events` (scope `events:read`; filters: `user_id`,
  `resource`, `action`, `permitted`, `since`, `limit`, `offset`)

## 8. Users, roles and guardians

| Call | Scope | Purpose |
|---|---|---|
| `GET /api/v1/roles`, `GET /api/v1/roles/{id}` | `roles:read` | Roles with scope and permissions |
| `GET /api/v1/users?school_id=&role_name=&limit=&offset=` | `users:read` | Paged user list |
| `GET /api/v1/users/{id}` | `users:read` | One user |
| `POST /api/v1/users` | `users:write` | Create a user; they get an email to set a password |
| `PATCH /api/v1/users/{id}` | `users:write` | Update `department`, `school_id`, `organization_id` |
| `PUT /api/v1/users/{id}/role` | `users:write` | Set the single role |
| `GET/POST /api/v1/users/{id}/guardian-links` | `users:read` / `users:write` | Link a parent to student ids |
| `DELETE /api/v1/users/{id}/guardian-links/{link_id}` | `users:write` | Remove a link |

Rules: school-scoped roles need `school_id`, organisation-scoped roles need `organization_id`; the Administrator
role cannot be assigned or changed through the API.

Create a parent and link their child:

```bash
curl -X POST $BASE/api/v1/users -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
  -H "Content-Type: application/json" \
  -d '{"username":"parent_mwangi","email":"mwangi@example.com","role_id":10}'
curl -X POST $BASE/api/v1/users/12/guardian-links -H "X-Client-Id: $CID" -H "X-Client-Secret: $CSECRET" \
  -H "Content-Type: application/json" -d '{"external_student_id":"STU-2041"}'
```

Get the `role_id` values from `GET /api/v1/roles`.

## 9. Errors and limits

Errors have one shape:

```json
{ "error": { "code": "insufficient_scope", "message": "This client lacks the 'users:write' scope." } }
```

| Status | Codes |
|---|---|
| 401 | `invalid_client` (bad/revoked credentials), `token_inactive` |
| 403 | `insufficient_scope`, `forbidden_role` |
| 404 | `user_not_found`, `role_not_found`, `link_not_found` |
| 409 | `username_taken`, `email_taken`, `link_exists` |
| 422 | `validation_error`, `invalid_resource`, `invalid_action`, `school_id_required`, `organization_id_required`, `invalid_department` |
| 429 | `rate_limited` (see the `Retry-After` header) |

Limits: 300 requests per minute per service client; 30 failed client authentications per minute per address.
Sign-in endpoints are limited per address (login 20/min, OTP 20/min, face 60/min).

## 10. Code you can copy

Ready-made clients are in the repository's `integration/` folder.

**Python / FastAPI** (`integration/python/dsfs_auth_client.py`, needs `requests`):

```python
from fastapi import Depends, FastAPI
from dsfs_auth_client import DsfsAuthClient, require_permission

auth = DsfsAuthClient("https://rbac.example.com", "dsfs_cl_...", "dsfs_sk_...")
app = FastAPI()

@app.get("/schools/{school_id}/attendance")
def read_attendance(
    school_id: str,
    decision=Depends(require_permission(
        auth, "attendance", "read",
        context_getter=lambda request: {"school_id": request.path_params["school_id"]},
    )),
):
    return {"requested_by": decision["user_id"]}

# After a meaningful action:
auth.report_events(user_token, [{"resource": "attendance", "action": "write", "entity_ref": "batch-77"}])
```

**Node / Express** (`integration/node/dsfsAuth.js`, Node 18+):

```javascript
const { requirePermission, reportEvents } = require('./dsfsAuth');
// env: DSFS_AUTH_URL, DSFS_CLIENT_ID, DSFS_CLIENT_SECRET

app.get('/schools/:schoolId/attendance',
  requirePermission('attendance', 'read', (req) => ({ school_id: req.params.schoolId })),
  (req, res) => res.json({ requestedBy: req.auth.user_id }));
```

## 11. Test your integration

1. Ask the administrator for a service client with the scopes you need.
2. Open `/api/v1/docs`, click **Authorize**, and enter your id and secret.
3. Sign in to the dashboard, copy your token, and try `POST /auth/introspect` and `POST /authz/check`.
4. Ask the administrator to look at **Integrations → Authorization audit**. Your calls appear with the decision
   and reason.
5. If your module runs in Docker and the RBAC service runs on the same machine, use
   `http://host.docker.internal:8000` as the base URL from inside your container.

## 12. Checklist and known limits

- Keep the client secret on the server, in an environment variable; rotate it if it leaks
- Call `authz/check` on the **server side** for every protected action; hiding buttons is not security
- Handle `token_inactive` by sending the user to sign in again
- Do not cache decisions for long: sessions can be terminated at any time
- Events need an active user session; activity recorded offline cannot be reported after the token expires
- Tokens expire after 30 minutes with no refresh