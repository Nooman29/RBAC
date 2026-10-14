# Integrating with the RBAC central auth service

API docs (Swagger): http://localhost:8000/api/v1/docs

1. Ask an administrator to register your module as a service client. You get a
   `client_id` and a `client_secret` (shown once) plus the scopes you need.
2. Users log in through the RBAC service and receive an access token. Your frontend
   sends it to your backend as `Authorization: Bearer <token>`.
3. Your backend validates it and asks for decisions through `/api/v1`:
   - `POST /api/v1/auth/introspect`  who is this user, and is the session still active?
   - `POST /api/v1/authz/check`      may this user do `action` on `resource` for this record?

Copy `python/dsfs_auth_client.py` (FastAPI) or `node/dsfsAuth.js` (Express) into your project.
Keep the client secret on the server only.