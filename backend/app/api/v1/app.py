from fastapi import FastAPI

from app.api.v1.errors import register_error_handlers
from app.api.v1.routes import auth, authz, meta, roles, users

DESCRIPTION = """
Central authentication and authorization for the Digital School Feeding System.

**For module developers**

1. An administrator registers your module as a *service client* in the RBAC dashboard and gives you a
   `client_id` and a `client_secret` (shown once). Send them on every call as the headers
   `X-Client-Id` and `X-Client-Secret`. Use these server-to-server only; never ship them to a browser.
2. Users log in through the RBAC service (`/api/auth/login`, then Face ID or OTP) and receive an access token.
   Your frontend sends that token to *your* backend as `Authorization: Bearer <token>`.
3. Your backend calls `POST /auth/introspect` to validate the token, or `POST /authz/check` to ask whether
   the user may perform an action on a resource (with the context of the record).

Errors have the shape `{"error": {"code": "...", "message": "..."}}`.
"""

TAGS = [
    {"name": "Meta", "description": "Health and catalog"},
    {"name": "Authentication", "description": "Token validation"},
    {"name": "Authorization", "description": "Permission and scope decisions"},
    {"name": "Roles", "description": "Role and permission directory"},
    {"name": "Users", "description": "User management and guardian links"},
]

v1_app = FastAPI(
    title="DSFS Central Auth & Authorization API",
    version="1.0.0",
    description=DESCRIPTION,
    openapi_tags=TAGS,
)
register_error_handlers(v1_app)

v1_app.include_router(meta.router)
v1_app.include_router(auth.router)
v1_app.include_router(authz.router)
v1_app.include_router(roles.router)
v1_app.include_router(users.router)