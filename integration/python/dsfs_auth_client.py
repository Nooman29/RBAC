"""
Drop-in client for the DSFS central auth service. Requires: pip install requests

    from dsfs_auth_client import DsfsAuthClient, require_permission

    auth = DsfsAuthClient(
        base_url="http://localhost:8000",
        client_id="dsfs_cl_...",
        client_secret="dsfs_sk_...",
    )

    # FastAPI: protect a route. The user's Bearer token is validated and the
    # decision is made by the central service; nothing is decided locally.
    @app.get("/schools/{school_id}/attendance")
    def read_attendance(
        school_id: str,
        decision=Depends(require_permission(
            auth, "attendance", "read",
            context_getter=lambda request: {"school_id": request.path_params["school_id"]},
        )),
    ):
        return {"user_id": decision["user_id"], ...}
"""

import time
from typing import Callable, Optional

import requests


class DsfsAuthError(Exception):
    """Misconfiguration or outage (bad client credentials, service unreachable)."""


class DsfsAuthClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 timeout: float = 5.0, cache_seconds: float = 0.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_seconds = cache_seconds
        self._headers = {"X-Client-Id": client_id, "X-Client-Secret": client_secret}
        self._cache = {}

    def _post(self, path: str, payload: dict) -> requests.Response:
        try:
            return requests.post(f"{self.base_url}/api/v1{path}", json=payload,
                                 headers=self._headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise DsfsAuthError(f"Auth service unreachable: {exc}") from exc

    def introspect(self, token: str) -> dict:
        """Returns {'active': bool, ...user, roles, permissions when active}."""
        cached = self._cache.get(token)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        resp = self._post("/auth/introspect", {"token": token})
        if resp.status_code != 200:
            raise DsfsAuthError(f"introspect failed: {resp.status_code} {resp.text}")
        data = resp.json()
        if self.cache_seconds and data.get("active"):
            self._cache[token] = (time.monotonic() + self.cache_seconds, data)
        return data

    def check(self, token: str, resource: str, action: str, context: Optional[dict] = None) -> dict:
        """Returns {'allowed': bool, 'reason': str, 'user_id': int|None, 'roles': [...]}."""
        resp = self._post("/authz/check", {
            "token": token, "resource": resource, "action": action, "context": context or {},
        })
        if resp.status_code == 200:
            return resp.json()
        error = (resp.json().get("error", {}) if resp.headers.get("content-type", "").startswith("application/json") else {})
        if resp.status_code == 401 and error.get("code") == "token_inactive":
            return {"allowed": False, "reason": "token_inactive", "user_id": None, "roles": []}
        raise DsfsAuthError(f"authz check failed: {resp.status_code} {resp.text}")


def require_permission(client: DsfsAuthClient, resource: str, action: str,
                       context_getter: Optional[Callable] = None):
    """FastAPI dependency factory. context_getter(request) -> dict of context fields."""
    from fastapi import HTTPException, Request

    def dependency(request: Request):
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token = header[7:].strip()
        context = context_getter(request) if context_getter else None
        try:
            decision = client.check(token, resource, action, context)
        except DsfsAuthError as exc:
            raise HTTPException(status_code=503, detail=str(exc))
        if not decision["allowed"]:
            status = 401 if decision["reason"] == "token_inactive" else 403
            raise HTTPException(status_code=status, detail=f"Access denied: {decision['reason']}")
        return decision

    return dependency