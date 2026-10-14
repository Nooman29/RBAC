from typing import Optional

from fastapi import Depends, Request, Security
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.api.v1.errors import api_error
from app.core.rate_limit import (
    V1_CLIENT_LIMIT_PER_MINUTE,
    V1_FAILED_AUTH_PER_MINUTE,
    client_ip,
    limiter,
)
from app.db.database import get_db
from app.models.service_client import ServiceClient
from app.services.service_client_service import (
    authenticate_client,
    parse_scopes,
    touch_last_used,
)

client_id_header = APIKeyHeader(
    name="X-Client-Id", auto_error=False, description="Service client id, e.g. dsfs_cl_ab12cd34ef56"
)
client_secret_header = APIKeyHeader(
    name="X-Client-Secret", auto_error=False, description="Service client secret (shown once at creation)"
)


def _count_failure(ip: str) -> None:
    allowed, retry_after = limiter.hit(f"v1-auth-fail:{ip}", V1_FAILED_AUTH_PER_MINUTE)
    if not allowed:
        raise api_error(
            429, "rate_limited", "Too many failed client authentications.",
            headers={"Retry-After": str(retry_after)},
        )


def get_service_client(
    request: Request,
    client_id: Optional[str] = Security(client_id_header),
    client_secret: Optional[str] = Security(client_secret_header),
    db: Session = Depends(get_db),
) -> ServiceClient:
    ip = client_ip(request)
    if not client_id or not client_secret:
        _count_failure(ip)
        raise api_error(401, "invalid_client", "Missing X-Client-Id or X-Client-Secret header.")

    client = authenticate_client(db, client_id, client_secret)
    if client is None:
        _count_failure(ip)
        raise api_error(401, "invalid_client", "Invalid, revoked or disabled client credentials.")

    allowed, retry_after = limiter.hit(f"client:{client.client_id}", V1_CLIENT_LIMIT_PER_MINUTE)
    if not allowed:
        raise api_error(
            429, "rate_limited", "Client rate limit exceeded.", headers={"Retry-After": str(retry_after)}
        )

    touch_last_used(db, client)
    return client


def require_scope(scope: str):
    def dependency(client: ServiceClient = Depends(get_service_client)) -> ServiceClient:
        if scope not in parse_scopes(client.scopes):
            raise api_error(403, "insufficient_scope", f"This client lacks the '{scope}' scope.")
        return client

    return dependency