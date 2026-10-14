import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.service_scopes import SERVICE_SCOPES
from app.models.service_client import ServiceClient, AuthzAuditLog

logger = logging.getLogger(__name__)

_DUMMY_HASH = "0" * 64


def hash_client_secret(secret: str) -> str:
    """
    HMAC-SHA256 keyed with SECRET_KEY. Client secrets are long random tokens, so a
    fast keyed hash is appropriate (bcrypt would add latency to every API call).
    Note: changing SECRET_KEY invalidates existing client secrets; rotate them.
    """
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def generate_client_id() -> str:
    return "dsfs_cl_" + secrets.token_hex(6)


def generate_client_secret() -> str:
    return "dsfs_sk_" + secrets.token_urlsafe(32)


def parse_scopes(raw: Optional[str]) -> List[str]:
    return [s for s in (raw or "").split(",") if s]


def serialize_scopes(scopes: List[str]) -> str:
    return ",".join(sorted(set(scopes)))


def invalid_scopes(scopes: List[str]) -> List[str]:
    return [s for s in scopes if s not in SERVICE_SCOPES]


def authenticate_client(db: Session, client_id: str, client_secret: str) -> Optional[ServiceClient]:
    """Constant-time check. Returns the client only if the secret matches and it is active."""
    client = db.query(ServiceClient).filter(ServiceClient.client_id == client_id).first()
    candidate = hash_client_secret(client_secret)
    expected = client.secret_hash if client else _DUMMY_HASH
    secret_ok = hmac.compare_digest(candidate, expected)
    if client is None or not secret_ok or not client.is_active:
        return None
    return client


def touch_last_used(db: Session, client: ServiceClient) -> None:
    now = datetime.utcnow()
    if client.last_used_at is None or (now - client.last_used_at).total_seconds() > 60:
        client.last_used_at = now
        db.commit()


def record_audit(
    db: Session,
    client: ServiceClient,
    user_id: Optional[int],
    resource_name: str,
    action_type: str,
    allowed: bool,
    reason: str,
    context: Optional[dict] = None,
) -> None:
    """Best-effort audit write: a logging failure must not change the decision."""
    try:
        db.add(
            AuthzAuditLog(
                service_client_id=client.id,
                user_id=user_id,
                resource_name=resource_name,
                action_type=action_type,
                allowed=allowed,
                reason=reason,
                context_json=json.dumps(context) if context else None,
            )
        )
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        logger.exception("Failed to write authz audit log")