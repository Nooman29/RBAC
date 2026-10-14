import json
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.service_scopes import SERVICE_SCOPES
from app.db.database import get_db
from app.models.service_client import AuthzAuditLog, ServiceClient
from app.models.user import User
from app.services.service_client_service import (
    generate_client_id,
    generate_client_secret,
    hash_client_secret,
    invalid_scopes,
    parse_scopes,
    serialize_scopes,
)

router = APIRouter(prefix="/api/service-clients", tags=["service-clients"])


class ServiceClientCreate(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, max_length=255)
    scopes: List[str]


class ServiceClientUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=3, max_length=100)
    description: Optional[str] = Field(default=None, max_length=255)
    scopes: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ServiceClientOut(BaseModel):
    id: int
    client_id: str
    name: str
    description: Optional[str] = None
    scopes: List[str]
    is_active: bool
    created_at: datetime
    secret_rotated_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class ServiceClientCreated(ServiceClientOut):
    client_secret: str   # returned ONCE; only a hash is stored


class AuditEntryOut(BaseModel):
    id: int
    service_client_id: Optional[int] = None
    client_name: Optional[str] = None
    user_id: Optional[int] = None
    resource_name: str
    action_type: str
    allowed: bool
    reason: str
    context: Optional[dict] = None
    created_at: datetime


def _out(client: ServiceClient) -> dict:
    return {
        "id": client.id,
        "client_id": client.client_id,
        "name": client.name,
        "description": client.description,
        "scopes": parse_scopes(client.scopes),
        "is_active": client.is_active,
        "created_at": client.created_at,
        "secret_rotated_at": client.secret_rotated_at,
        "last_used_at": client.last_used_at,
    }


def _validate_scopes(scopes: List[str]) -> None:
    bad = invalid_scopes(scopes)
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scope(s): {', '.join(bad)}. Valid: {', '.join(SERVICE_SCOPES)}",
        )
    if not scopes:
        raise HTTPException(status_code=400, detail="At least one scope is required.")


def _get_or_404(db: Session, client_pk: int) -> ServiceClient:
    client = db.query(ServiceClient).filter(ServiceClient.id == client_pk).first()
    if client is None:
        raise HTTPException(status_code=404, detail="Service client not found")
    return client


@router.get("/scopes", dependencies=[Depends(require_permission("service_client", "read"))])
def list_scopes():
    return [{"scope": s, "description": d} for s, d in SERVICE_SCOPES.items()]


@router.get(
    "/audit",
    response_model=List[AuditEntryOut],
    dependencies=[Depends(require_permission("service_client", "read"))],
)
def list_audit(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    service_client_id: Optional[int] = None,
    user_id: Optional[int] = None,
    allowed: Optional[bool] = None,
    db: Session = Depends(get_db),
):
    query = db.query(AuthzAuditLog, ServiceClient.name).outerjoin(
        ServiceClient, ServiceClient.id == AuthzAuditLog.service_client_id
    )
    if service_client_id is not None:
        query = query.filter(AuthzAuditLog.service_client_id == service_client_id)
    if user_id is not None:
        query = query.filter(AuthzAuditLog.user_id == user_id)
    if allowed is not None:
        query = query.filter(AuthzAuditLog.allowed == allowed)
    rows = query.order_by(AuthzAuditLog.id.desc()).offset(offset).limit(limit).all()
    return [
        AuditEntryOut(
            id=entry.id,
            service_client_id=entry.service_client_id,
            client_name=name,
            user_id=entry.user_id,
            resource_name=entry.resource_name,
            action_type=entry.action_type,
            allowed=entry.allowed,
            reason=entry.reason,
            context=json.loads(entry.context_json) if entry.context_json else None,
            created_at=entry.created_at,
        )
        for entry, name in rows
    ]


@router.get(
    "/", response_model=List[ServiceClientOut],
    dependencies=[Depends(require_permission("service_client", "read"))],
)
def list_clients(db: Session = Depends(get_db)):
    return [_out(c) for c in db.query(ServiceClient).order_by(ServiceClient.id).all()]


@router.post("/", response_model=ServiceClientCreated)
def create_client(
    payload: ServiceClientCreate,
    current_user: User = Depends(require_permission("service_client", "write")),
    db: Session = Depends(get_db),
):
    _validate_scopes(payload.scopes)
    if db.query(ServiceClient).filter(ServiceClient.name == payload.name).first():
        raise HTTPException(status_code=400, detail="A service client with that name already exists")

    secret = generate_client_secret()
    client = ServiceClient(
        client_id=generate_client_id(),
        name=payload.name,
        description=payload.description,
        secret_hash=hash_client_secret(secret),
        scopes=serialize_scopes(payload.scopes),
        is_active=True,
        created_by=current_user.user_id,
    )
    db.add(client)
    db.commit()
    db.refresh(client)
    return {**_out(client), "client_secret": secret}


@router.post("/{client_pk}/rotate-secret", response_model=ServiceClientCreated)
def rotate_secret(
    client_pk: int,
    _user: User = Depends(require_permission("service_client", "write")),
    db: Session = Depends(get_db),
):
    client = _get_or_404(db, client_pk)
    secret = generate_client_secret()
    client.secret_hash = hash_client_secret(secret)
    client.secret_rotated_at = datetime.utcnow()
    db.commit()
    db.refresh(client)
    return {**_out(client), "client_secret": secret}


@router.patch("/{client_pk}", response_model=ServiceClientOut)
def update_client(
    client_pk: int,
    payload: ServiceClientUpdate,
    _user: User = Depends(require_permission("service_client", "write")),
    db: Session = Depends(get_db),
):
    client = _get_or_404(db, client_pk)
    fields = payload.model_fields_set

    if "name" in fields and payload.name is not None and payload.name != client.name:
        if db.query(ServiceClient).filter(ServiceClient.name == payload.name).first():
            raise HTTPException(status_code=400, detail="A service client with that name already exists")
        client.name = payload.name
    if "description" in fields:
        client.description = payload.description
    if "scopes" in fields and payload.scopes is not None:
        _validate_scopes(payload.scopes)
        client.scopes = serialize_scopes(payload.scopes)
    if "is_active" in fields and payload.is_active is not None:
        client.is_active = payload.is_active

    db.commit()
    db.refresh(client)
    return _out(client)


@router.delete("/{client_pk}")
def delete_client(
    client_pk: int,
    _user: User = Depends(require_permission("service_client", "write")),
    db: Session = Depends(get_db),
):
    client = _get_or_404(db, client_pk)
    name = client.name
    db.delete(client)   # audit rows keep their history (FK is ON DELETE SET NULL)
    db.commit()
    return {"detail": f"Service client '{name}' deleted"}