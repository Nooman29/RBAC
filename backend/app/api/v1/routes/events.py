import json
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.api.v1.deps import require_scope
from app.api.v1.errors import api_error
from app.core.constants import RESOURCES
from app.core.dsfs_catalog import ACTIONS
from app.db.database import get_db
from app.models.module_event import ModuleEvent
from app.models.session import AccessLog
from app.schemas.module_event import EventPage
from app.services.introspection_service import validate_access_token
from app.services.module_event_service import query_events
from app.services.rbac_service import user_has_permission

router = APIRouter(prefix="/events", tags=["Events"])

CORE_RESOURCES = {"dashboard", "role", "user", "service_client"}
MODULE_RESOURCES = [r for r in RESOURCES if r not in CORE_RESOURCES]

# The anomaly model counts read/write/delete per session, so module actions are
# mapped onto those. The raw action is preserved in module_events.
ACTION_FOR_ACCESS_LOG = {"read": "read", "write": "write", "approve": "write", "export": "read"}

MAX_DETAILS_CHARS = 2000


def _naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


class EventItem(BaseModel):
    resource: str
    action: str
    entity_ref: Optional[str] = Field(default=None, max_length=100, description="e.g. 'payment:8841'")
    occurred_at: Optional[datetime] = None
    details: Optional[dict] = Field(default=None, description="Small free-form context, max 2000 characters")

    @field_validator("resource")
    @classmethod
    def _check_resource(cls, value):
        if value not in MODULE_RESOURCES:
            raise ValueError(f"unknown module resource '{value}'; valid: {', '.join(MODULE_RESOURCES)}")
        return value

    @field_validator("action")
    @classmethod
    def _check_action(cls, value):
        if value not in ACTIONS:
            raise ValueError(f"unknown action '{value}'; valid: {', '.join(ACTIONS)}")
        return value

    @field_validator("occurred_at")
    @classmethod
    def _utc(cls, value):
        return _naive_utc(value)

    @field_validator("details")
    @classmethod
    def _details_size(cls, value):
        if value is not None and len(json.dumps(value)) > MAX_DETAILS_CHARS:
            raise ValueError(f"details too large (max {MAX_DETAILS_CHARS} characters)")
        return value


class EventsIn(BaseModel):
    token: str = Field(min_length=1, description="The acting user's access token")
    events: List[EventItem] = Field(min_length=1, max_length=100)


class EventsOut(BaseModel):
    recorded: int
    not_permitted: int
    user_id: int
    session_id: int
    event_ids: List[int]


@router.post(
    "",
    response_model=EventsOut,
    status_code=201,
    summary="Report user activity from your module",
    description=(
        "Records what a user did in your module. The events join the user's live session and are "
        "included when the session is scored for anomalies at logout. Report meaningful business "
        "actions (for example 'attendance batch submitted'), not one event per row, so normal work "
        "does not inflate the user's activity volume. Rejected as a whole (nothing recorded) if any "
        "event is invalid. An inactive token returns 401 `token_inactive`."
    ),
)
def record_events(
    payload: EventsIn,
    client=Depends(require_scope("events:write")),
    db: Session = Depends(get_db),
):
    check = validate_access_token(db, payload.token)
    if not check.active:
        raise api_error(401, "token_inactive", f"The user's token is not active ({check.reason}).")

    user, session = check.user, check.session
    event_rows, access_rows = [], []
    for item in payload.events:
        event_rows.append(
            ModuleEvent(
                service_client_id=client.id,
                user_id=user.user_id,
                session_id=session.session_id,
                resource_name=item.resource,
                action_type=item.action,
                entity_ref=item.entity_ref,
                permitted=user_has_permission(user, item.resource, item.action),
                details_json=json.dumps(item.details) if item.details else None,
                occurred_at=item.occurred_at,
            )
        )
        access_rows.append(
            AccessLog(
                session_id=session.session_id,
                resource_name=item.resource,
                action_performed=ACTION_FOR_ACCESS_LOG[item.action],
            )
        )

    db.add_all(access_rows)
    db.add_all(event_rows)
    db.flush()                       # assigns ids
    event_ids = [row.id for row in event_rows]
    db.commit()

    return EventsOut(
        recorded=len(event_rows),
        not_permitted=sum(1 for row in event_rows if not row.permitted),
        user_id=user.user_id,
        session_id=session.session_id,
        event_ids=event_ids,
    )


@router.get("", response_model=EventPage, summary="Read reported events (for fraud detection and reporting)")
def list_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    user_id: Optional[int] = None,
    resource: Optional[str] = None,
    action: Optional[str] = None,
    permitted: Optional[bool] = None,
    since: Optional[datetime] = Query(None, description="Only events recorded at/after this UTC time"),
    _client=Depends(require_scope("events:read")),
    db: Session = Depends(get_db),
):
    total, items = query_events(
        db, limit, offset, user_id=user_id, resource=resource, action=action,
        permitted=permitted, since=_naive_utc(since),
    )
    return EventPage(items=items, total=total, limit=limit, offset=offset)