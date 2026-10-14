import json
from datetime import datetime
from typing import List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.module_event import ModuleEvent
from app.models.service_client import ServiceClient
from app.schemas.module_event import EventOut


def to_event_out(event: ModuleEvent, client_name: Optional[str]) -> EventOut:
    return EventOut(
        id=event.id,
        source_client=client_name,
        user_id=event.user_id,
        session_id=event.session_id,
        resource_name=event.resource_name,
        action_type=event.action_type,
        entity_ref=event.entity_ref,
        permitted=event.permitted,
        details=json.loads(event.details_json) if event.details_json else None,
        occurred_at=event.occurred_at,
        created_at=event.created_at,
    )


def query_events(
    db: Session,
    limit: int,
    offset: int,
    user_id: Optional[int] = None,
    resource: Optional[str] = None,
    action: Optional[str] = None,
    permitted: Optional[bool] = None,
    since: Optional[datetime] = None,
    service_client_id: Optional[int] = None,
) -> Tuple[int, List[EventOut]]:
    query = db.query(ModuleEvent, ServiceClient.name).outerjoin(
        ServiceClient, ServiceClient.id == ModuleEvent.service_client_id
    )
    if user_id is not None:
        query = query.filter(ModuleEvent.user_id == user_id)
    if resource:
        query = query.filter(ModuleEvent.resource_name == resource)
    if action:
        query = query.filter(ModuleEvent.action_type == action)
    if permitted is not None:
        query = query.filter(ModuleEvent.permitted == permitted)
    if since is not None:
        query = query.filter(ModuleEvent.created_at >= since)
    if service_client_id is not None:
        query = query.filter(ModuleEvent.service_client_id == service_client_id)

    total = query.count()
    rows = query.order_by(ModuleEvent.id.desc()).offset(offset).limit(limit).all()
    return total, [to_event_out(event, name) for event, name in rows]