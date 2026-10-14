from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.db.database import get_db
from app.schemas.module_event import EventPage
from app.services.module_event_service import query_events

router = APIRouter(prefix="/api/module-events", tags=["module-events"])


@router.get(
    "/",
    response_model=EventPage,
    dependencies=[Depends(require_permission("fraud", "read"))],
)
def list_module_events(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user_id: Optional[int] = None,
    resource: Optional[str] = None,
    action: Optional[str] = None,
    permitted: Optional[bool] = None,
    service_client_id: Optional[int] = None,
    since: Optional[datetime] = None,
    db: Session = Depends(get_db),
):
    total, items = query_events(
        db, limit, offset, user_id=user_id, resource=resource, action=action,
        permitted=permitted, since=since, service_client_id=service_client_id,
    )
    return EventPage(items=items, total=total, limit=limit, offset=offset)