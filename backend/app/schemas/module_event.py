from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class EventOut(BaseModel):
    id: int
    source_client: Optional[str] = None
    user_id: Optional[int] = None
    session_id: Optional[int] = None
    resource_name: str
    action_type: str
    entity_ref: Optional[str] = None
    permitted: bool
    details: Optional[dict] = None
    occurred_at: Optional[datetime] = None
    created_at: datetime


class EventPage(BaseModel):
    items: List[EventOut]
    total: int
    limit: int
    offset: int