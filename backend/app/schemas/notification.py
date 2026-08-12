from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class NotificationOut(BaseModel):
    notification_id: int
    alert_id: Optional[int]
    title: str
    body: Optional[str]
    is_read: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UnreadCountOut(BaseModel):
    unread_count: int