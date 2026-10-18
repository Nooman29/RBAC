from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AuditEntryOut(BaseModel):
    entry_id: str                      # "api-<id>" or "ui-<id>" (the two sources have separate id spaces)
    timestamp: datetime
    username: str
    department: Optional[str] = None
    session_id: Optional[int] = None
    component: str
    resource_name: Optional[str] = None
    action_performed: str
    endpoint: Optional[str] = None
    source: str                        # "api" (permission-gated request) or "ui" (interface action)