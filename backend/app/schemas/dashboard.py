from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class DashboardSummary(BaseModel):
    active_sessions: int
    total_users: int
    roles_configured: int
    alerts_today: int


class AnomalyAlertSummary(BaseModel):
    alert_id: int
    session_id: int
    user_id: int
    username: str
    anomaly_score: float
    is_anomaly: bool
    alert_timestamp: datetime
    reviewed: bool
    model_config = ConfigDict(from_attributes=True)


class AnomalyAlertDetail(AnomalyAlertSummary):
    reviewed_by: Optional[int] = None
    notes: Optional[str] = None
    features: Dict[str, Any]
    role_names: List[str] = []
    login_time: datetime
    session_duration: Optional[float] = None
    access_location: Optional[str] = None


class AlertReviewUpdate(BaseModel):
    reviewed: Optional[bool] = None
    notes: Optional[str] = None


class SessionOut(BaseModel):
    session_id: int
    user_id: int
    username: str
    login_time: datetime
    logout_time: Optional[datetime] = None
    session_duration: Optional[float] = None
    access_location: Optional[str] = None
    is_active: bool