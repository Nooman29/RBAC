from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class DashboardSummary(BaseModel):
    active_sessions: int
    total_users: int
    roles_configured: int
    alerts_today: int


class ShapContribution(BaseModel):
    feature: str
    shap_value: float


class AnomalyAlertSummary(BaseModel):
    alert_id: int
    session_id: int
    user_id: int
    username: str
    department: Optional[str] = None
    anomaly_score: float
    is_anomaly: bool
    detection_reason: str = "ml_model"
    alert_timestamp: datetime
    reviewed: bool
    model_config = ConfigDict(from_attributes=True)


class AnomalyAlertDetail(AnomalyAlertSummary):
    reviewed_by: Optional[int] = None
    notes: Optional[str] = None
    features: Dict[str, Any]
    shap_contributions: List[ShapContribution] = []
    role_names: List[str] = []
    login_time: datetime
    session_duration: Optional[float] = None
    access_location: Optional[str] = None
    session_terminated: bool = False
   


class AlertReviewUpdate(BaseModel):
    reviewed: Optional[bool] = None
    notes: Optional[str] = None


class SessionOut(BaseModel):
    session_id: int
    user_id: int
    username: str
    department: Optional[str] = None
    login_time: datetime
    logout_time: Optional[datetime] = None
    session_duration: Optional[float] = None
    access_location: Optional[str] = None
    is_active: bool
    terminated: bool


class TerminateSessionResult(BaseModel):
    session_id: int
    terminated: bool
    logout_time: Optional[datetime] = None
    session_duration: Optional[float] = None


class ScenarioOut(BaseModel):
    key: str
    label: str
    description: str


class SimulateAttackRequest(BaseModel):
    user_id: int
    scenario: str
    demo_mode: str = "isolated"


class SimulateAttackResult(BaseModel):
    scenario: str
    scenario_label: str
    demo_mode: str
    session_id: int
    user_id: int
    username: str
    alert_id: Optional[int] = None
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    detection_reason: Optional[str] = None

class AuditLogEntryOut(BaseModel):
    log_id: int
    timestamp: datetime
    username: str
    department: Optional[str] = None
    session_id: int
    resource_name: str
    action_performed: str

class AnomalyAlertDetail(AnomalyAlertSummary):
    reviewed_by: Optional[int] = None
    notes: Optional[str] = None
    features: Dict[str, Any]
    shap_contributions: List[ShapContribution] = []
    role_names: List[str] = []
    login_time: datetime
    session_duration: Optional[float] = None
    access_location: Optional[str] = None
    session_terminated: bool = False
    session_active: bool = False

class AlertReviewUpdate(BaseModel):
    reviewed: Optional[bool] = None
    notes: Optional[str] = None
    review_verdict: Optional[str] = None


class AnomalyAlertSummary(BaseModel):
    alert_id: int
    session_id: int
    user_id: int
    username: str
    department: Optional[str] = None
    anomaly_score: float
    is_anomaly: bool
    detection_reason: str = "ml_model"
    review_verdict: Optional[str] = None
    is_overdue: bool = False
    alert_timestamp: datetime
    reviewed: bool
    model_config = ConfigDict(from_attributes=True)


class AnomalyAlertDetail(AnomalyAlertSummary):
    reviewed_by: Optional[int] = None
    notes: Optional[str] = None
    features: Dict[str, Any]
    shap_contributions: List[ShapContribution] = []
    role_names: List[str] = []
    login_time: datetime
    session_duration: Optional[float] = None
    access_location: Optional[str] = None
    session_terminated: bool = False
    session_active: bool = False


class DetectionOutcomeSummary(BaseModel):
    confirmed_threat: int
    false_positive: int
    authorized_exception: int
    unreviewed: int
    unreviewed_overdue: int
    total_flagged: int