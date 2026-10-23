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
    review_verdict: Optional[str] = None
    is_overdue: bool = False
    alert_timestamp: datetime
    reviewed: bool
    model_config = ConfigDict(from_attributes=True)


class AnomalyAlertDetail(AnomalyAlertSummary):
    reviewed_by: Optional[int] = None
    notes: Optional[str] = None
    pattern_signature: Optional[str] = None
    features: Dict[str, Any]
    shap_contributions: List[ShapContribution] = []
    role_names: List[str] = []
    login_time: datetime
    session_duration: Optional[float] = None
    access_location: Optional[str] = None
    session_terminated: bool = False
    session_active: bool = False
    # Adaptive thresholds and cold start (None on alerts scored before these were stored)
    threshold_used: Optional[float] = None
    risk_tier: Optional[str] = None
    is_learning: Optional[bool] = None
    prior_sessions: Optional[int] = None


class AlertReviewUpdate(BaseModel):
    reviewed: Optional[bool] = None
    notes: Optional[str] = None
    review_verdict: Optional[str] = None


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
    simulated: bool = False
    # Detection result for this session, once it has been scored
    alert_id: Optional[int] = None
    is_anomaly: Optional[bool] = None
    anomaly_score: Optional[float] = None
    review_verdict: Optional[str] = None


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


class SimulateAttackResult(BaseModel):
    scenario: str
    scenario_label: str
    session_id: int
    user_id: int
    username: str
    alert_id: Optional[int] = None
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    detection_reason: Optional[str] = None
    pattern_signature: Optional[str] = None


class AuditLogEntryOut(BaseModel):
    log_id: int
    timestamp: datetime
    username: str
    department: Optional[str] = None
    session_id: int
    resource_name: str
    action_performed: str


class DetectionOutcomeSummary(BaseModel):
    confirmed_threat: int
    false_positive: int
    authorized_exception: int
    unreviewed: int
    unreviewed_overdue: int
    total_flagged: int
    # Sessions the detector did NOT flag that an administrator later confirmed as threats
    missed_threat: int = 0
