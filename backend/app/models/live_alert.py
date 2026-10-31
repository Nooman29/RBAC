from datetime import datetime
from sqlalchemy import (
    Column, Integer, Float, Boolean, String, Text, DateTime, ForeignKey, UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.db.database import Base


class LiveAlert(Base):
    """
    Early warning raised while a session is still active (see live_detection_service).

    Kept apart from anomaly_alerts on purpose: that table holds exactly one model verdict
    per session, written when the session ends. A session can raise several live alerts,
    one row per rule; repeat hits update the row instead of adding new ones. Live alerts
    never feed the model's features, baselines or retraining.
    """
    __tablename__ = "live_alerts"
    __table_args__ = (UniqueConstraint("session_id", "rule", name="uq_live_alerts_session_rule"),)

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.session_id"), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    rule = Column(String(40), nullable=False)
    severity = Column(String(10), nullable=False)          # high | medium | low
    status = Column(String(20), nullable=False, default="open", index=True)  # open | dismissed | terminated
    summary = Column(String(300), nullable=False)
    evidence_json = Column(Text, nullable=True)
    hit_count = Column(Integer, nullable=False, default=1)
    is_learning = Column(Boolean, nullable=True)
    first_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_by = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    session = relationship("UserSession")


class DeniedAttempt(Base):
    """
    A request refused during a session: missing permission, record outside the user's
    scope, or a module reporting an action the user had no permission for.

    Deliberately NOT an access_logs row: those feed the anomaly model, and refused
    requests must not change what the model sees. No foreign keys, like module_events.
    """
    __tablename__ = "denied_attempts"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    resource_name = Column(String(100), nullable=False)
    action_type = Column(String(20), nullable=False)
    endpoint = Column(String(200), nullable=True)
    reason = Column(String(20), nullable=False)            # permission | visibility | module
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class LiveSessionScore(Base):
    """
    Latest provisional Isolation Forest score of a session while it was active.
    One row per session: it throttles live scoring and lets the alert page show the
    provisional score next to the official end-of-session score.
    """
    __tablename__ = "live_session_scores"

    session_id = Column(Integer, ForeignKey("sessions.session_id"), primary_key=True)
    scored_at = Column(DateTime, nullable=False)
    anomaly_score = Column(Float, nullable=False)
    peak_score = Column(Float, nullable=False)
    threshold_used = Column(Float, nullable=False)
    risk_tier = Column(String(20), nullable=False)
    is_learning = Column(Boolean, nullable=False)
    n_events = Column(Integer, nullable=False)
    elapsed_sec = Column(Float, nullable=False)
    shap_values_json = Column(Text, nullable=True)
