from datetime import datetime
from sqlalchemy import Column, Integer, Float, Boolean, Text, DateTime, ForeignKey, String
from sqlalchemy.orm import relationship

from app.db.database import Base


class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"

    alert_id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.session_id"), nullable=False, unique=True)
    anomaly_score = Column(Float, nullable=False)
    is_anomaly = Column(Boolean, nullable=False, default=False)
    features_json = Column(Text, nullable=True)
    shap_values_json = Column(Text, nullable=True)  # top contributing features for this alert
    alert_timestamp = Column(DateTime, default=datetime.utcnow)
    reviewed = Column(Boolean, default=False, nullable=False)
    reviewed_by = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    notes = Column(Text, nullable=True)

    session = relationship("UserSession", backref="anomaly_alert", uselist=False)
    # attack simulation / feedback loop
    detection_reason = Column(String(50), nullable=False, default="ml_model")
    pattern_signature = Column(String(100), nullable=True)
    review_verdict = Column(String(30), nullable=True)

    # Adaptive thresholds and cold start (null on alerts scored before this was added)
    threshold_used = Column(Float, nullable=True)      # the cutoff this session was compared against
    risk_tier = Column(String(20), nullable=True)      # high | standard | low
    is_learning = Column(Boolean, nullable=True)       # user had too little history for personal baselines
    prior_sessions = Column(Integer, nullable=True)    # user's earlier closed, non-simulated sessions
