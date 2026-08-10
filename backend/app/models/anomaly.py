from datetime import datetime
from sqlalchemy import Column, Integer, Float, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.db.database import Base


class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"

    alert_id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.session_id"), nullable=False, unique=True)
    anomaly_score = Column(Float, nullable=False)        # -score_samples(); higher = more anomalous
    is_anomaly = Column(Boolean, nullable=False, default=False)
    features_json = Column(Text, nullable=True)          # JSON feature vector used for this score (feeds SHAP later)
    alert_timestamp = Column(DateTime, default=datetime.utcnow)
    reviewed = Column(Boolean, default=False, nullable=False)
    reviewed_by = Column(Integer, ForeignKey("users.user_id"), nullable=True)
    notes = Column(Text, nullable=True)

    session = relationship("UserSession", backref="anomaly_alert", uselist=False)