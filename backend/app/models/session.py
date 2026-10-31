from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship

from app.db.database import Base


class UserSession(Base):
    __tablename__ = "sessions"

    session_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    login_time = Column(DateTime, default=datetime.utcnow)
    logout_time = Column(DateTime, nullable=True)
    session_duration = Column(Float, nullable=True)
    access_location = Column(String(100), nullable=True)
    simulated_scenario = Column(String(50), nullable=True) #simulated scenario key if this session was created by the attack simulation feature
    terminated = Column(Boolean, nullable=False, default=False)  # admin-forced termination

    user = relationship("User", back_populates="sessions")
    access_logs = relationship("AccessLog", back_populates="session")


class AccessLog(Base):
    __tablename__ = "access_logs"
    # Live detection counts a session's recent rows on every request.
    __table_args__ = (Index("ix_access_logs_session_time", "session_id", "access_timestamp"),)

    log_id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.session_id"), nullable=False)
    resource_name = Column(String(100), nullable=False)
    access_timestamp = Column(DateTime, default=datetime.utcnow)
    action_performed = Column(String(20), nullable=False)
    # Friendly name of the part of the dashboard the request belonged to (e.g. "Alerts"),
    # and the request itself (e.g. "GET /api/dashboard/alerts/12"). Labels only: they do not
    # add rows, so the anomaly features that count access_logs are unaffected.
    component = Column(String(60), nullable=True)
    endpoint = Column(String(200), nullable=True)

    session = relationship("UserSession", back_populates="access_logs")