from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, ForeignKey
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
    terminated = Column(Boolean, nullable=False, default=False)  # admin-forced termination

    user = relationship("User", back_populates="sessions")
    access_logs = relationship("AccessLog", back_populates="session")


class AccessLog(Base):
    __tablename__ = "access_logs"

    log_id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.session_id"), nullable=False)
    resource_name = Column(String(100), nullable=False)
    access_timestamp = Column(DateTime, default=datetime.utcnow)
    action_performed = Column(String(20), nullable=False)

    session = relationship("UserSession", back_populates="access_logs")