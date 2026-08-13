from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship

from app.db.database import Base
from app.models.associations import user_roles


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    roles = relationship("Role", secondary=user_roles, back_populates="users")
    sessions = relationship("UserSession", back_populates="user")

    is_biometric_enrolled = Column(Boolean, default=False, nullable=False)
    biometric_enrollment = relationship("BiometricEnrollment", back_populates="user", uselist=False)

    # Forced first-time setup flow
    password_set = Column(Boolean, default=True, nullable=False)
    password_setup_token = Column(String(255), nullable=True, unique=True)
    password_setup_expires = Column(DateTime, nullable=True)
    biometric_choice_made = Column(Boolean, default=True, nullable=False)