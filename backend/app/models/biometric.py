from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.database import Base

class BiometricEnrollment(Base):
    __tablename__ = "biometric_enrollments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    embedding = Column(Text, nullable=False)  # JSON-encoded list of floats
    model_name = Column(String, nullable=False, default="Facenet512")
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="biometric_enrollment")