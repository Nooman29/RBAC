from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint

from app.db.database import Base


class GuardianLink(Base):
    """
    Links a Parent/Guardian user to an EXTERNAL student identifier owned by
    another module (e.g. Student Beneficiary Management). The RBAC service
    stores only the link, never the student's data.

    ON DELETE CASCADE at the database level means deleting a user removes
    their links without any change to the existing delete_user route.
    """
    __tablename__ = "guardian_links"
    __table_args__ = (
        UniqueConstraint("guardian_user_id", "external_student_id", name="uq_guardian_student"),
    )

    id = Column(Integer, primary_key=True, index=True)
    guardian_user_id = Column(
        Integer, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_student_id = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)