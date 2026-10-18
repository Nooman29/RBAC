from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey

from app.db.database import Base


class UiEvent(Base):
    """
    Interface interactions that are not permission-gated API calls (for example opening the
    notification bell). Deliberately separate from access_logs: those rows feed the anomaly
    model, and UI chatter must not change what the model sees.

    ON DELETE CASCADE at the database level means deleting a user removes their events
    without any change to the existing delete_user route. session_id has no foreign key
    for the same reason.
    """
    __tablename__ = "ui_events"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(Integer, nullable=True, index=True)
    component = Column(String(60), nullable=False, index=True)
    action = Column(String(40), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)