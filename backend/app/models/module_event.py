from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text

from app.db.database import Base


class ModuleEvent(Base):
    """
    Activity reported by a DSFS module about a user (e.g. 'approved payment pay-9').

    user_id and session_id deliberately have NO foreign keys: the existing
    delete_user route removes sessions manually, and event history should
    survive the user it describes.
    """
    __tablename__ = "module_events"

    id = Column(Integer, primary_key=True, index=True)
    service_client_id = Column(
        Integer, ForeignKey("service_clients.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id = Column(Integer, nullable=True, index=True)
    session_id = Column(Integer, nullable=True, index=True)
    resource_name = Column(String(100), nullable=False)
    action_type = Column(String(20), nullable=False)
    entity_ref = Column(String(100), nullable=True)
    permitted = Column(Boolean, nullable=False)          # did the user hold this permission?
    details_json = Column(Text, nullable=True)
    occurred_at = Column(DateTime, nullable=True)        # as reported by the module (UTC)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)