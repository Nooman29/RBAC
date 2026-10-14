from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text

from app.db.database import Base


class ServiceClient(Base):
    """A DSFS module (or other trusted system) allowed to call /api/v1."""
    __tablename__ = "service_clients"

    id = Column(Integer, primary_key=True, index=True)
    client_id = Column(String(40), unique=True, nullable=False, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    secret_hash = Column(String(64), nullable=False)
    scopes = Column(String(500), nullable=False, default="")   # comma-separated
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    secret_rotated_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True)


class AuthzAuditLog(Base):
    """Every authorization decision made on behalf of a service client."""
    __tablename__ = "authz_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    service_client_id = Column(
        Integer, ForeignKey("service_clients.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id = Column(Integer, nullable=True, index=True)   # no FK: history outlives the user
    resource_name = Column(String(100), nullable=False)
    action_type = Column(String(20), nullable=False)
    allowed = Column(Boolean, nullable=False)
    reason = Column(String(50), nullable=False)
    context_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)