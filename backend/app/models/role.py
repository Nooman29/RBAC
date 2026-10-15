from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from app.db.database import Base
from app.models.associations import user_roles, role_permissions

class Role(Base):
    __tablename__ = "roles"

    role_id = Column(Integer, primary_key=True, index=True)
    role_name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    # Data-visibility scope: global | school | department | own | organization.
    # Defaults to the most restrictive value so a misconfigured role can only
    # deny access, never over-grant it.
    scope = Column(String(20), nullable=False, default="own", server_default="own")

    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")


class Permission(Base):
    __tablename__ = "permissions"

    permission_id = Column(Integer, primary_key=True, index=True)
    resource_name = Column(String(100), nullable=False)
    action_type = Column(String(20), nullable=False)  # read | write | approve | export
    description = Column(String(255), nullable=True)

    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")