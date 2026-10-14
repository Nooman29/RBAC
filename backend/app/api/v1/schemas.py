from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RoleBrief(BaseModel):
    role_id: int
    role_name: str
    scope: str
    model_config = ConfigDict(from_attributes=True)


class PermissionBrief(BaseModel):
    resource_name: str
    action_type: str
    model_config = ConfigDict(from_attributes=True)


class RoleDetailV1(RoleBrief):
    description: Optional[str] = None
    permissions: List[PermissionBrief] = []


# ---- introspection / authorization -----------------------------------------

class IntrospectRequest(BaseModel):
    token: str = Field(min_length=1, description="The user's access token (Bearer value)")


class IntrospectResponse(BaseModel):
    active: bool
    reason: Optional[str] = None
    user_id: Optional[int] = None
    username: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None
    school_id: Optional[str] = None
    organization_id: Optional[str] = None
    session_id: Optional[int] = None
    expires_at: Optional[int] = None
    roles: Optional[List[RoleBrief]] = None
    permissions: Optional[List[PermissionBrief]] = None


class AccessContextIn(BaseModel):
    """Facts about the record being accessed. Required fields depend on the role's scope."""
    model_config = ConfigDict(extra="forbid")

    school_id: Optional[str] = None
    department: Optional[str] = None
    organization_id: Optional[str] = None
    owner_id: Optional[int] = None
    student_id: Optional[str] = None

    @field_validator("school_id", "department", "organization_id", "student_id", mode="before")
    @classmethod
    def _to_str(cls, value):
        return None if value is None else str(value)


class AuthzCheckRequest(BaseModel):
    token: str = Field(min_length=1)
    resource: str
    action: str
    context: AccessContextIn = AccessContextIn()


class AuthzCheckResponse(BaseModel):
    allowed: bool
    reason: str
    user_id: Optional[int] = None
    roles: List[str] = []


# ---- users -------------------------------------------------------------------

class UserOutV1(BaseModel):
    user_id: int
    username: str
    # Plain str on OUTPUT: stored data must never be re-validated (and 500) on the way out.
    # Input emails are still validated with EmailStr in UserCreateV1.
    email: str
    department: str
    school_id: Optional[str] = None
    organization_id: Optional[str] = None
    roles: List[RoleBrief] = []
    is_biometric_enrolled: bool = False
    password_set: bool = True
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)


class UserCreatedV1(UserOutV1):
    setup_email_sent: bool


class UserPage(BaseModel):
    items: List[UserOutV1]
    total: int
    limit: int
    offset: int


class UserCreateV1(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    role_id: int
    department: str = "Unassigned"
    school_id: Optional[str] = Field(default=None, max_length=50)
    organization_id: Optional[str] = Field(default=None, max_length=50)


class UserUpdateV1(BaseModel):
    department: Optional[str] = None
    school_id: Optional[str] = Field(default=None, max_length=50)
    organization_id: Optional[str] = Field(default=None, max_length=50)


class SetRoleV1(BaseModel):
    role_id: int


class GuardianLinkIn(BaseModel):
    external_student_id: str = Field(min_length=1, max_length=100)


class GuardianLinkOut(BaseModel):
    id: int
    external_student_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)