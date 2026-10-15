from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, ConfigDict

class RoleOut(BaseModel):
    role_id: int
    role_name: str
    description: Optional[str] = None
    scope: str = "own"
    model_config = ConfigDict(from_attributes=True)

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    department: str
    role_ids: List[int] = []

class UserOut(BaseModel):
    user_id: int
    username: str
    email: EmailStr
    created_at: datetime
    roles: List[RoleOut] = []
    is_biometric_enrolled: bool = False
    password_set: bool = True
    department: str = "Unassigned"
    school_id: Optional[str] = None
    organization_id: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class UpdateDepartmentRequest(BaseModel):
    department: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    username: str
    password: str

class PermissionOut(BaseModel):
    permission_id: int
    resource_name: str
    action_type: str
    description: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class RoleDetail(RoleOut):
    permissions: List[PermissionOut] = []

class SetRoleRequest(BaseModel):
    role_id: int

class PermissionPair(BaseModel):
    resource_name: str
    action_type: str


class MyPermissionsOut(BaseModel):
    username: str
    role_name: Optional[str] = None
    department: str
    permissions: List[PermissionPair] = []

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str