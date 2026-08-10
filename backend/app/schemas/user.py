from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, ConfigDict

class RoleOut(BaseModel):
    role_id: int
    role_name: str
    description: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    role_ids: List[int] = []

class UserOut(BaseModel):
    user_id: int
    username: str
    email: EmailStr
    created_at: datetime
    roles: List[RoleOut] = []
    model_config = ConfigDict(from_attributes=True)

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