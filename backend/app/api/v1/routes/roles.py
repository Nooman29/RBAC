from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.deps import require_scope
from app.api.v1.errors import api_error
from app.api.v1.schemas import RoleDetailV1
from app.db.database import get_db
from app.models.role import Role

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get("", response_model=List[RoleDetailV1], summary="List roles with their permissions")
def list_roles(_client=Depends(require_scope("roles:read")), db: Session = Depends(get_db)):
    return db.query(Role).order_by(Role.role_id).all()


@router.get("/{role_id}", response_model=RoleDetailV1, summary="One role with its permissions")
def get_role(role_id: int, _client=Depends(require_scope("roles:read")), db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if role is None:
        raise api_error(404, "role_not_found", "Role not found.")
    return role