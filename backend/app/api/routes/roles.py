from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.role import Role, Permission
from app.schemas.user import RoleOut

router = APIRouter(prefix="/api/roles", tags=["roles"])

@router.get("/", response_model=List[RoleOut])
def list_roles(db: Session = Depends(get_db)):
    return db.query(Role).all()

@router.post("/", response_model=RoleOut)
def create_role(role_name: str, description: str = "", db: Session = Depends(get_db)):
    if db.query(Role).filter(Role.role_name == role_name).first():
        raise HTTPException(status_code=400, detail="Role already exists")
    role = Role(role_name=role_name, description=description)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role

@router.post("/{role_id}/permissions")
def grant_permission(role_id: int, resource_name: str, action_type: str, db: Session = Depends(get_db)):
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    perm = db.query(Permission).filter(
        Permission.resource_name == resource_name, Permission.action_type == action_type
    ).first()
    if not perm:
        perm = Permission(resource_name=resource_name, action_type=action_type)
        db.add(perm)
        db.commit()
        db.refresh(perm)

    if perm not in role.permissions:
        role.permissions.append(perm)
        db.commit()

    return {"detail": f"Granted {action_type} on {resource_name} to {role.role_name}"}