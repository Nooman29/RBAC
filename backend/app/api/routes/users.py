from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import hash_password
from app.models.user import User
from app.models.role import Role
from app.schemas.user import UserCreate, UserOut
from app.core.rbac import require_permission
from app.services import rbac_service

router = APIRouter(prefix="/api/users", tags=["users"])

ADMIN_ROLE_NAME = "Administrator"


def _count_administrators(db: Session, exclude_user_id: int = None) -> int:
    query = db.query(User).join(User.roles).filter(Role.role_name == ADMIN_ROLE_NAME)
    if exclude_user_id is not None:
        query = query.filter(User.user_id != exclude_user_id)
    return query.distinct().count()


def _is_administrator(user: User) -> bool:
    return any(r.role_name == ADMIN_ROLE_NAME for r in user.roles)


@router.get("/", response_model=List[UserOut], dependencies=[Depends(require_permission("user", "read"))])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()


@router.get("/{user_id}", response_model=UserOut, dependencies=[Depends(require_permission("user", "read"))])
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.post("/", response_model=UserOut, dependencies=[Depends(require_permission("user", "write"))])
def create_user(payload: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=payload.username,
        password=hash_password(payload.password),
        email=payload.email,
    )
    if payload.role_ids:
        user.roles = db.query(Role).filter(Role.role_id.in_(payload.role_ids)).all()

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(require_permission("user", "write")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.user_id == current_user.user_id:
        raise HTTPException(
            status_code=400,
            detail="You cannot delete your own account while logged in.",
        )

    if _is_administrator(user) and _count_administrators(db, exclude_user_id=user.user_id) == 0:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete the last remaining Administrator — this would lock everyone out.",
        )

    db.delete(user)
    db.commit()
    return {"detail": f"User '{user.username}' deleted"}


@router.post(
    "/{user_id}/roles/{role_id}",
    response_model=UserOut,
    dependencies=[Depends(require_permission("user", "write"))],
)
def assign_role_to_user(user_id: int, role_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    return rbac_service.assign_role(db, user, role)


@router.delete(
    "/{user_id}/roles/{role_id}",
    response_model=UserOut,
)
def remove_role_from_user(
    user_id: int,
    role_id: int,
    current_user: User = Depends(require_permission("user", "write")),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if role.role_name == ADMIN_ROLE_NAME:
        if user.user_id == current_user.user_id:
            raise HTTPException(
                status_code=400,
                detail="You cannot remove your own Administrator role while logged in.",
            )
        if _count_administrators(db, exclude_user_id=user.user_id) == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot remove the last remaining Administrator role — this would lock everyone out.",
            )

    return rbac_service.remove_role(db, user, role)