from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import hash_password
from app.models.user import User
from app.models.role import Role
from app.schemas.user import UserCreate, UserOut
from app.core.rbac import require_permission

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/", response_model=List[UserOut], dependencies=[Depends(require_permission("user", "read"))])
def list_users(db: Session = Depends(get_db)):
    return db.query(User).all()


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