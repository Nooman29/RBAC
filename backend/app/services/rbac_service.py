from sqlalchemy.orm import Session
from app.models.user import User
from app.models.role import Role


def assign_role(db: Session, user: User, role: Role) -> User:
    if role not in user.roles:
        user.roles.append(role)
        db.commit()
        db.refresh(user)
    return user


def remove_role(db: Session, user: User, role: Role) -> User:
    if role in user.roles:
        user.roles.remove(role)
        db.commit()
        db.refresh(user)
    return user


def user_has_permission(user: User, resource_name: str, action_type: str) -> bool:
    for role in user.roles:
        for perm in role.permissions:
            if perm.resource_name == resource_name and perm.action_type == action_type:
                return True
    return False