from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.constants import RESOURCES
from app.core.dsfs_catalog import ACTIONS, ROLE_SCOPES
from app.models.associations import user_roles
from app.models.role import Role, Permission
from app.models.user import User
from app.schemas.user import RoleOut, RoleDetail, RoleListItem, PermissionOut, PermissionCatalog
from app.core.rbac import require_permission
from app.services.session_service import annotate_access

router = APIRouter(prefix="/api/roles", tags=["roles"])

# Built-in roles are the ones the DSFS catalog defines (the three original roles and the DSFS
# roles); the seed script creates them and other parts of the system rely on them, so they can
# never be deleted. This decides what is protected, not who can see what (that is role scope).
BUILTIN_ROLES = frozenset(ROLE_SCOPES)

# Revoking this from the last role that holds it would leave nobody able to manage roles, and
# nobody could grant it back (the same idea as "never remove the last Administrator").
LOCKOUT_PERMISSION = ("role", "write")

MAX_NAMES_IN_ERROR = 5


def _get_role(db: Session, role_id: int) -> Role:
    role = db.query(Role).filter(Role.role_id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    return role


def _holders_of_permission(db: Session, resource_name: str, action_type: str, exclude_role_id: int) -> int:
    """Users who hold the permission through some role OTHER than exclude_role_id."""
    return (
        db.query(func.count(func.distinct(User.user_id)))
        .join(User.roles)
        .join(Role.permissions)
        .filter(
            Role.role_id != exclude_role_id,
            Permission.resource_name == resource_name,
            Permission.action_type == action_type,
        )
        .scalar()
    )


@router.get("/", response_model=List[RoleListItem], dependencies=[Depends(require_permission("role", "read"))])
def list_roles(db: Session = Depends(get_db)):
    counts = dict(
        db.query(user_roles.c.role_id, func.count(user_roles.c.user_id)).group_by(user_roles.c.role_id).all()
    )
    return [
        RoleListItem(
            role_id=r.role_id,
            role_name=r.role_name,
            description=r.description,
            scope=r.scope,
            user_count=counts.get(r.role_id, 0),
            is_builtin=r.role_name in BUILTIN_ROLES,
        )
        for r in db.query(Role).order_by(Role.role_id).all()
    ]


@router.get(
    "/permissions",
    response_model=List[PermissionOut],
    dependencies=[Depends(require_permission("role", "read"))],
)
def list_permissions(db: Session = Depends(get_db)):
    """All permissions in the system — used to populate a 'grant permission' picker."""
    return db.query(Permission).all()


@router.get(
    "/catalog",
    response_model=PermissionCatalog,
    dependencies=[Depends(require_permission("role", "read"))],
)
def permission_catalog():
    """The resources and actions a permission can name (for the 'grant permission' picker)."""
    return PermissionCatalog(resources=list(RESOURCES), actions=list(ACTIONS))


@router.get(
    "/{role_id}",
    response_model=RoleDetail,
    dependencies=[Depends(require_permission("role", "read"))],
)
def get_role(role_id: int, db: Session = Depends(get_db)):
    return _get_role(db, role_id)


@router.post("/", response_model=RoleOut, dependencies=[Depends(require_permission("role", "write"))])
def create_role(role_name: str, description: str = "", db: Session = Depends(get_db)):
    if db.query(Role).filter(Role.role_name == role_name).first():
        raise HTTPException(status_code=400, detail="Role already exists")
    role = Role(role_name=role_name, description=description)
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


@router.delete("/{role_id}", dependencies=[Depends(require_permission("role", "write"))])
def delete_role(role_id: int, request: Request, db: Session = Depends(get_db)):
    role = _get_role(db, role_id)

    if role.role_name in BUILTIN_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"'{role.role_name}' is a built-in role and cannot be deleted.",
        )

    holders = sorted(u.username for u in role.users)
    if holders:
        names = ", ".join(holders[:MAX_NAMES_IN_ERROR]) + (", …" if len(holders) > MAX_NAMES_IN_ERROR else "")
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot delete '{role.role_name}': {len(holders)} user(s) still hold this role ({names}). "
                "Assign them another role first."
            ),
        )

    name = role.role_name
    role.permissions.clear()          # removes the role's links; the permissions stay for other roles
    db.delete(role)
    db.commit()
    annotate_access(db, request, f"Deleted role '{name}'")
    return {"detail": f"Deleted role {name}"}


@router.post("/{role_id}/permissions", dependencies=[Depends(require_permission("role", "write"))])
def grant_permission(
    role_id: int, resource_name: str, action_type: str, request: Request, db: Session = Depends(get_db)
):
    role = _get_role(db, role_id)

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
        annotate_access(db, request, f"Granted {action_type} on {resource_name} to {role.role_name}")

    return {"detail": f"Granted {action_type} on {resource_name} to {role.role_name}"}


@router.delete(
    "/{role_id}/permissions/{permission_id}",
    dependencies=[Depends(require_permission("role", "write"))],
)
def revoke_permission(role_id: int, permission_id: int, request: Request, db: Session = Depends(get_db)):
    role = _get_role(db, role_id)

    perm = db.query(Permission).filter(Permission.permission_id == permission_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    if perm not in role.permissions:
        raise HTTPException(
            status_code=404,
            detail=f"{role.role_name} does not have {perm.action_type} on {perm.resource_name}.",
        )

    if (perm.resource_name, perm.action_type) == LOCKOUT_PERMISSION and role.users:
        if _holders_of_permission(db, perm.resource_name, perm.action_type, exclude_role_id=role.role_id) == 0:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Cannot revoke {perm.action_type} on {perm.resource_name} from {role.role_name}: "
                    "nobody else could manage roles, so it could never be granted back."
                ),
            )

    role.permissions.remove(perm)
    db.commit()
    # Takes effect on the user's next request: permissions are read from the database on every
    # request (the access token carries only the user and session ids).
    annotate_access(db, request, f"Revoked {perm.action_type} on {perm.resource_name} from {role.role_name}")
    return {"detail": f"Revoked {perm.action_type} on {perm.resource_name} from {role.role_name}"}
