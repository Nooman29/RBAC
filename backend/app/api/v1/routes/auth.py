from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.deps import require_scope
from app.api.v1.schemas import (
    IntrospectRequest,
    IntrospectResponse,
    PermissionBrief,
    RoleBrief,
)
from app.db.database import get_db
from app.services.introspection_service import validate_access_token

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/introspect",
    response_model=IntrospectResponse,
    response_model_exclude_none=True,
    summary="Validate a user's access token",
    description=(
        "Users log in through the RBAC service (password, then Face ID or OTP) and receive an access "
        "token. A module forwards that token here. `active: false` means the token is expired, invalid, "
        "or its session was logged out or terminated by an administrator."
    ),
)
def introspect(
    payload: IntrospectRequest,
    _client=Depends(require_scope("auth:introspect")),
    db: Session = Depends(get_db),
):
    check = validate_access_token(db, payload.token)
    if not check.active:
        return IntrospectResponse(active=False, reason=check.reason)

    user = check.user
    pairs = sorted({(p.resource_name, p.action_type) for r in user.roles for p in r.permissions})
    return IntrospectResponse(
        active=True,
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        department=user.department,
        school_id=user.school_id,
        organization_id=user.organization_id,
        session_id=check.session.session_id,
        expires_at=check.expires_at,
        roles=[RoleBrief.model_validate(r) for r in user.roles],
        permissions=[PermissionBrief(resource_name=r, action_type=a) for r, a in pairs],
    )