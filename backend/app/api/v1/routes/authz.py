from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.deps import require_scope
from app.api.v1.errors import api_error
from app.api.v1.schemas import AuthzCheckRequest, AuthzCheckResponse
from app.core.constants import RESOURCES
from app.core.dsfs_catalog import ACTIONS
from app.db.database import get_db
from app.services.introspection_service import validate_access_token
from app.services.rbac_service import AccessContext, check_access
from app.services.service_client_service import record_audit

router = APIRouter(prefix="/authz", tags=["Authorization"])


@router.post(
    "/check",
    response_model=AuthzCheckResponse,
    summary="May this user perform this action on this resource?",
    description=(
        "Deny-by-default. The user needs a role that grants the permission AND whose scope matches "
        "the supplied context (school, department, organisation or ownership). Every decision is "
        "audit-logged against the calling client. An inactive token returns 401 `token_inactive`."
    ),
)
def authz_check(
    payload: AuthzCheckRequest,
    client=Depends(require_scope("authz:check")),
    db: Session = Depends(get_db),
):
    if payload.resource not in RESOURCES:
        raise api_error(422, "invalid_resource", f"Unknown resource '{payload.resource}'. See GET /catalog.")
    if payload.action not in ACTIONS:
        raise api_error(422, "invalid_action", f"Unknown action '{payload.action}'. See GET /catalog.")

    context_dict = payload.context.model_dump(exclude_none=True)

    check = validate_access_token(db, payload.token)
    if not check.active:
        record_audit(db, client, None, payload.resource, payload.action, False, "token_inactive", context_dict)
        raise api_error(401, "token_inactive", f"The user's token is not active ({check.reason}).")

    user = check.user
    decision = check_access(db, user, payload.resource, payload.action, AccessContext(**context_dict))
    record_audit(db, client, user.user_id, payload.resource, payload.action,
                 decision.allowed, decision.reason, context_dict)

    return AuthzCheckResponse(
        allowed=decision.allowed,
        reason=decision.reason,
        user_id=user.user_id,
        roles=[r.role_name for r in user.roles],
    )