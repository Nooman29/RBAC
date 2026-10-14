from fastapi import APIRouter, Depends

from app.api.v1.deps import get_service_client
from app.core.constants import RESOURCES
from app.core.dsfs_catalog import ACTIONS, SCOPES
from app.core.service_scopes import SERVICE_SCOPES

router = APIRouter(tags=["Meta"])


@router.get("/health", summary="Liveness check (no credentials needed)")
def health():
    return {"status": "ok", "api_version": "1"}


@router.get("/catalog", summary="Resources, actions and scopes this service understands")
def catalog(_client=Depends(get_service_client)):
    return {
        "resources": RESOURCES,
        "actions": ACTIONS,
        "role_scopes": SCOPES,
        "client_scopes": SERVICE_SCOPES,
        "context_fields": {
            "school_id": "Needed for school-scoped roles (Teacher, School Administrator, School Staff)",
            "organization_id": "Needed for organisation-scoped roles (Supplier)",
            "department": "Needed for department-scoped roles (Manager)",
            "owner_id": "user_id that owns the record; used by 'own'-scoped roles",
            "student_id": "External student id; Parent/Guardian is allowed only for linked students",
        },
    }