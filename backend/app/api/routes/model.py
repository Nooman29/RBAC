"""Model management: versions, drift, retrain, promote/rollback. Global-scope administrators only."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.rbac import require_permission, get_current_user_and_session
from app.core.visibility import visibility_scope
from app.db.database import get_db
from app.models.user import User
from app.services import model_registry_service as registry
from app.services import live_detection_service

router = APIRouter(prefix="/api/model", tags=["model"])


def _require_global_scope(user: User, db: Session, current, action: str, endpoint: str) -> None:
    if visibility_scope(user)["level"] != "all":
        # Refused like any other out-of-scope request, so live detection (R1) counts it.
        live_detection_service.on_denied(db, current[1], "dashboard", action, endpoint=endpoint, reason="visibility")
        raise HTTPException(
            status_code=403,
            detail="Model management is limited to administrators with programme-wide (global) scope.",
        )


@router.get("/status")
def model_status(
    current_user: User = Depends(require_permission("dashboard", "read")),
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    _require_global_scope(current_user, db, current, "read", "GET /api/model/status")
    return registry.get_status(db)


@router.post("/retrain")
def retrain_model(
    current_user: User = Depends(require_permission("dashboard", "write")),
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    _require_global_scope(current_user, db, current, "write", "POST /api/model/retrain")
    try:
        return registry.train_candidate(db, triggered_by=current_user.username, promote=True)
    except registry.RetrainInProgress as e:
        raise HTTPException(status_code=409, detail=str(e))
    except registry.NotEnoughData as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/versions/{version_id}/promote")
def promote_model_version(
    version_id: str,
    current_user: User = Depends(require_permission("dashboard", "write")),
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    _require_global_scope(current_user, db, current, "write", f"POST /api/model/versions/{version_id}/promote")
    try:
        return registry.promote_version(version_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Model version not found")
    except registry.PromotionRefused as e:
        raise HTTPException(status_code=400, detail=str(e))
    except registry.RetrainInProgress as e:
        raise HTTPException(status_code=409, detail=str(e))
