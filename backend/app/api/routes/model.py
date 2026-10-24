"""Model management: versions, drift, retrain, promote/rollback. Global-scope administrators only."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.visibility import visibility_scope
from app.db.database import get_db
from app.models.user import User
from app.services import model_registry_service as registry

router = APIRouter(prefix="/api/model", tags=["model"])


def _require_global_scope(user: User) -> None:
    if visibility_scope(user)["level"] != "all":
        raise HTTPException(
            status_code=403,
            detail="Model management is limited to administrators with programme-wide (global) scope.",
        )


@router.get("/status")
def model_status(
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    _require_global_scope(current_user)
    return registry.get_status(db)


@router.post("/retrain")
def retrain_model(
    current_user: User = Depends(require_permission("dashboard", "write")),
    db: Session = Depends(get_db),
):
    _require_global_scope(current_user)
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
):
    _require_global_scope(current_user)
    try:
        return registry.promote_version(version_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Model version not found")
    except registry.PromotionRefused as e:
        raise HTTPException(status_code=400, detail=str(e))
    except registry.RetrainInProgress as e:
        raise HTTPException(status_code=409, detail=str(e))