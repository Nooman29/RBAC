import csv
import io
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

# Reuse the exact visibility rules of the dashboard (admin: all, manager: department, others: self).
from app.api.routes.dashboard import _apply_visibility, _visibility_scope
from app.core.components import KNOWN_COMPONENTS, UI_EVENTS
from app.core.rbac import get_current_user_and_session, require_permission
from app.db.database import get_db
from app.models.session import AccessLog, UserSession
from app.models.ui_event import UiEvent
from app.models.user import User
from app.schemas.audit import AuditEntryOut

router = APIRouter(prefix="/api/audit", tags=["audit"])

PREVIEW_LIMIT = 500
EXPORT_LIMIT = 50000


def _collect(
    db: Session,
    scope: dict,
    start_date: Optional[datetime],
    end_date: Optional[datetime],
    user_ids: Optional[List[int]],
    components: Optional[List[str]],
    source: Optional[str],
    limit: int,
) -> List[AuditEntryOut]:
    entries: List[AuditEntryOut] = []

    if source in (None, "", "api"):
        query = (
            db.query(AccessLog, User)
            .join(UserSession, AccessLog.session_id == UserSession.session_id)
            .join(User, UserSession.user_id == User.user_id)
        )
        query = _apply_visibility(query, scope)
        if start_date:
            query = query.filter(AccessLog.access_timestamp >= start_date)
        if end_date:
            query = query.filter(AccessLog.access_timestamp <= end_date)
        if user_ids:
            query = query.filter(UserSession.user_id.in_(user_ids))
        if components:
            query = query.filter(func.coalesce(AccessLog.component, "Other").in_(components))
        for log, user in query.order_by(AccessLog.access_timestamp.desc()).limit(limit).all():
            entries.append(
                AuditEntryOut(
                    entry_id=f"api-{log.log_id}",
                    timestamp=log.access_timestamp,
                    username=user.username,
                    department=user.department,
                    session_id=log.session_id,
                    component=log.component or "Other",
                    resource_name=log.resource_name,
                    action_performed=log.action_performed,
                    endpoint=log.endpoint,
                    source="api",
                )
            )

    if source in (None, "", "ui"):
        query = db.query(UiEvent, User).join(User, UiEvent.user_id == User.user_id)
        query = _apply_visibility(query, scope)
        if start_date:
            query = query.filter(UiEvent.created_at >= start_date)
        if end_date:
            query = query.filter(UiEvent.created_at <= end_date)
        if user_ids:
            query = query.filter(UiEvent.user_id.in_(user_ids))
        if components:
            query = query.filter(UiEvent.component.in_(components))
        for event, user in query.order_by(UiEvent.created_at.desc()).limit(limit).all():
            entries.append(
                AuditEntryOut(
                    entry_id=f"ui-{event.id}",
                    timestamp=event.created_at,
                    username=user.username,
                    department=user.department,
                    session_id=event.session_id,
                    component=event.component,
                    resource_name=None,
                    action_performed=event.action,
                    endpoint=None,
                    source="ui",
                )
            )

    entries.sort(key=lambda e: e.timestamp, reverse=True)
    return entries[:limit]


@router.get("/components", response_model=List[str])
def list_components(
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    """Component names to offer as filters: the known ones plus any seen in the data (e.g. 'Module: Payments')."""
    names = set(KNOWN_COMPONENTS) | {"Other"}
    names.update(c for (c,) in db.query(AccessLog.component).filter(AccessLog.component.isnot(None)).distinct().all())
    names.update(c for (c,) in db.query(UiEvent.component).distinct().all())
    return sorted(names)


@router.get("/preview", response_model=List[AuditEntryOut])
def preview_audit(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_ids: Optional[List[int]] = Query(None),
    components: Optional[List[str]] = Query(None),
    source: Optional[str] = Query(None, pattern="^(api|ui)$"),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)
    return _collect(db, scope, start_date, end_date, user_ids, components, source, PREVIEW_LIMIT)


@router.get("/export")
def export_audit(
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    user_ids: Optional[List[int]] = Query(None),
    components: Optional[List[str]] = Query(None),
    source: Optional[str] = Query(None, pattern="^(api|ui)$"),
    current_user: User = Depends(require_permission("dashboard", "read")),
    db: Session = Depends(get_db),
):
    scope = _visibility_scope(current_user)
    entries = _collect(db, scope, start_date, end_date, user_ids, components, source, EXPORT_LIMIT)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "timestamp", "username", "department", "session_id", "source",
        "component", "resource_name", "action_performed", "endpoint",
    ])
    for e in entries:
        writer.writerow([
            e.timestamp.isoformat(), e.username, e.department or "", e.session_id or "", e.source,
            e.component, e.resource_name or "", e.action_performed, e.endpoint or "",
        ])

    filename = f"audit_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


class UiEventIn(BaseModel):
    component: str
    action: str


@router.post("/ui-event", status_code=201)
def record_ui_event(
    payload: UiEventIn,
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    """
    The frontend reports meaningful interface actions that are not API calls (for example opening
    the notification bell). Only a fixed list is accepted, so this cannot be used to write
    arbitrary text into the audit log. Never called for polling.
    """
    allowed_actions = UI_EVENTS.get(payload.component)
    if allowed_actions is None or payload.action not in allowed_actions:
        raise HTTPException(status_code=422, detail="Unknown interface event.")

    user, session_id = current

    # Ignore an identical event within two seconds (double clicks).
    recent = (
        db.query(UiEvent.id)
        .filter(
            UiEvent.user_id == user.user_id,
            UiEvent.component == payload.component,
            UiEvent.action == payload.action,
            UiEvent.created_at >= datetime.utcnow() - timedelta(seconds=2),
        )
        .first()
    )
    if recent is None:
        db.add(UiEvent(user_id=user.user_id, session_id=session_id, component=payload.component, action=payload.action))
        db.commit()
    return {"status": "recorded"}