from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.rbac import get_current_user_and_session
from app.models.notification import Notification
from app.schemas.notification import NotificationOut, UnreadCountOut

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("", response_model=List[NotificationOut])
def list_notifications(
    unread_only: bool = False,
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    user, _ = current
    query = db.query(Notification).filter(Notification.user_id == user.user_id)
    if unread_only:
        query = query.filter(Notification.is_read.is_(False))
    return query.order_by(Notification.created_at.desc()).limit(50).all()


@router.get("/unread-count", response_model=UnreadCountOut)
def unread_count(
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    user, _ = current
    count = (
        db.query(Notification)
        .filter(Notification.user_id == user.user_id, Notification.is_read.is_(False))
        .count()
    )
    return UnreadCountOut(unread_count=count)


@router.post("/{notification_id}/read", response_model=NotificationOut)
def mark_read(
    notification_id: int,
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    user, _ = current
    notif = (
        db.query(Notification)
        .filter(Notification.notification_id == notification_id, Notification.user_id == user.user_id)
        .first()
    )
    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.is_read = True
    db.commit()
    db.refresh(notif)
    return notif


@router.post("/read-all")
def mark_all_read(
    current=Depends(get_current_user_and_session),
    db: Session = Depends(get_db),
):
    user, _ = current
    db.query(Notification).filter(
        Notification.user_id == user.user_id, Notification.is_read.is_(False)
    ).update({"is_read": True})
    db.commit()
    return {"status": "ok"}