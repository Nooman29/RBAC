"""
Fan-out for anomaly alerts: creates in-app Notification rows for everyone who can act on
the alert and emails them, reusing the same SMTP pattern as otp_service.
Called from anomaly_service.score_session() the moment is_anomaly=True.

Who is told is decided by permission and scope, never by role name (see _alert_recipients),
so a custom or DSFS role given the right permission is covered the same way as Administrator.

Live (mid-session) alerts use notify_live_alert: in-app only, because an SMTP round trip
inside the request that triggered the check would slow that request down.
"""

from __future__ import annotations

import json
import logging
import smtplib
from email.mime.text import MIMEText
from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.models.user import User
from app.models.role import Role, Permission
from app.models.notification import Notification
from app.models.anomaly import AnomalyAlert
from app.models.live_alert import LiveAlert
from app.core.visibility import in_scope, visibility_scope

logger = logging.getLogger(__name__)


def _alert_recipients(db: DBSession, flagged_user: Optional[User]) -> list[User]:
    """
    Everyone who can act on an alert about flagged_user: users holding dashboard:write (the
    permission that allows reviewing alerts and terminating sessions) whose visibility scope
    covers the flagged user. The flagged user is never told about their own alert, so a
    compromised account cannot see or act on the warning about itself.

    If the flagged user no longer exists, only global-scope users are told.
    """
    candidates = (
        db.query(User)
        .join(User.roles)
        .join(Role.permissions)
        .filter(Permission.resource_name == "dashboard", Permission.action_type == "write")
        .distinct()
        .all()
    )
    if flagged_user is None:
        return [u for u in candidates if visibility_scope(u)["level"] == "all"]
    return [
        u for u in candidates
        if u.user_id != flagged_user.user_id and in_scope(flagged_user, visibility_scope(u))
    ]


def _format_email_body(admin: User, alert: AnomalyAlert) -> str:
    session = alert.session
    user = session.user if session else None
    username = user.username if user else "unknown"

    top_features = []
    if alert.shap_values_json:
        try:
            contributions = json.loads(alert.shap_values_json)
            top_features = [
                f"  - {c['feature']}: {c['shap_value']:.3f}" for c in contributions[:3]
            ]
        except Exception:
            pass

    link = f"{settings.FRONTEND_URL}/alerts/{alert.alert_id}"

    lines = [
        f"Hi {admin.username},",
        "",
        f"A new anomalous session was flagged for user '{username}'.",
        f"Anomaly score: {alert.anomaly_score:.4f}",
        f"Session ID: {alert.session_id}",
    ]
    if top_features:
        lines.append("Top contributing factors:")
        lines.extend(top_features)
    lines.extend(["", f"Review it here: {link}"])
    return "\n".join(lines)


def _send_alert_email(admin: User, alert: AnomalyAlert) -> bool:
    body = _format_email_body(admin, alert)
    msg = MIMEText(body)
    msg["Subject"] = "Security Alert: Anomalous Session Detected"
    msg["From"] = settings.SMTP_USER
    msg["To"] = admin.email

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, admin.email, msg.as_string())
        return True
    except Exception as e:
        logger.error("Failed to send anomaly alert email to %s: %s", admin.email, e)
        return False


def notify_admins_of_anomaly(db: DBSession, alert: AnomalyAlert) -> None:
    session = alert.session
    flagged_user = session.user if session else None
    username = flagged_user.username if flagged_user else "unknown"

    recipients = _alert_recipients(db, flagged_user)
    if not recipients:
        logger.warning("Nobody can act on anomaly alert_id=%s (no in-scope dashboard:write users).", alert.alert_id)
        return

    for recipient in recipients:
        notification = Notification(
            user_id=recipient.user_id,
            alert_id=alert.alert_id,
            title=f"Anomalous session flagged for {username}",
            body=f"Score {alert.anomaly_score:.4f}. Click to review the flagged session.",
        )
        db.add(notification)

        sent = _send_alert_email(recipient, alert)
        if not sent:
            logger.warning("Anomaly email not sent to user_id=%s but in-app notification was still created.", recipient.user_id)

    db.commit()


def notify_live_alert(db: DBSession, alert: LiveAlert, rule_label: str) -> None:
    session = alert.session
    flagged_user = session.user if session else None
    if flagged_user is None:
        return

    recipients = _alert_recipients(db, flagged_user)
    if not recipients:
        logger.warning("Nobody can act on live_alert_id=%s (no in-scope dashboard:write users).", alert.id)
        return

    for recipient in recipients:
        db.add(
            Notification(
                user_id=recipient.user_id,
                live_alert_id=alert.id,
                title=f"Live alert: {rule_label} ({flagged_user.username})"[:200],
                body=f"{alert.summary}. The session is still active: open Alerts to terminate it.",
            )
        )
    db.commit()
