"""
Fan-out for anomaly alerts: creates in-app Notification rows for every
Administrator and emails them, reusing the same SMTP pattern as otp_service.
Called from anomaly_service.score_session() the moment is_anomaly=True.
"""

from __future__ import annotations

import json
import logging
import smtplib
from email.mime.text import MIMEText

from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.models.user import User
from app.models.role import Role
from app.models.notification import Notification
from app.models.anomaly import AnomalyAlert

logger = logging.getLogger(__name__)


def _get_admin_users(db: DBSession) -> list[User]:
    return (
        db.query(User)
        .join(User.roles)
        .filter(Role.role_name == "Administrator")
        .distinct()
        .all()
    )


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

    admins = _get_admin_users(db)
    if not admins:
        logger.warning("No Administrator users found — anomaly alert_id=%s not delivered.", alert.alert_id)
        return

    for admin in admins:
        notification = Notification(
            user_id=admin.user_id,
            alert_id=alert.alert_id,
            title=f"Anomalous session flagged for {username}",
            body=f"Score {alert.anomaly_score:.4f}. Click to review the flagged session.",
        )
        db.add(notification)

        sent = _send_alert_email(admin, alert)
        if not sent:
            logger.warning("Anomaly email not sent to admin_id=%s but in-app notification was still created.", admin.user_id)

    db.commit()