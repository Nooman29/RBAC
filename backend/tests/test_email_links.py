from unittest.mock import Mock

import pytest

from app.core.config import Settings, settings
from app.models.anomaly import AnomalyAlert
from app.models.user import User
from app.services import password_reset_service, welcome_email_service
from app.services.notification_service import _format_email_body


def test_default_frontend_url(monkeypatch):
    monkeypatch.delenv("FRONTEND_URL", raising=False)
    config = Settings(
        _env_file=None,
        DATABASE_URL="sqlite://",
        SECRET_KEY="test-secret",
        SMTP_USER="test@example.com",
        SMTP_PASSWORD="test-password",
    )
    assert config.FRONTEND_URL == "http://127.0.0.1:5173"


@pytest.mark.parametrize(
    "frontend_url", ["http://127.0.0.1:5173", "https://rbac.example.com"]
)
@pytest.mark.parametrize(
    "service,function_name,path",
    [
        (welcome_email_service, "send_welcome_email", "setup-password"),
        (password_reset_service, "send_reset_email", "reset-password"),
    ],
)
def test_account_email_links(
    monkeypatch, frontend_url, service, function_name, path
):
    monkeypatch.setattr(settings, "FRONTEND_URL", frontend_url)
    send_email = Mock(return_value=True)
    monkeypatch.setattr(service, "send_email", send_email)
    user = User(username="test-user", email="test@example.com")

    assert getattr(service, function_name)(user, "test-token") is True

    send_email.assert_called_once()
    recipient, subject, body = send_email.call_args.args
    assert recipient == user.email
    assert f"{frontend_url}/{path}?token=test-token" in body
    assert "localhost" not in body


@pytest.mark.parametrize(
    "frontend_url", ["http://127.0.0.1:5173", "https://rbac.example.com"]
)
def test_anomaly_email_link(monkeypatch, frontend_url):
    monkeypatch.setattr(settings, "FRONTEND_URL", frontend_url)
    admin = User(username="admin", email="admin@example.com")
    alert = AnomalyAlert(alert_id=42, session_id=7, anomaly_score=-0.25)

    body = _format_email_body(admin, alert)

    assert f"Review it here: {frontend_url}/alerts/42" in body
    assert "localhost" not in body
