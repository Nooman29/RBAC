from app.core.config import settings
from app.services.mailer import send_email


def send_reset_email(user, reset_token: str) -> bool:
    link = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
    body = (
        f"Hi {user.username},\n\n"
        f"We received a request to reset your password. If this was you, click the link below "
        f"to set a new password:\n{link}\n\n"
        f"This link expires in 1 hour. If you didn't request this, you can safely ignore this email — "
        f"your password will not be changed."
    )
    return send_email(user.email, "Reset your password", body)