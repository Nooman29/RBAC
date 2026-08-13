from app.core.config import settings
from app.services.mailer import send_email


def send_welcome_email(user, setup_token: str) -> bool:
    link = f"{settings.FRONTEND_URL}/setup-password?token={setup_token}"
    role_names = ", ".join(r.role_name for r in user.roles) if user.roles else "no roles assigned yet"

    body = (
        f"Hi {user.username},\n\n"
        f"An account has been created for you on the RBAC Admin platform.\n"
        f"Assigned role(s): {role_names}\n\n"
        f"To activate your account, set your password here:\n{link}\n\n"
        f"This link expires in 48 hours. After setting your password, you'll be asked to "
        f"set up Face ID login (or use an email code if you don't have camera access).\n\n"
        f"If you didn't expect this account, you can ignore this email."
    )
    return send_email(user.email, "Welcome — Set up your account", body)