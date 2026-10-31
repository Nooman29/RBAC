import logging
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from sqlalchemy.orm import Session
from app.models.otp import OTPCode
from app.core.config import settings

logger = logging.getLogger(__name__)

# Wrong guesses allowed per code. The next wrong guess burns the code, so a new one must be
# requested; with a six-digit code that leaves a guesser about a 1-in-180,000 chance per code.
MAX_OTP_ATTEMPTS = 5


def generate_code() -> str:
    """Six digits from the operating system's secure random source (never `random`)."""
    return f"{secrets.randbelow(900000) + 100000}"


def generate_and_send_otp(db: Session, user_id: str, recipient_email: str) -> bool:
    code = generate_code()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.OTP_EXPIRY_SECONDS)

    db.add(OTPCode(user_id=user_id, code=code, expires_at=expires_at, used=False))
    db.commit()

    msg = MIMEText(f"Your verification code is: {code}\nExpires in {settings.OTP_EXPIRY_SECONDS // 60} minutes.")
    msg["Subject"] = "Your Verification Code"
    msg["From"] = settings.SMTP_USER
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, recipient_email, msg.as_string())
        return True
    except Exception:
        logger.exception("OTP email failed")
        return False


def verify_otp(db: Session, user_id: int, entered_code: str) -> bool:
    record = (
        db.query(OTPCode)
        .filter_by(user_id=user_id, used=False)
        .order_by(OTPCode.created_at.desc(), OTPCode.id.desc())
        .first()
    )
    if record is None:
        return False
    if datetime.now(timezone.utc) > record.expires_at.replace(tzinfo=timezone.utc):
        return False
    if not secrets.compare_digest(entered_code.strip(), record.code):
        record.failed_attempts = (record.failed_attempts or 0) + 1
        if record.failed_attempts >= MAX_OTP_ATTEMPTS:
            record.used = True
        db.commit()
        return False

    record.used = True
    db.commit()
    return True
