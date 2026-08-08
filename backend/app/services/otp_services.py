import random
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from sqlalchemy.orm import Session
from app.models.otp import OTPCode
from app.core.config import settings


def generate_and_send_otp(db: Session, user_id: int, recipient_email: str) -> bool:
    code = str(random.randint(100000, 999999))
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
    except Exception as e:
        print(f"OTP email failed: {e}")
        return False


def verify_otp(db: Session, user_id: int, entered_code: str) -> bool:
    record = (
        db.query(OTPCode)
        .filter_by(user_id=user_id, used=False)
        .order_by(OTPCode.created_at.desc())
        .first()
    )
    if record is None:
        return False
    if datetime.now(timezone.utc) > record.expires_at.replace(tzinfo=timezone.utc):
        return False
    if entered_code.strip() != record.code:
        return False

    record.used = True
    db.commit()
    return True