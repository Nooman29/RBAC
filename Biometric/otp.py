import random
import smtplib
import time
from email.mime.text import MIMEText
from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, OTP_EXPIRY_SECONDS

# In-memory store: {user_id: {"code": "123456", "expires_at": timestamp}}
# NOTE: this resets if the app restarts — fine for this prototype phase,
# will move to the database during integration (3.3.5).
_otp_store = {}


def generate_otp(user_id, recipient_email):
    """Generate a 6-digit OTP, store it with an expiry, and email it."""
    code = str(random.randint(100000, 999999))
    expires_at = time.time() + OTP_EXPIRY_SECONDS

    _otp_store[user_id] = {"code": code, "expires_at": expires_at}

    subject = "Your Verification Code"
    body = f"Your one-time verification code is: {code}\n\nThis code expires in {OTP_EXPIRY_SECONDS // 60} minutes."

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, recipient_email, msg.as_string())
        print(f"OTP sent to {recipient_email}.")
        return True
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
        return False


def verify_otp(user_id, entered_code):
    """Check the entered code against the stored one, respecting expiry."""
    record = _otp_store.get(user_id)

    if record is None:
        print("No OTP was generated for this user.")
        return False

    if time.time() > record["expires_at"]:
        print("OTP has expired.")
        del _otp_store[user_id]
        return False

    if entered_code.strip() == record["code"]:
        print("OTP verified successfully.")
        del _otp_store[user_id]  # one-time use — invalidate after success
        return True
    else:
        print("Incorrect OTP.")
        return False


if __name__ == "__main__":
    user_id = input("Enter user ID: ").strip()
    email = input("Enter email to send OTP to: ").strip()

    if generate_otp(user_id, email):
        entered = input("Enter the OTP you received: ").strip()
        result = verify_otp(user_id, entered)
        print(f"\nResult: {'ACCESS GRANTED' if result else 'ACCESS DENIED'}")