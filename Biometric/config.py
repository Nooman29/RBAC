import os
from dotenv import load_dotenv

load_dotenv()

# Face verification
VERIFICATION_MODEL = "Facenet512"   # DeepFace model — good accuracy/speed tradeoff
DISTANCE_THRESHOLD = 0.30           # lower = stricter match; tune during testing
DETECTOR_BACKEND = "retinaface"         # face detector used before embedding

# Storage
ENROLLED_FACES_DIR = "data/enrolled_faces"

# SMTP (OTP fallback)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
OTP_EXPIRY_SECONDS = 300            # 5 minutes