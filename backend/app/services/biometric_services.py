import json
import base64
import numpy as np
import cv2
from deepface import DeepFace
from sqlalchemy.orm import Session
from app.models.biometric import BiometricEnrollment
from app.core.config import settings  # adjust import to match your config pattern


def decode_base64_image(image_b64: str):
    """Convert a base64 string (from the client) into an OpenCV image."""
    img_bytes = base64.b64decode(image_b64)
    np_arr = np.frombuffer(img_bytes, np.uint8)
    return cv2.imdecode(np_arr, cv2.IMREAD_COLOR)


def extract_embedding(image_b64: str):
    """Run face detection + embedding extraction. Returns None if no face found."""
    frame = decode_base64_image(image_b64)
    try:
        result = DeepFace.represent(
            img_path=frame,
            model_name=settings.BIOMETRIC_MODEL,
            detector_backend=settings.BIOMETRIC_DETECTOR,
            enforce_detection=True
        )
        return result[0]["embedding"]
    except ValueError:
        return None


def cosine_distance(a, b):
    a, b = np.array(a), np.array(b)
    return 1 - (np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def enroll_face(db: Session, user_id: int, image_b64: str) -> bool:
    embedding = extract_embedding(image_b64)
    if embedding is None:
        return False

    existing = db.query(BiometricEnrollment).filter_by(user_id=user_id).first()
    if existing:
        existing.embedding = json.dumps(embedding)
    else:
        db.add(BiometricEnrollment(user_id=user_id, embedding=json.dumps(embedding)))

    db.commit()
    return True


def verify_face(db: Session, user_id: int, image_b64: str) -> bool:
    enrollment = db.query(BiometricEnrollment).filter_by(user_id=user_id).first()
    if enrollment is None:
        return False

    live_embedding = extract_embedding(image_b64)
    if live_embedding is None:
        return False

    stored_embedding = json.loads(enrollment.embedding)
    distance = cosine_distance(stored_embedding, live_embedding)
    return distance <= settings.BIOMETRIC_DISTANCE_THRESHOLD