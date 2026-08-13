import json
import base64
import logging
import numpy as np
import cv2
from deepface import DeepFace
from sqlalchemy.orm import Session
from app.models.biometric import BiometricEnrollment
from app.core.config import settings

logger = logging.getLogger(__name__)


def decode_base64_image(image_b64: str):
    try:
        if "," in image_b64 and image_b64.strip().startswith("data:"):
            image_b64 = image_b64.split(",", 1)[1]
        img_bytes = base64.b64decode(image_b64)
        np_arr = np.frombuffer(img_bytes, np.uint8)
        frame = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        return frame
    except Exception:
        logger.exception("Failed to decode base64 image for biometric processing")
        return None


def check_liveness(frame) -> bool:
    """
    Runs DeepFace's built-in anti-spoofing model (MiniFASNet) on the frame.
    Returns True only if the detected face is classified as real/live.
    A printed photo or a phone/screen held up to the camera should fail this.
    """
    try:
        faces = DeepFace.extract_faces(
            img_path=frame,
            detector_backend=settings.BIOMETRIC_DETECTOR,
            enforce_detection=True,
            anti_spoofing=True,
        )
        if not faces:
            return False
        # extract_faces returns a list of dicts; each has "is_real" when anti_spoofing=True
        return bool(faces[0].get("is_real", False))
    except ValueError:
        logger.info("Biometric: no face detected during liveness check")
        return False
    except Exception:
        logger.exception("Biometric: liveness check failed unexpectedly")
        return False


def extract_embedding(image_b64: str):
    frame = decode_base64_image(image_b64)
    if frame is None:
        logger.warning("Biometric: decoded frame is None (bad base64 or corrupt image)")
        return None

    try:
        result = DeepFace.represent(
            img_path=frame,
            model_name=settings.BIOMETRIC_MODEL,
            detector_backend=settings.BIOMETRIC_DETECTOR,
            enforce_detection=True,
        )
        return result[0]["embedding"]
    except ValueError:
        logger.info("Biometric: no face detected in frame")
        return None
    except Exception:
        logger.exception("Biometric: unexpected error during embedding extraction")
        return None


def cosine_distance(a, b):
    a, b = np.array(a), np.array(b)
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    if denom == 0:
        return 1.0
    return 1 - (np.dot(a, b) / denom)


def enroll_face(db: Session, user_id: int, image_b64: str) -> bool:
    frame = decode_base64_image(image_b64)
    if frame is None:
        return False

    # Require liveness at enrollment too — otherwise someone could enroll
    # a photo of another person and later "verify" with that same photo.
    if not check_liveness(frame):
        logger.info("Biometric: enrollment rejected — liveness check failed for user_id=%s", user_id)
        return False

    embedding = extract_embedding(image_b64)
    if embedding is None:
        return False

    existing = db.query(BiometricEnrollment).filter_by(user_id=user_id).first()
    if existing:
        existing.embedding = json.dumps(embedding)
        existing.model_name = settings.BIOMETRIC_MODEL
    else:
        db.add(BiometricEnrollment(
            user_id=user_id,
            embedding=json.dumps(embedding),
            model_name=settings.BIOMETRIC_MODEL,
        ))

    db.commit()
    logger.info("Biometric: enrollment saved for user_id=%s", user_id)
    return True


def verify_face(db: Session, user_id: int, image_b64: str) -> bool:
    enrollment = db.query(BiometricEnrollment).filter_by(user_id=user_id).first()
    if enrollment is None:
        logger.info("Biometric: verify attempted but no enrollment exists for user_id=%s", user_id)
        return False

    frame = decode_base64_image(image_b64)
    if frame is None:
        return False

    if not check_liveness(frame):
        logger.info("Biometric: verify rejected — liveness check failed for user_id=%s", user_id)
        return False

    live_embedding = extract_embedding(image_b64)
    if live_embedding is None:
        return False

    stored_embedding = json.loads(enrollment.embedding)
    distance = cosine_distance(stored_embedding, live_embedding)
    match = distance <= settings.BIOMETRIC_DISTANCE_THRESHOLD

    logger.info(
        "Biometric: verify user_id=%s distance=%.4f threshold=%.4f -> %s",
        user_id, distance, settings.BIOMETRIC_DISTANCE_THRESHOLD, "MATCH" if match else "NO MATCH",
    )
    return match