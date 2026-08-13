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
    Runs DeepFace's built-in anti-spoofing model (MiniFASNet, PyTorch-based)
    on the frame. Returns True only if the detected face is classified as real/live.
    """
    try:
        faces = DeepFace.extract_faces(
            img_path=frame,
            detector_backend=settings.BIOMETRIC_DETECTOR,
            enforce_detection=True,
            anti_spoofing=True,
        )
        if not faces:
            logger.warning("Biometric: extract_faces returned empty list during liveness check")
            return False
        face_obj = faces[0]
        logger.info(
            "Biometric: liveness is_real=%s antispoof_score=%s",
            face_obj.get("is_real"), face_obj.get("antispoof_score"),
        )
        return bool(face_obj.get("is_real", False))
    except ValueError as e:
        logger.warning("Biometric: liveness ValueError (detector rejected frame): %s", str(e))
        return False
    except Exception as e:
        logger.exception("Biometric: liveness check failed unexpectedly: %s", str(e))
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


def enroll_face(db: Session, user_id: int, image_b64: str) -> tuple[bool, str]:
    frame = decode_base64_image(image_b64)
    if frame is None:
        return False, "Could not read the captured image."

    if not check_liveness(frame):
        return False, "Liveness check failed — make sure your face is well-lit and clearly visible, not a photo or video."

    embedding = extract_embedding(image_b64)
    if embedding is None:
        return False, "No face detected in the frame."

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
    return True, "Enrolled successfully."


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