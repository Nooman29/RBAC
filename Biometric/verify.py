import cv2
import numpy as np
from deepface import DeepFace
from config import VERIFICATION_MODEL, DETECTOR_BACKEND, DISTANCE_THRESHOLD
from store import load_embedding, load_all_embeddings

def capture_face_frame(window_title="Verification - Press 'c' to capture"):
    cap = cv2.VideoCapture(0, cv2.CAP_DSHOW)

    if not cap.isOpened():
        print("ERROR: Could not open webcam.")
        return None

    print("Position your face in frame. Press 'c' to capture, 'q' to cancel.")
    captured_frame = None

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            print("Failed to grab frame.")
            break

        cv2.imshow(window_title, frame)
        key = cv2.waitKey(1) & 0xFF

        if key == ord('c'):
            captured_frame = frame.copy()
            break
        elif key == ord('q'):
            print("Verification cancelled.")
            break

    cap.release()
    cv2.destroyAllWindows()
    return captured_frame


def get_embedding(frame):
    """Extract a face embedding from a captured frame. Returns None if no face found."""
    try:
        result = DeepFace.represent(
            img_path=frame,
            model_name=VERIFICATION_MODEL,
            detector_backend=DETECTOR_BACKEND,
            enforce_detection=True
        )
        return np.array(result[0]["embedding"])
    except ValueError as e:
        print(f"No face detected: {e}")
        return None


def cosine_distance(a, b):
    """0 = identical, 1 = orthogonal/unrelated. Standard metric for face embeddings."""
    a, b = np.array(a), np.array(b)
    return 1 - (np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def verify_against_user(user_id):
    """1:1 verification — does the live face match THIS specific enrolled user?"""
    enrolled = load_embedding(user_id)
    if enrolled is None:
        print(f"No enrollment found for user '{user_id}'.")
        return False, None

    frame = capture_face_frame()
    if frame is None:
        return False, None

    live_embedding = get_embedding(frame)
    if live_embedding is None:
        return False, None

    distance = cosine_distance(enrolled, live_embedding)
    match = distance <= DISTANCE_THRESHOLD

    print(f"Distance: {distance:.4f} (threshold: {DISTANCE_THRESHOLD}) -> {'MATCH' if match else 'NO MATCH'}")
    return match, distance


def identify_user():
    """1:N identification — whose face is this, out of everyone enrolled?"""
    all_embeddings = load_all_embeddings()
    if not all_embeddings:
        print("No users enrolled yet.")
        return None, None

    frame = capture_face_frame(window_title="Identification - Press 'c' to capture")
    if frame is None:
        return None, None

    live_embedding = get_embedding(frame)
    if live_embedding is None:
        return None, None

    best_user, best_distance = None, float("inf")
    for user_id, embedding in all_embeddings.items():
        distance = cosine_distance(embedding, live_embedding)
        if distance < best_distance:
            best_distance = distance
            best_user = user_id

    if best_distance <= DISTANCE_THRESHOLD:
        print(f"Identified as '{best_user}' (distance: {best_distance:.4f})")
        return best_user, best_distance
    else:
        print(f"No match found (closest was '{best_user}' at distance {best_distance:.4f}, above threshold)")
        return None, best_distance


if __name__ == "__main__":
    mode = input("Verify against specific user (v) or identify from all enrolled (i)? ").strip().lower()

    if mode == "v":
        user_id = input("Enter user ID to verify against: ").strip()
        match, distance = verify_against_user(user_id)
        print(f"\nResult: {'ACCESS GRANTED' if match else 'ACCESS DENIED'}")
    elif mode == "i":
        user_id, distance = identify_user()
        print(f"\nResult: {'ACCESS GRANTED as ' + user_id if user_id else 'ACCESS DENIED'}")
    else:
        print("Invalid choice.")