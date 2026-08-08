import cv2
from deepface import DeepFace
from config import VERIFICATION_MODEL, DETECTOR_BACKEND
from store import save_embedding

def capture_face_frame():
    """Opens webcam, waits for 'c' to capture a frame, 'q' to cancel."""
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

        cv2.imshow("Enrollment - Press 'c' to capture", frame)
        key = cv2.waitKey(1) & 0xFF

        if key == ord('c'):
            captured_frame = frame.copy()
            break
        elif key == ord('q'):
            print("Enrollment cancelled.")
            break

    cap.release()
    cv2.destroyAllWindows()
    return captured_frame


def enroll_user(user_id):
    """Full enrollment flow: capture face, extract embedding, save it."""
    frame = capture_face_frame()
    if frame is None:
        print("No frame captured. Enrollment aborted.")
        return False

    try:
        result = DeepFace.represent(
            img_path=frame,
            model_name=VERIFICATION_MODEL,
            detector_backend=DETECTOR_BACKEND,
            enforce_detection=True
        )
    except ValueError as e:
        print(f"No face detected in captured frame: {e}")
        return False

    embedding = result[0]["embedding"]
    save_embedding(user_id, embedding)
    return True


if __name__ == "__main__":
    user_id = input("Enter user ID to enroll: ").strip()
    success = enroll_user(user_id)
    if success:
        print(f"Enrollment complete for '{user_id}'.")
    else:
        print(f"Enrollment failed for '{user_id}'.")