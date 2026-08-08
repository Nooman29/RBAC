import os
import json
import numpy as np
from config import ENROLLED_FACES_DIR

os.makedirs(ENROLLED_FACES_DIR, exist_ok=True)

def _user_path(user_id):
    return os.path.join(ENROLLED_FACES_DIR, f"{user_id}.json")

def save_embedding(user_id, embedding):
    """Store a user's face embedding as JSON (list of floats)."""
    data = {
        "user_id": user_id,
        "embedding": np.array(embedding).tolist()
    }
    with open(_user_path(user_id), "w") as f:
        json.dump(data, f)
    print(f"Saved embedding for user '{user_id}'.")

def load_embedding(user_id):
    """Load a single user's embedding. Returns None if not enrolled."""
    path = _user_path(user_id)
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        data = json.load(f)
    return np.array(data["embedding"])

def load_all_embeddings():
    """Load every enrolled user's embedding as {user_id: np.array}."""
    result = {}
    for fname in os.listdir(ENROLLED_FACES_DIR):
        if fname.endswith(".json"):
            user_id = fname[:-5]
            result[user_id] = load_embedding(user_id)
    return result

def is_enrolled(user_id):
    return os.path.exists(_user_path(user_id))

def delete_embedding(user_id):
    path = _user_path(user_id)
    if os.path.exists(path):
        os.remove(path)
        print(f"Deleted embedding for user '{user_id}'.")
        return True
    return False