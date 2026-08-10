"""
One-off manual test: creates a single deliberately extreme session
(off-hours, unfamiliar IP, heavy write/delete volume) for an existing
user, scores it, and prints the result — so you have a clear "this
should flag as anomalous" data point to compare against normal sessions.

Run from backend/:
    python -m scripts.test_manual_anomaly
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal
from app.models.session import UserSession, AccessLog
from app.models.user import User
from app.services import anomaly_service

db = SessionLocal()
try:
    user = db.query(User).first()
    if not user:
        print("No users found.")
        sys.exit(1)

    login_time = datetime.utcnow().replace(hour=3, minute=0, second=0, microsecond=0)
    duration = 4200  # 70 minutes, long
    session = UserSession(
        user_id=user.user_id,
        login_time=login_time,
        logout_time=login_time + timedelta(seconds=duration),
        session_duration=duration,
        access_location="185.220.101.99",  # unfamiliar IP
    )
    db.add(session)
    db.flush()

    for _ in range(25):
        db.add(AccessLog(
            session_id=session.session_id,
            resource_name="hr_files",
            action_performed="delete",
            access_timestamp=login_time,
        ))
    db.commit()

    print(f"Created extreme test session_id={session.session_id} for user_id={user.user_id}")

    alert = anomaly_service.score_session(db, session.session_id)
    if alert is None:
        print("Scoring returned None — model artifacts may not be loaded.")
    else:
        print(f"anomaly_score={alert.anomaly_score:.4f}  is_anomaly={alert.is_anomaly}")
finally:
    db.close()