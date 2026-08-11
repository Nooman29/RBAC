"""
Scores every closed session that doesn't already have an AnomalyAlert.
Useful after seeding synthetic data in bulk (seed_synthetic_data.py inserts
sessions directly, bypassing close_session/score_session, so none of them
are scored yet) — run this afterward to populate anomaly_alerts for demo
purposes.

Run from backend/ (or via docker compose exec backend, see below):
    python -m scripts.score_existing_sessions
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.database import SessionLocal
from app.models.session import UserSession
from app.models.anomaly import AnomalyAlert
from app.services import anomaly_service


def main():
    db = SessionLocal()
    try:
        already_scored = {a.session_id for a in db.query(AnomalyAlert.session_id).all()}
        sessions = (
            db.query(UserSession)
            .filter(UserSession.session_duration.isnot(None))
            .filter(~UserSession.session_id.in_(already_scored) if already_scored else True)
            .all()
        )

        print(f"Found {len(sessions)} unscored closed sessions.")
        scored, flagged = 0, 0
        for s in sessions:
            alert = anomaly_service.score_session(db, s.session_id)
            if alert:
                scored += 1
                if alert.is_anomaly:
                    flagged += 1

        print(f"Scored {scored} sessions. {flagged} flagged as anomalous.")
    finally:
        db.close()


if __name__ == "__main__":
    main()