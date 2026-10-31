"""
Idempotent schema upgrades for the DSFS work.

The app creates tables with Base.metadata.create_all, which never adds columns
to tables that already exist. This module adds new columns/indexes with
`IF NOT EXISTS`, so it is safe to run on every startup and on any database
(fresh, or one created before these changes).

Callers must ensure the base tables exist first (main.py runs create_all
before calling this).
"""

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.db.database import Base
from app.models.guardian import GuardianLink

logger = logging.getLogger(__name__)

_SCHEMA_STATEMENTS = [
    "ALTER TABLE roles ADD COLUMN IF NOT EXISTS scope VARCHAR(20) NOT NULL DEFAULT 'own'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS school_id VARCHAR(50)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id VARCHAR(50)",
    "CREATE INDEX IF NOT EXISTS ix_users_school_id ON users (school_id)",
    # Original roles: give them their documented scopes. Only touches rows still
    # at the column default, so it never overrides a later deliberate change.
    "UPDATE roles SET scope = 'global' WHERE role_name = 'Administrator' AND scope = 'own'",
    "UPDATE roles SET scope = 'department' WHERE role_name = 'Manager' AND scope = 'own'",
    # Component-level audit log
    "ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS component VARCHAR(60)",
    "ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS endpoint VARCHAR(200)",
    # Adaptive thresholds and cold start on each alert
    "ALTER TABLE anomaly_alerts ADD COLUMN IF NOT EXISTS threshold_used DOUBLE PRECISION",
    "ALTER TABLE anomaly_alerts ADD COLUMN IF NOT EXISTS risk_tier VARCHAR(20)",
    "ALTER TABLE anomaly_alerts ADD COLUMN IF NOT EXISTS is_learning BOOLEAN",
    "ALTER TABLE anomaly_alerts ADD COLUMN IF NOT EXISTS prior_sessions INTEGER",
    # Live (mid-session) detection. The live_alerts, denied_attempts and live_session_scores
    # tables come from create_all; these cover databases created before them.
    "ALTER TABLE notifications ADD COLUMN IF NOT EXISTS live_alert_id INTEGER REFERENCES live_alerts(id)",
    "CREATE INDEX IF NOT EXISTS ix_access_logs_session_time ON access_logs (session_id, access_timestamp)",
    # Audit detail for administrative changes (role grant/revoke/delete)
    "ALTER TABLE access_logs ADD COLUMN IF NOT EXISTS details VARCHAR(300)",
]


def apply_dsfs_pass1_schema(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine, tables=[GuardianLink.__table__])
    with engine.begin() as conn:
        for statement in _SCHEMA_STATEMENTS:
            conn.execute(text(statement))
    logger.info("DSFS schema is up to date.")
