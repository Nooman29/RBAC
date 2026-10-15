"""
Idempotent schema upgrade for DSFS Pass 1.

The app creates tables with Base.metadata.create_all, which never adds columns
to tables that already exist. This module adds the new columns/index with
`IF NOT EXISTS`, so it is safe to run on every startup and on any database
(fresh, or one created before Pass 1).

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
]


def apply_dsfs_pass1_schema(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine, tables=[GuardianLink.__table__])
    with engine.begin() as conn:
        for statement in _SCHEMA_STATEMENTS:
            conn.execute(text(statement))
    logger.info("DSFS Pass 1 schema is up to date.")