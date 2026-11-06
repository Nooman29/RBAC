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
from sqlalchemy.orm import Session

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
    # Wrong guesses per emailed code (a code is burned after MAX_OTP_ATTEMPTS)
    "ALTER TABLE otp_codes ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0",
    # Emailed codes are stored as a 64-character hash (protect_stored_secrets below)
    "ALTER TABLE otp_codes ALTER COLUMN code TYPE VARCHAR(64)",
]


def apply_dsfs_pass1_schema(engine: Engine) -> None:
    Base.metadata.create_all(bind=engine, tables=[GuardianLink.__table__])
    with engine.begin() as conn:
        for statement in _SCHEMA_STATEMENTS:
            conn.execute(text(statement))
    logger.info("DSFS schema is up to date.")


def protect_stored_secrets(engine: Engine) -> dict:
    """
    Converts secrets saved before they were protected (app/core/crypto.py): face templates are encrypted
    (or re-encrypted under a newly configured key), and outstanding emailed codes and password-setup/reset tokens are replaced by their hash, so links and
    codes already sent keep working. Rows that are already protected are left alone, so this is safe to run
    on every startup. Returns how many rows of each kind were converted.
    """
    from app.core.crypto import (
        decrypt_template, encrypt_template, hash_token, is_encrypted_template, is_token_hash, needs_rotation,
        rotate_template,
    )
    from app.models.biometric import BiometricEnrollment
    from app.models.otp import OTPCode
    from app.models.user import User

    counts = {"face_templates": 0, "rotated_templates": 0, "codes": 0, "setup_tokens": 0, "reset_tokens": 0}
    with Session(bind=engine) as db:
        for row in db.query(BiometricEnrollment).all():
            if not is_encrypted_template(row.embedding):
                row.embedding = encrypt_template(decrypt_template(row.embedding))
                counts["face_templates"] += 1
            elif needs_rotation(row.embedding):
                # Encrypted with an older key (e.g. before BIOMETRIC_ENCRYPTION_KEY was set): move to the new key.
                try:
                    row.embedding = rotate_template(row.embedding)
                    counts["rotated_templates"] += 1
                except ValueError:
                    logger.error("Face template of user_id=%s cannot be decrypted with any configured key; "
                                 "the user must enrol Face ID again", row.user_id)
        for row in db.query(OTPCode).all():
            if not is_token_hash(row.code):
                row.code = hash_token(row.code)
                counts["codes"] += 1
        for user in db.query(User).filter(
            (User.password_setup_token.isnot(None)) | (User.password_reset_token.isnot(None))
        ).all():
            if user.password_setup_token and not is_token_hash(user.password_setup_token):
                user.password_setup_token = hash_token(user.password_setup_token)
                counts["setup_tokens"] += 1
            if user.password_reset_token and not is_token_hash(user.password_reset_token):
                user.password_reset_token = hash_token(user.password_reset_token)
                counts["reset_tokens"] += 1
        db.commit()
    if any(counts.values()):
        logger.info("Protected stored secrets: %s", counts)
    return counts
