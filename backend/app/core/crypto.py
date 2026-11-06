"""
Protection for secrets stored in the database.

One-time secrets (emailed sign-in codes, password-setup and password-reset tokens) only ever need an
EXACT match, so only their keyed hash is stored: someone who can read the database cannot use them.

Face templates cannot be hashed: every camera capture gives slightly different numbers and a sign-in
is accepted when the two templates are CLOSE enough, which a hash cannot tell. They are encrypted
instead (Fernet: AES-128-CBC with an HMAC-SHA256 integrity check) and decrypted only in memory to be
compared.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import settings

logger = logging.getLogger(__name__)

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------- one-time secrets (hashed)

def hash_token(value: str) -> str:
    """HMAC-SHA256 of a one-time code or token, keyed with SECRET_KEY (64 hex characters).
    Changing SECRET_KEY invalidates outstanding codes and links, like it ends every session."""
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), b"one-time-secret:" + value.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def is_token_hash(value: str | None) -> bool:
    """True for a stored hash; False for a value stored in plain text before hashing was added."""
    return bool(value) and bool(_HASH_RE.match(value))


def token_matches(entered: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(entered), stored_hash)


# ---------------------------------------------------------------- face templates (encrypted)

def _derived_key() -> bytes:
    return base64.urlsafe_b64encode(
        hashlib.sha256(b"biometric-template-key:" + settings.SECRET_KEY.encode("utf-8")).digest()
    )


@lru_cache(maxsize=1)
def _keys() -> tuple:
    """(primary Fernet, MultiFernet that also reads older keys). With a dedicated key configured, templates
    encrypted earlier with the key derived from SECRET_KEY can still be read, and are re-encrypted under the
    dedicated key at startup (needs_rotation / rotate_template), so adding a key never forces re-enrolment."""
    dedicated = settings.BIOMETRIC_ENCRYPTION_KEY.strip()
    derived = Fernet(_derived_key())
    if not dedicated:
        logger.warning("BIOMETRIC_ENCRYPTION_KEY is not set; face templates are encrypted with a key derived "
                       "from SECRET_KEY. Set a dedicated key in backend/.env.docker (see .env.docker.example).")
        return derived, MultiFernet([derived])
    primary = Fernet(dedicated.encode("ascii"))
    return primary, MultiFernet([primary, derived])


def _fernet() -> MultiFernet:
    return _keys()[1]


def is_encrypted_template(stored: str | None) -> bool:
    """Templates saved before encryption are a JSON list ("[...]"); encrypted ones are a Fernet token."""
    return bool(stored) and not stored.lstrip().startswith("[")


def encrypt_template(embedding) -> str:
    return _keys()[0].encrypt(json.dumps(list(embedding)).encode("utf-8")).decode("ascii")


def needs_rotation(stored: str) -> bool:
    """An encrypted template the current primary key cannot read (it was encrypted with an older key)."""
    if not is_encrypted_template(stored):
        return False
    try:
        _keys()[0].decrypt(stored.encode("ascii"))
        return False
    except InvalidToken:
        return True


def rotate_template(stored: str) -> str:
    """Re-encrypts a template under the primary key (raises ValueError if no known key can read it)."""
    try:
        return _fernet().rotate(stored.encode("ascii")).decode("ascii")
    except InvalidToken as exc:
        raise ValueError("Face template cannot be decrypted with any configured key") from exc


def decrypt_template(stored: str) -> list:
    """The template as a list of floats. Reads older unencrypted rows too, so nobody has to re-enrol.
    Raises ValueError if the template was encrypted with a different key."""
    if not is_encrypted_template(stored):
        return json.loads(stored)
    try:
        return json.loads(_fernet().decrypt(stored.encode("ascii")))
    except InvalidToken as exc:
        raise ValueError("Face template cannot be decrypted with the configured key") from exc
