"""Stored secrets: one-time codes and tokens are kept only as hashes; face templates are encrypted."""
import json
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType

import pytest
from cryptography.fernet import Fernet

# The auth routes import biometric_service (OpenCV/DeepFace); CI does not install them (see test_auth_hardening).
try:
    import cv2  # noqa: F401
except ImportError:
    sys.modules.setdefault("app.services.biometric_service", ModuleType("app.services.biometric_service"))

from app.api.routes import auth
from app.core import crypto
from app.db.migrations import protect_stored_secrets
from app.models.biometric import BiometricEnrollment
from app.models.otp import OTPCode
from app.services import otp_service

TEMPLATE = [0.125, -0.5, 0.75, 1.0]


@pytest.fixture(autouse=True)
def fresh_key_cache():
    crypto._keys.cache_clear()
    yield
    crypto._keys.cache_clear()


# --- hashing ---------------------------------------------------------------------------------------

def test_hash_is_keyed_fixed_length_and_not_the_secret():
    h = crypto.hash_token("123456")
    assert len(h) == 64 and crypto.is_token_hash(h)
    assert h == crypto.hash_token("123456") and h != crypto.hash_token("123457")
    assert "123456" not in h
    assert crypto.token_matches("123456", h) and not crypto.token_matches("654321", h)


def test_plain_values_are_not_mistaken_for_hashes():
    assert not crypto.is_token_hash("123456")
    assert not crypto.is_token_hash("Xy3-k9_" * 6)          # a token_urlsafe(32)-style value
    assert not crypto.is_token_hash(None)


# --- emailed codes -----------------------------------------------------------------------------------

class _FakeSMTP:
    sent = []

    def __init__(self, *a, **k): pass
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self): pass
    def login(self, *a): pass
    def sendmail(self, _from, _to, message): _FakeSMTP.sent.append(message)


def test_emailed_code_is_stored_only_as_a_hash_and_still_works(db, make_user, monkeypatch):
    monkeypatch.setattr(otp_service.smtplib, "SMTP", _FakeSMTP)
    _FakeSMTP.sent.clear()
    user = make_user()

    assert otp_service.generate_and_send_otp(db, user.user_id, user.email)

    code = next(line.split(": ")[1].strip() for line in _FakeSMTP.sent[0].splitlines()
                if line.startswith("Your verification code is"))
    stored = db.query(OTPCode).filter_by(user_id=user.user_id).one().code
    assert stored != code and crypto.is_token_hash(stored)
    assert otp_service.verify_otp(db, user.user_id, code)


# --- password-setup and reset tokens -----------------------------------------------------------------

def test_setup_link_works_while_the_database_holds_only_its_hash(db, make_user):
    user = make_user()
    user.password_set = False
    user.password_setup_token = crypto.hash_token("setup-link-token")
    user.password_setup_expires = datetime.utcnow() + timedelta(hours=1)
    db.commit()

    result = auth.setup_password(auth.SetupPasswordRequest(token="setup-link-token", new_password="New#Pass123"), db)

    assert result["status"] == "password_set"
    db.refresh(user)
    assert user.password_set and user.password_setup_token is None


def test_the_stored_hash_itself_does_not_work_as_a_link(db, make_user):
    """Someone who reads the database gets the hash, which is useless as a setup link."""
    user = make_user()
    stored = crypto.hash_token("setup-link-token")
    user.password_setup_token = stored
    user.password_setup_expires = datetime.utcnow() + timedelta(hours=1)
    db.commit()

    with pytest.raises(auth.HTTPException):
        auth.setup_password(auth.SetupPasswordRequest(token=stored, new_password="New#Pass123"), db)


def test_reset_token_is_stored_as_a_hash_and_the_emailed_one_works(db, make_user, monkeypatch):
    emailed = []
    monkeypatch.setattr(auth.password_reset_service, "send_reset_email", lambda u, t: emailed.append(t) or True)
    user = make_user()

    auth.forgot_password(auth.ForgotPasswordRequest(email=user.email), db)

    db.refresh(user)
    assert user.password_reset_token == crypto.hash_token(emailed[0]) != emailed[0]
    auth.reset_password(auth.ResetPasswordRequest(token=emailed[0], new_password="New#Pass123"), db)
    db.refresh(user)
    assert user.password_reset_token is None


# --- face templates ----------------------------------------------------------------------------------

def test_template_round_trip_and_ciphertext_reveals_nothing():
    stored = crypto.encrypt_template(TEMPLATE)
    assert crypto.is_encrypted_template(stored)
    assert "0.125" not in stored and not stored.startswith("[")
    assert crypto.decrypt_template(stored) == TEMPLATE


def test_templates_saved_before_encryption_are_still_read():
    legacy = json.dumps(TEMPLATE)
    assert not crypto.is_encrypted_template(legacy)
    assert crypto.decrypt_template(legacy) == TEMPLATE


def test_a_template_from_an_unknown_key_is_refused(monkeypatch):
    monkeypatch.setattr(crypto.settings, "BIOMETRIC_ENCRYPTION_KEY", Fernet.generate_key().decode())
    crypto._keys.cache_clear()
    stored = crypto.encrypt_template(TEMPLATE)
    monkeypatch.setattr(crypto.settings, "BIOMETRIC_ENCRYPTION_KEY", Fernet.generate_key().decode())
    crypto._keys.cache_clear()
    with pytest.raises(ValueError):
        crypto.decrypt_template(stored)


def test_adding_a_dedicated_key_later_never_forces_re_enrolment(db, make_user, monkeypatch):
    """Templates encrypted with the key derived from SECRET_KEY are still read after a dedicated key is
    configured, and the startup conversion moves them to the new key."""
    user = make_user()
    db.add(BiometricEnrollment(user_id=user.user_id, embedding=crypto.encrypt_template(TEMPLATE)))
    db.commit()
    key = Fernet.generate_key()
    monkeypatch.setattr(crypto.settings, "BIOMETRIC_ENCRYPTION_KEY", key.decode())
    crypto._keys.cache_clear()

    stored = db.query(BiometricEnrollment).filter_by(user_id=user.user_id).one().embedding
    assert crypto.decrypt_template(stored) == TEMPLATE and crypto.needs_rotation(stored)

    assert protect_stored_secrets(db.get_bind())["rotated_templates"] == 1
    db.expire_all()
    rotated = db.query(BiometricEnrollment).filter_by(user_id=user.user_id).one().embedding
    assert json.loads(Fernet(key).decrypt(rotated.encode())) == TEMPLATE
    assert protect_stored_secrets(db.get_bind())["rotated_templates"] == 0


def test_a_dedicated_key_is_used_when_configured(monkeypatch):
    key = Fernet.generate_key()
    monkeypatch.setattr(crypto.settings, "BIOMETRIC_ENCRYPTION_KEY", key.decode())
    crypto._keys.cache_clear()
    stored = crypto.encrypt_template(TEMPLATE)
    assert json.loads(Fernet(key).decrypt(stored.encode())) == TEMPLATE


# --- converting existing data --------------------------------------------------------------------------

def test_existing_plain_secrets_are_converted_once_and_keep_working(db, make_user):
    user = make_user()
    user.password_set = False
    user.password_setup_token = "legacy-setup-token-sent-before-upgrade"
    user.password_setup_expires = datetime.utcnow() + timedelta(hours=1)
    db.add(BiometricEnrollment(user_id=user.user_id, embedding=json.dumps(TEMPLATE), model_name="Facenet512"))
    db.add(OTPCode(user_id=user.user_id, code="246810", used=False,
                   expires_at=datetime.now(timezone.utc) + timedelta(minutes=5)))
    db.commit()

    first = protect_stored_secrets(db.get_bind())
    second = protect_stored_secrets(db.get_bind())

    assert first == {"face_templates": 1, "rotated_templates": 0, "codes": 1, "setup_tokens": 1, "reset_tokens": 0}
    assert not any(second.values())
    db.expire_all()
    enrolment = db.query(BiometricEnrollment).filter_by(user_id=user.user_id).one()
    assert crypto.is_encrypted_template(enrolment.embedding)
    assert crypto.decrypt_template(enrolment.embedding) == TEMPLATE
    assert otp_service.verify_otp(db, user.user_id, "246810")              # a code already emailed still works
    result = auth.setup_password(
        auth.SetupPasswordRequest(token="legacy-setup-token-sent-before-upgrade", new_password="New#Pass123"), db)
    assert result["status"] == "password_set"                               # so does a link already emailed


# --- Face ID end to end (needs OpenCV/DeepFace: runs in the Docker image, skipped in CI) ---------------

def test_face_id_enrols_encrypted_and_still_matches(db, make_user, monkeypatch):
    pytest.importorskip("cv2")
    from app.services import biometric_service as bio

    monkeypatch.setattr(bio, "decode_base64_image", lambda image: object())
    monkeypatch.setattr(bio, "check_liveness", lambda frame: True)
    monkeypatch.setattr(bio, "extract_embedding", lambda image: list(TEMPLATE))
    user = make_user()

    ok, _ = bio.enroll_face(db, user.user_id, "image")
    stored = db.query(BiometricEnrollment).filter_by(user_id=user.user_id).one().embedding

    assert ok and crypto.is_encrypted_template(stored)
    assert bio.verify_face(db, user.user_id, "image")
    monkeypatch.setattr(bio, "extract_embedding", lambda image: [-x for x in TEMPLATE])   # a different face
    assert not bio.verify_face(db, user.user_id, "image")
