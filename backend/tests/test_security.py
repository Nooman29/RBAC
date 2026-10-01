import pytest
from jose import JWTError

from app.core import security


def test_password_hash_is_salted_and_verifiable():
    hashed = security.hash_password("S3cure!pass")

    assert hashed != "S3cure!pass"
    assert security.hash_password("S3cure!pass") != hashed
    assert security.verify_password("S3cure!pass", hashed)
    assert not security.verify_password("wrong-pass", hashed)


def test_access_token_round_trip_keeps_claims_and_sets_expiry():
    token = security.create_access_token({"sub": "7", "sid": "42"})
    payload = security.decode_access_token(token)

    assert payload["sub"] == "7"
    assert payload["sid"] == "42"
    assert "exp" in payload


def test_tampered_access_token_is_rejected():
    token = security.create_access_token({"sub": "7", "sid": "42"})
    header, body, signature = token.split(".")
    tampered = f"{header}.{body}.{signature[::-1]}"

    with pytest.raises(JWTError):
        security.decode_access_token(tampered)


def test_pending_token_accepts_only_its_own_scope():
    token = security.create_pending_token(5)

    assert security.decode_pending_token(token) == "5"
    assert security.decode_pending_token(token, expected_scope="password_reset") is None


def test_pending_token_rejects_garbage():
    assert security.decode_pending_token("not-a-jwt") is None


def test_access_token_cannot_be_used_as_pending_token():
    access = security.create_access_token({"sub": "5", "sid": "1"})

    assert security.decode_pending_token(access) is None
