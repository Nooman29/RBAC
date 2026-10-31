"""Security review fixes: ended sessions, emailed codes, client address, first-time setup, password reset."""
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType, SimpleNamespace

import pytest

# The auth routes import biometric_service, which loads OpenCV and DeepFace. CI installs the light
# requirements-ci.txt without them, so stand in an empty module there. None of these tests use
# Face ID; where OpenCV is installed (the Docker image) the real module is imported as usual.
try:
    import cv2  # noqa: F401
except ImportError:
    sys.modules.setdefault("app.services.biometric_service", ModuleType("app.services.biometric_service"))
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.api.routes import auth
from app.core import rate_limit, rbac
from app.core.security import create_access_token, create_pending_token, decode_pending_token, hash_password
from app.models.otp import OTPCode
from app.models.session import UserSession
from app.services import anomaly_service, otp_service


def _bearer(user, session_id):
    token = create_access_token({"sub": str(user.user_id), "sid": str(session_id)})
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _request(headers=None, peer="172.18.0.5"):
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "POST", "path": "/", "headers": raw, "client": (peer, 5000)})


def _open_session(db, user):
    session = UserSession(user_id=user.user_id, access_location="10.0.0.1")
    db.add(session)
    db.commit()
    return session


def _code(db, user, code="123456", minutes=5):
    record = OTPCode(user_id=user.user_id, code=code, used=False,
                     expires_at=datetime.now(timezone.utc) + timedelta(minutes=minutes))
    db.add(record)
    db.commit()
    return record


# --- ended sessions --------------------------------------------------------------------------------

def test_token_stops_working_after_logout(db, make_user):
    user = make_user()
    session = _open_session(db, user)
    assert rbac.get_current_user_and_session(_bearer(user, session.session_id), db)[1] == session.session_id

    session.logout_time = datetime.utcnow()
    session.session_duration = 60.0
    db.commit()

    with pytest.raises(HTTPException) as exc:
        rbac.get_current_user_and_session(_bearer(user, session.session_id), db)
    assert exc.value.status_code == 401
    assert "ended" in exc.value.detail


def test_terminated_session_still_says_terminated(db, make_user):
    user = make_user()
    session = UserSession(user_id=user.user_id, terminated=True, logout_time=datetime.utcnow(), session_duration=5.0)
    db.add(session)
    db.commit()

    with pytest.raises(HTTPException) as exc:
        rbac.get_current_user_and_session(_bearer(user, session.session_id), db)
    assert "terminated" in exc.value.detail


def test_token_for_a_session_that_does_not_exist_is_rejected(db, make_user):
    user = make_user()
    with pytest.raises(HTTPException) as exc:
        rbac.get_current_user_and_session(_bearer(user, 99999), db)
    assert exc.value.status_code == 401


def test_token_pairing_a_user_with_someone_elses_session_is_rejected(db, make_user):
    owner, other = make_user(), make_user()
    session = _open_session(db, owner)
    with pytest.raises(HTTPException):
        rbac.get_current_user_and_session(_bearer(other, session.session_id), db)


# --- emailed codes ---------------------------------------------------------------------------------

def test_codes_are_six_digits():
    codes = {otp_service.generate_code() for _ in range(200)}
    assert all(len(c) == 6 and c.isdigit() and not c.startswith("0") for c in codes)
    assert len(codes) > 150  # not a fixed or tiny set


def test_right_code_after_a_few_wrong_guesses_still_works(db, make_user):
    user = make_user()
    record = _code(db, user)
    for _ in range(otp_service.MAX_OTP_ATTEMPTS - 1):
        assert not otp_service.verify_otp(db, user.user_id, "000000")
    assert otp_service.verify_otp(db, user.user_id, "123456")
    db.refresh(record)
    assert record.used


def test_code_is_burned_after_too_many_wrong_guesses(db, make_user):
    user = make_user()
    record = _code(db, user)
    for _ in range(otp_service.MAX_OTP_ATTEMPTS):
        assert not otp_service.verify_otp(db, user.user_id, "000000")
    db.refresh(record)
    assert record.used and record.failed_attempts == otp_service.MAX_OTP_ATTEMPTS
    assert not otp_service.verify_otp(db, user.user_id, "123456")  # even the right code no longer works


def test_expired_code_is_refused(db, make_user):
    user = make_user()
    _code(db, user, minutes=-1)
    assert not otp_service.verify_otp(db, user.user_id, "123456")


# --- client address ----------------------------------------------------------------------------------

def test_forged_first_entry_is_ignored_behind_one_proxy(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "TRUSTED_PROXY_HOPS", 1)
    # The browser sent "1.2.3.4"; nginx appended the address it really saw.
    req = _request({"X-Forwarded-For": "1.2.3.4, 172.18.0.1"})
    assert rate_limit.client_ip(req) == "172.18.0.1"


def test_production_reads_the_visitor_written_by_caddy(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "TRUSTED_PROXY_HOPS", 2)
    # Caddy replaced the header with the visitor; nginx appended Caddy's address.
    req = _request({"X-Forwarded-For": "41.90.1.2, 172.20.0.3"})
    assert rate_limit.client_ip(req) == "41.90.1.2"


def test_without_the_header_the_peer_address_is_used(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "TRUSTED_PROXY_HOPS", 1)
    assert rate_limit.client_ip(_request(peer="172.18.0.9")) == "172.18.0.9"


def test_zero_hops_ignores_the_header(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "TRUSTED_PROXY_HOPS", 0)
    req = _request({"X-Forwarded-For": "1.2.3.4"}, peer="172.18.0.9")
    assert rate_limit.client_ip(req) == "172.18.0.9"


def test_new_session_records_the_proxied_client_address(db, make_user, monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "TRUSTED_PROXY_HOPS", 1)
    user = make_user()
    auth._issue_full_login(db, _request({"X-Forwarded-For": "6.6.6.6, 192.168.65.1"}), user)
    assert db.query(UserSession).filter_by(user_id=user.user_id).one().access_location == "192.168.65.1"


# --- first-time setup needs the emailed code ---------------------------------------------------------

@pytest.fixture
def new_user(db, make_user):
    """Has a password but has not chosen Face ID or email codes yet (e.g. made by create_admin)."""
    user = make_user()
    user.password = hash_password("Correct#Pass1")
    user.biometric_choice_made = False
    db.commit()
    return user


def test_password_alone_does_not_open_first_time_setup(db, new_user):
    form = SimpleNamespace(username=new_user.username, password="Correct#Pass1")
    result = auth.login(_request(), form, db)

    assert result.status == "2fa_required"
    assert decode_pending_token(result.pending_token, expected_scope="first_time_setup") is None
    with pytest.raises(HTTPException):  # the 2FA token cannot be used to skip setup
        auth.skip_biometric_setup(auth.SkipBiometricSetupRequest(pending_token=result.pending_token), _request(), db)


def test_verified_code_leads_a_new_user_to_first_time_setup(db, new_user):
    _code(db, new_user)
    pending = create_pending_token(new_user.user_id)
    result = auth.verify_otp_route(auth.VerifyOtpRequest(pending_token=pending), _request(), db, code="123456")

    assert result.status == "first_time_setup_required"
    assert decode_pending_token(result.pending_token, expected_scope="first_time_setup") == str(new_user.user_id)
    assert db.query(UserSession).filter_by(user_id=new_user.user_id).count() == 0  # not signed in yet


def test_verified_code_signs_in_a_user_who_already_chose(db, make_user):
    user = make_user()  # biometric_choice_made defaults to True
    _code(db, user)
    result = auth.verify_otp_route(
        auth.VerifyOtpRequest(pending_token=create_pending_token(user.user_id)), _request(), db, code="123456"
    )
    assert result.access_token
    assert db.query(UserSession).filter_by(user_id=user.user_id).count() == 1


# --- password reset ------------------------------------------------------------------------------------

def test_password_reset_ends_open_sessions(db, make_user, monkeypatch):
    monkeypatch.setattr(anomaly_service, "score_session", lambda *a, **k: None)
    user = make_user()
    sessions = [_open_session(db, user) for _ in range(2)]
    user.password_reset_token = "reset-token"
    user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
    db.commit()

    auth.reset_password(auth.ResetPasswordRequest(token="reset-token", new_password="New#Pass123"), db)

    for s in sessions:
        db.refresh(s)
        assert s.logout_time is not None
        with pytest.raises(HTTPException):
            rbac.get_current_user_and_session(_bearer(user, s.session_id), db)
