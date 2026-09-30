"""Unit tests — app.core.security (JWT foundation, Epic 06 Sprint 1)."""

from datetime import timedelta

import pytest

from app.core import security
from app.core.config import settings
from app.core.rbac import Role
from app.core.security import create_access_token, decode_access_token

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _hs256(monkeypatch):
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "HS256")
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "unit-test-signing-key")
    monkeypatch.setattr(settings, "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 15)


@pytest.fixture(autouse=True)
def _no_blocklist(monkeypatch):
    monkeypatch.setattr(security, "is_jti_blocklisted", lambda jti: False)


def _token(**overrides):
    kwargs = dict(subject="user-1", tenant_id="acme", role=Role.SecOps)
    kwargs.update(overrides)
    return create_access_token(**kwargs)


def test_roundtrip_preserves_claims():
    token = _token(email="a@b.c")
    data = decode_access_token(token)
    assert data.sub == "user-1"
    assert data.tenant_id == "acme"
    assert data.role is Role.SecOps
    assert data.email == "a@b.c"
    assert data.jti
    assert data.exp > data.iat


def test_jti_is_unique_per_token():
    assert decode_access_token(_token()).jti != decode_access_token(_token()).jti


def test_expired_token_is_rejected():
    token = _token(expires_delta=timedelta(seconds=-10))
    with pytest.raises(ValueError, match="invalid token"):
        decode_access_token(token)


def test_tampered_signature_is_rejected():
    token = _token()
    with pytest.raises(ValueError, match="invalid token"):
        decode_access_token(token + "x")


def test_wrong_key_is_rejected(monkeypatch):
    token = _token()
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "another-key")
    with pytest.raises(ValueError, match="invalid token"):
        decode_access_token(token)


def test_blocklisted_jti_is_rejected(monkeypatch):
    token = _token()
    jti = decode_access_token(token).jti
    monkeypatch.setattr(security, "is_jti_blocklisted", lambda j: j == jti)
    with pytest.raises(ValueError, match="revoked"):
        decode_access_token(token)


def test_rs256_creation_refuses_without_keypair(monkeypatch):
    monkeypatch.setattr(settings, "JWT_ALGORITHM", "RS256")
    with pytest.raises(RuntimeError, match="RS256"):
        _token()


def test_token_type_claim_defaults_to_access_and_supports_api():
    access = decode_access_token(_token())
    assert access.typ == "access"
    api = decode_access_token(_token(token_type="api"))
    assert api.typ == "api"


def test_secret_falls_back_to_app_secret(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "")
    monkeypatch.setattr(settings, "APP_SECRET_KEY", "app-secret")
    token = _token()
    monkeypatch.setattr(settings, "APP_SECRET_KEY", "changed")
    with pytest.raises(ValueError):
        decode_access_token(token)
