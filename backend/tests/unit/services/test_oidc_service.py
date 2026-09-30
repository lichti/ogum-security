"""US-06.01 — unidade do oidc_service: map_role, discovery e validação de id_token.

Sem Arango/Redis/Vault: IdP simulado via httpx.MockTransport e RSA gerada em
memória (python-jose[cryptography] já traz o backend).
"""

from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from app.core.rbac import Role
from app.services import oidc_service

pytestmark = pytest.mark.unit

ISSUER = "https://idp.example.com"
CLIENT_ID = "ogum-client"

# capturado ANTES do patch autouse — a checagem SSRF real (getaddrinfo)
_REAL_ASSERT_PUBLIC_HOST = oidc_service._assert_public_host


@pytest.fixture(autouse=True)
def _no_dns(monkeypatch):
    """Descarte a checagem SSRF de DNS: os hosts dos testes são fictícios."""
    monkeypatch.setattr(oidc_service, "_assert_public_host", lambda url: None)
    # o cache de JWKS é keyed pela URL (igual em todos os testes) — sem o
    # clear, a chave RSA de um teste vaza para o seguinte
    oidc_service._jwks_cache_key.cache_clear()
    yield
    oidc_service._jwks_cache_key.cache_clear()


def _rsa_material():
    import base64

    def b64uint(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = private_key.public_key().public_numbers()
    entry = {"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": b64uint(pub.n), "e": b64uint(pub.e)}
    return pem, entry


def _discovery(entry) -> dict:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
        "keys": [entry],  # o mock de /jwks devolve o doc inteiro
    }


def _mock_client(discovery: dict) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jwks"):
            return httpx.Response(200, json={"keys": discovery["keys"]})
        return httpx.Response(404)

    return httpx.Client(transport=httpx.MockTransport(handler))


# ── map_role ─────────────────────────────────────────────────────────────────


def _config(**overrides) -> oidc_service.OidcConfig:
    defaults = dict(
        idp_name="Corp IdP",
        discovery_url=f"{ISSUER}/.well-known/openid-configuration",
        client_id=CLIENT_ID,
        role_mappings=[
            oidc_service.RoleMapping(group="sec-team", role=Role.SecOps),
            oidc_service.RoleMapping(group="admins", role=Role.PlatformAdmin),
        ],
    )
    defaults.update(overrides)
    return oidc_service.OidcConfig(**defaults)


def test_map_role_group_match_wins_over_default():
    config = _config(default_role=Role.DevOps)
    assert oidc_service.map_role({"groups": ["sec-team", "other"]}, config) is Role.SecOps


def test_map_role_platform_admin_only_via_explicit_mapping():
    config = _config()
    assert oidc_service.map_role({"groups": ["admins"]}, config) is Role.PlatformAdmin
    assert oidc_service.map_role({"groups": ["nobody"]}, config) is config.default_role


def test_map_role_string_group_claim_and_missing_claim():
    config = _config(default_role=Role.Auditor)
    assert oidc_service.map_role({"groups": "sec-team"}, config) is Role.SecOps
    assert oidc_service.map_role({}, config) is Role.Auditor
    assert oidc_service.map_role({"groups": None}, config) is Role.Auditor


def test_map_role_custom_claim_key():
    config = _config(group_claim_key="roles", default_role=Role.SecOps)
    assert oidc_service.map_role({"roles": ["sec-team"]}, config) is Role.SecOps


# ── discovery ────────────────────────────────────────────────────────────────


def _route(monkeypatch, discovery: dict | None, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        if discovery is None or status != 200:
            return httpx.Response(status, text="boom")
        return httpx.Response(200, json=discovery)

    monkeypatch.setattr(oidc_service, "_http", lambda: httpx.Client(transport=httpx.MockTransport(handler)))


def test_fetch_discovery_appends_wellknown_and_returns_doc(monkeypatch):
    discovery = _discovery(_rsa_material()[1])
    _route(monkeypatch, discovery)
    doc = oidc_service.fetch_discovery(f"{ISSUER}/")  # trailing slash normalizado
    assert doc["token_endpoint"] == f"{ISSUER}/token"


def test_fetch_discovery_http_error_raises(monkeypatch):
    _route(monkeypatch, None, status=500)
    with pytest.raises(oidc_service.DiscoveryError, match="discovery endpoint failed"):
        oidc_service.fetch_discovery(ISSUER)


def test_fetch_discovery_missing_required_fields_raises(monkeypatch):
    _route(monkeypatch, {"issuer": ISSUER})
    with pytest.raises(oidc_service.DiscoveryError, match="missing fields"):
        oidc_service.fetch_discovery(ISSUER)


def test_discovery_private_host_rejected(monkeypatch):
    monkeypatch.setattr(oidc_service, "_assert_public_host", _REAL_ASSERT_PUBLIC_HOST)
    with pytest.raises(oidc_service.DiscoveryError, match="private"):
        oidc_service.fetch_discovery("http://127.0.0.1:8080")


# ── id_token ─────────────────────────────────────────────────────────────────


def _mint_id_token(pem, claims: dict) -> str:
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "test-key"})


def _claims(**overrides) -> dict:
    base = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-123",
        "email": "dev@corp.example.com",
        "groups": ["sec-team"],
        "nonce": "nonce-abc",
        "exp": 4102444800,  # 2100-01-01
    }
    base.update(overrides)
    return base


def test_validate_id_token_happy_path(monkeypatch):
    pem, entry = _rsa_material()
    discovery = _discovery(entry)
    monkeypatch.setattr(oidc_service, "_http", lambda: _mock_client(discovery))
    config = _config()
    claims = oidc_service.validate_id_token(_mint_id_token(pem, _claims()), discovery, config, "nonce-abc")
    assert claims["sub"] == "user-123"


def test_validate_id_token_wrong_nonce_rejected(monkeypatch):
    pem, entry = _rsa_material()
    discovery = _discovery(entry)
    monkeypatch.setattr(oidc_service, "_http", lambda: _mock_client(discovery))
    with pytest.raises(ValueError, match="nonce mismatch"):
        oidc_service.validate_id_token(_mint_id_token(pem, _claims()), discovery, _config(), "nonce-OUTRO")


def test_validate_id_token_wrong_audience_rejected(monkeypatch):
    pem, entry = _rsa_material()
    discovery = _discovery(entry)
    monkeypatch.setattr(oidc_service, "_http", lambda: _mock_client(discovery))
    token = _mint_id_token(pem, _claims(aud="another-client"))
    with pytest.raises(ValueError, match="validation failed"):
        oidc_service.validate_id_token(token, discovery, _config(), "nonce-abc")


def test_validate_id_token_unknown_kid_rejected(monkeypatch):
    pem, entry = _rsa_material()
    discovery = _discovery(entry)
    monkeypatch.setattr(oidc_service, "_http", lambda: _mock_client(discovery))
    token = jwt.encode(_claims(), pem, algorithm="RS256", headers={"kid": "outra-chave"})
    with pytest.raises(ValueError, match="kid not found"):
        oidc_service.validate_id_token(token, discovery, _config(), "nonce-abc")
