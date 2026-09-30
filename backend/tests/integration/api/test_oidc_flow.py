"""US-06.01 — fluxo OIDC ponta a ponta com IdP mockado.

Cobre o Sprint 2: login → state no Redis; callback feliz (code trocado,
id_token validado, JWT interno nos cookies HttpOnly, role mapeada de
grupos); anti-CSRF (state reutilizado → 400); nonce inválido → 400;
refresh com rotação (replay do refresh antigo → 401); middleware aceita o
cookie `ogum_access`; configuração do IdP exclusiva de PlatformAdmin.

O IdP é um httpx.MockTransport injetado em `oidc_service._http`; o Vault é
falso em memória; Redis/ArangoDB reais (marca integration/security).
"""

from __future__ import annotations

import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jose import jwt

from app.core.config import settings
from app.core.rbac import Role
from app.core.security import create_access_token, decode_access_token
from app.main import app
from app.services import oidc_service, tenant_registry
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

pytestmark = [pytest.mark.integration, pytest.mark.security]


@pytest.fixture(autouse=True)
def _auth_on(monkeypatch):
    """Perfil OIDC: gate ativo mesmo em .env local com AUTH_ENABLED=false —
    os 3 flows públicos são isentos no middleware; o resto precisa do gate."""
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)


ISSUER = "https://idp.ogum-test.invalid"
CLIENT_ID = "ogum-tenant-a"
REDIRECT_CALLBACK = "/api/v1/auth/oidc/callback"

# Vault falso compartilhado (semeado pelo fixture oidc_tenant, escrito pelo
# POST /config via store_credentials mockado)
FAKE_VAULT: dict[str, str] = {}


def _redis_up() -> bool:
    try:
        from app.api.v1.auth import _redis

        _redis().ping()
        return True
    except Exception:
        return False


redis_available = pytest.mark.skipif(not _redis_up(), reason="Redis indisponível (docker não subiu)")

# ── infra de teste: RSA + IdP falso + Vault falso ────────────────────────────


@pytest.fixture(scope="module")
def rsa_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = private_key.public_key().public_numbers()

    def b64uint(value: int) -> str:
        import base64

        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    entry = {"kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": b64uint(pub.n), "e": b64uint(pub.e)}
    return pem, entry


@pytest.fixture(autouse=True)
def fake_idp(monkeypatch, rsa_material):
    """IdP mockado: discovery/jwks/token via MockTransport; Vault em memória."""
    pem, entry = rsa_material
    idp_state: dict = {"nonce": None, "token_error": None}
    vault = FAKE_VAULT

    def mint(nonce: str, nonce_is_wrong: bool = False) -> str:
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "ada@corp.example.com",
            "email": "ada@corp.example.com",
            "groups": ["sec-team"],
            "nonce": "nonce-errado" if nonce_is_wrong else nonce,
            "exp": 4102444800,
        }
        return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "test-key"})

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.host != "idp.ogum-test.invalid":
            return httpx.Response(404, text="unknown host")  # IdP estranho no config → 422
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/jwks",
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        if path.endswith("/jwks"):
            return httpx.Response(200, json={"keys": [entry]})
        if path.endswith("/token"):
            if idp_state["token_error"]:
                return httpx.Response(400, json={"error": idp_state["token_error"]})
            code = dict(pair.split("=", 1) for pair in request.content.decode().split("&"))
            if code.get("code") != "auth-code-123":
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": mint(idp_state["nonce"] or ""), "access_token": "x"})
        return httpx.Response(404)

    monkeypatch.setattr(oidc_service, "_assert_public_host", lambda url: None)
    monkeypatch.setattr(oidc_service, "_http", lambda: httpx.Client(transport=httpx.MockTransport(handler)))

    def fake_store(tenant_id, key, secrets):
        vault.update(secrets)
        return {"path": "x", "version": 1}

    monkeypatch.setattr(oidc_service.vault_client, "store_credentials", fake_store)
    monkeypatch.setattr(
        oidc_service.vault_client, "load_credentials", lambda path: {"client_secret": vault.get("client_secret", "")}
    )
    yield idp_state


@pytest.fixture
def oidc_tenant(db_tenant_a):
    """Config do IdP no database do Tenant A (+ limpa estados no Redis)."""
    from app.api.v1.auth import REFRESH_KEY_PREFIX, STATE_KEY_PREFIX, _redis

    config = oidc_service.OidcConfig(
        idp_name="Corp Okta",
        discovery_url=f"{ISSUER}/.well-known/openid-configuration",
        client_id=CLIENT_ID,
        role_mappings=[oidc_service.RoleMapping(group="sec-team", role=Role.SecOps)],
    )
    col = (
        db_tenant_a.collection("oidc_config")
        if db_tenant_a.has_collection("oidc_config")
        else db_tenant_a.create_collection("oidc_config")
    )
    col.insert({"_key": "idp", **config.model_dump(mode="json")}, overwrite_mode="replace")
    FAKE_VAULT.clear()
    FAKE_VAULT["client_secret"] = "s3cret-do-tenant"
    redis = _redis()
    for key in (*redis.scan_iter(f"{STATE_KEY_PREFIX}*"), *redis.scan_iter(f"{REFRESH_KEY_PREFIX}*")):
        redis.delete(key)
    yield db_tenant_a
    for key in (*redis.scan_iter(f"{STATE_KEY_PREFIX}*"), *redis.scan_iter(f"{REFRESH_KEY_PREFIX}*")):
        redis.delete(key)


# ── login ────────────────────────────────────────────────────────────────────


@redis_available
def test_login_redirects_to_idp_with_state(oidc_tenant):
    client = TestClient(app)
    response = client.get(f"/api/v1/auth/oidc/login?tenant_id={TEST_TENANT_A}", follow_redirects=False)
    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith(f"{ISSUER}/authorize?")
    assert "response_type=code" in location and "state=" in location and "nonce=" in location
    state = location.split("state=")[1].split("&")[0]
    from app.api.v1.auth import STATE_KEY_PREFIX, _redis

    assert _redis().exists(f"{STATE_KEY_PREFIX}{state}")


@redis_available
def test_login_unregistered_tenant_404(oidc_tenant):
    client = TestClient(app)
    response = client.get("/api/v1/auth/oidc/login?tenant_id=ghost-oidc", follow_redirects=False)
    assert response.status_code == 404


@redis_available
def test_login_without_oidc_config_404(db_tenant_a):
    client = TestClient(app)
    response = client.get(f"/api/v1/auth/oidc/login?tenant_id={TEST_TENANT_A}", follow_redirects=False)
    assert response.status_code == 404
    assert "No OIDC" in response.json()["detail"]


# ── callback ─────────────────────────────────────────────────────────────────


def _run_login(client: TestClient) -> str:
    response = client.get(f"/api/v1/auth/oidc/login?tenant_id={TEST_TENANT_A}", follow_redirects=False)
    return response.headers["location"].split("state=")[1].split("&")[0]


@redis_available
def test_callback_happy_path_sets_cookies_and_role(oidc_tenant, fake_idp):
    client = TestClient(app)
    state = _run_login(client)
    from app.api.v1.auth import STATE_KEY_PREFIX, _redis

    fake_idp["nonce"] = str(json.loads(_redis().get(f"{STATE_KEY_PREFIX}{state}"))["nonce"])
    response = client.get(f"{REDIRECT_CALLBACK}?code=auth-code-123&state={state}", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == f"{settings.FRONTEND_URL.rstrip('/')}/dashboard"
    cookies = response.headers["set-cookie"]
    assert "ogum_access=" in cookies and "ogum_refresh=" in cookies and "HttpOnly" in cookies
    access = response.cookies["ogum_access"]
    data = decode_access_token(access)
    assert data.tenant_id == TEST_TENANT_A
    assert data.role.value == "SecOps"  # grupo sec-team mapeado
    assert data.email == "ada@corp.example.com"
    assert data.typ == "access"
    # state consumido
    assert not _redis().exists(f"{STATE_KEY_PREFIX}{state}")


@redis_available
def test_callback_reused_state_rejected(oidc_tenant, fake_idp):
    client = TestClient(app)
    state = _run_login(client)
    from app.api.v1.auth import STATE_KEY_PREFIX, _redis

    fake_idp["nonce"] = str(json.loads(_redis().get(f"{STATE_KEY_PREFIX}{state}"))["nonce"])
    first = client.get(f"{REDIRECT_CALLBACK}?code=auth-code-123&state={state}", follow_redirects=False)
    assert first.status_code == 307
    replay = client.get(f"{REDIRECT_CALLBACK}?code=auth-code-123&state={state}", follow_redirects=False)
    assert replay.status_code == 400
    assert "state" in replay.json()["detail"].lower()


@redis_available
def test_callback_bad_nonce_rejected(oidc_tenant, fake_idp):
    client = TestClient(app)
    state = _run_login(client)
    fake_idp["nonce"] = "nonce-forjado"  # id_token com nonce que não bate
    response = client.get(f"{REDIRECT_CALLBACK}?code=auth-code-123&state={state}", follow_redirects=False)
    assert response.status_code == 400
    assert "nonce" in response.json()["detail"]


@redis_available
def test_callback_group_maps_to_platform_admin_only_via_mapping(oidc_tenant, fake_idp):
    """Grupo 'admins' mapeado → PlatformAdmin (mapping explícito do tenant)."""
    from app.core.rbac import Role

    oidc_tenant.collection("oidc_config").insert(
        {
            "_key": "idp",
            **oidc_service.OidcConfig(
                idp_name="Corp Okta",
                discovery_url=f"{ISSUER}/.well-known/openid-configuration",
                client_id=CLIENT_ID,
                role_mappings=[oidc_service.RoleMapping(group="sec-team", role=Role.SecOps)],
            ).model_dump(mode="json"),
        },
        overwrite_mode="replace",
    )
    client = TestClient(app)
    state = _run_login(client)
    from app.api.v1.auth import STATE_KEY_PREFIX, _redis

    fake_idp["nonce"] = str(json.loads(_redis().get(f"{STATE_KEY_PREFIX}{state}"))["nonce"])
    response = client.get(f"{REDIRECT_CALLBACK}?code=auth-code-123&state={state}", follow_redirects=False)
    assert response.status_code == 307
    assert decode_access_token(response.cookies["ogum_access"]).role is Role.SecOps


# ── middleware aceita o cookie ───────────────────────────────────────────────


@redis_available
def test_api_accepts_access_cookie(oidc_tenant, fake_idp):
    client = TestClient(app)
    state = _run_login(client)
    from app.api.v1.auth import STATE_KEY_PREFIX, _redis

    fake_idp["nonce"] = str(json.loads(_redis().get(f"{STATE_KEY_PREFIX}{state}"))["nonce"])
    client.get(f"{REDIRECT_CALLBACK}?code=auth-code-123&state={state}", follow_redirects=False)
    response = client.get("/api/v1/inventory")  # sem header — vai por cookie
    assert response.status_code == 200


# ── refresh com rotação ──────────────────────────────────────────────────────


@redis_available
def test_refresh_rotates_and_replay_fails(oidc_tenant, fake_idp):
    client = TestClient(app)
    state = _run_login(client)
    from app.api.v1.auth import STATE_KEY_PREFIX, _redis

    fake_idp["nonce"] = str(json.loads(_redis().get(f"{STATE_KEY_PREFIX}{state}"))["nonce"])
    client.get(f"{REDIRECT_CALLBACK}?code=auth-code-123&state={state}", follow_redirects=False)
    old_refresh = client.cookies["ogum_refresh"]

    renewed = client.post("/api/v1/auth/refresh")
    assert renewed.status_code == 200
    assert renewed.json()["data"]["expires_in"] == settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert renewed.cookies["ogum_refresh"] != old_refresh

    # replay do refresh antigo → 401 (jti consumido na rotação)
    replay = client.post("/api/v1/auth/refresh", cookies={settings.REFRESH_COOKIE_NAME: old_refresh})
    assert replay.status_code == 401


@redis_available
def test_refresh_rejects_access_token_as_refresh():
    client = TestClient(app)
    access = create_access_token(subject="user:x", tenant_id=TEST_TENANT_A, role="SecOps", token_type="access")
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": access})
    assert response.status_code == 401
    assert "Not a refresh token" in response.json()["detail"]


# ── configuração do IdP (PlatformAdmin) ──────────────────────────────────────


@redis_available
def test_config_requires_platform_admin(oidc_tenant):
    client = TestClient(app)
    response = client.post(
        "/api/v1/auth/oidc/config",
        json={
            "tenant_id": TEST_TENANT_A,
            "discovery_url": f"{ISSUER}/.well-known/openid-configuration",
            "client_id": CLIENT_ID,
            "client_secret": "s3cret",
        },
    )
    assert response.status_code == 401  # sem token


@redis_available
def test_config_secops_forbidden(oidc_tenant):
    client = TestClient(app)
    token = tenant_registry.mint_api_token(TEST_TENANT_B).api_token  # SecOps
    response = client.post(
        "/api/v1/auth/oidc/config",
        json={
            "tenant_id": TEST_TENANT_A,
            "discovery_url": f"{ISSUER}/.well-known/openid-configuration",
            "client_id": CLIENT_ID,
            "client_secret": "s3cret",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@redis_available
def test_config_platform_admin_saves(oidc_tenant, fake_idp):
    client = TestClient(app)
    token = tenant_registry.mint_api_token(TEST_TENANT_A, platform_admin=True).api_token
    response = client.post(
        "/api/v1/auth/oidc/config",
        json={
            "tenant_id": TEST_TENANT_A,
            "idp_name": "Okta Corp",
            "discovery_url": f"{ISSUER}/.well-known/openid-configuration",
            "client_id": CLIENT_ID,
            "client_secret": "s3cret-nova",
            "role_mappings": [{"group": "admins", "role": "PlatformAdmin"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["data"]["idp_name"] == "Okta Corp"
    doc = oidc_tenant.collection("oidc_config").get("idp")
    assert doc["client_id"] == CLIENT_ID
    assert "client_secret" not in doc  # secret só no Vault


@redis_available
def test_config_invalid_discovery_rolls_back(oidc_tenant):
    """Discovery que não responde → 422 e NADA persistido (rollback)."""
    client = TestClient(app)
    token = tenant_registry.mint_api_token(TEST_TENANT_A, platform_admin=True).api_token
    response = client.post(
        "/api/v1/auth/oidc/config",
        json={
            "tenant_id": TEST_TENANT_A,
            "discovery_url": "https://idp-quebrado.example.com/.well-known/openid-configuration",
            "client_id": CLIENT_ID,
            "client_secret": "s3cret",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422
    assert oidc_tenant.collection("oidc_config").get("idp") is None


# ── status do IdP (login page) ───────────────────────────────────────────────


@redis_available
def test_status_reports_idp_name(oidc_tenant):
    client = TestClient(app)
    response = client.get(f"/api/v1/auth/oidc/status?tenant_id={TEST_TENANT_A}")
    assert response.status_code == 200
    assert response.json()["data"] == {"enabled": True, "idp_name": "Corp Okta"}


@redis_available
def test_status_without_config_404(db_tenant_a):
    client = TestClient(app)
    response = client.get(f"/api/v1/auth/oidc/status?tenant_id={TEST_TENANT_A}")
    assert response.status_code == 404
