"""RBAC enforcement tests — security-critical, always run in CI (US-06.09).

Verify that the interim tenant-token gate enforces authentication and the
PlatformAdmin boundary on /api/v1/admin/*, and that the tenant identity is
resolved from the verified token — never from client headers.

Real ArangoDB (tenant registry in `_system`) and real Redis (blocklist),
per the global test rules. The auth flag is flipped per test via
monkeypatch — the middleware reads `settings.AUTH_ENABLED` at request time.
"""

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.middleware import TenantIdentityMiddleware
from app.main import app
from app.services import tenant_registry
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

CDR_NOT_BUILT = "CDR engine and approval flow are Epic 04 — not implemented yet"


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def auth_enabled(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)


@pytest.fixture
def clean_registry(sys_db):
    """Remove os registros de token e o database de tenant criados pelos testes
    (os das fixtures db_tenant_a/b são limpos pelas próprias fixtures)."""
    yield
    if sys_db.has_collection(tenant_registry.TENANTS_COLLECTION):
        col = sys_db.collection(tenant_registry.TENANTS_COLLECTION)
        for tenant_id in (TEST_TENANT_A, TEST_TENANT_B, "dev"):
            col.delete(tenant_id, ignore_missing=True)
    sys_db.delete_database(f"ogum_{TEST_TENANT_B}", ignore_missing=True)


def _mint(tenant_id: str, platform_admin: bool = False) -> str:
    return tenant_registry.mint_api_token(tenant_id, platform_admin=platform_admin).api_token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.security
@pytest.mark.usefixtures("auth_enabled")
class TestAuthenticationRequired:
    """Every protected route returns 401 when no (valid) token is provided."""

    def test_inventory_requires_auth(self, client):
        assert client.get("/api/v1/inventory").status_code == 401

    def test_findings_requires_auth(self, client):
        assert client.get("/api/v1/findings").status_code == 401

    def test_scans_requires_auth(self, client):
        response = client.post("/api/v1/scans", json={})
        assert response.status_code == 401

    def test_admin_jobs_requires_auth(self, client):
        assert client.get("/api/v1/admin/jobs").status_code == 401

    def test_garbage_token_rejected(self, client):
        response = client.get("/api/v1/inventory", headers=_auth("not-a-jwt"))
        assert response.status_code == 401

    def test_health_stays_public(self, client):
        assert client.get("/health").status_code == 200

    def test_scanner_webhooks_bypass_bearer_gate(self, client):
        """Webhooks autenticam por x-ogum-token próprio — nunca pelo Bearer.

        Sem os headers obrigatórios do webhook a resposta é 422 (FastAPI),
        nunca 401 do gate Bearer.
        """
        response = client.post("/api/v1/side-scans/webhooks/k8s-scan", json={})
        assert response.status_code != 401

    def test_401_carries_www_authenticate(self, client):
        response = client.get("/api/v1/inventory")
        assert response.headers.get("www-authenticate") == "Bearer"


@pytest.mark.security
@pytest.mark.usefixtures("auth_enabled", "clean_registry")
class TestRoleEnforcement:
    """/api/v1/admin/* exige token com flag platform_admin; SecOps → 403."""

    def test_secops_token_cannot_list_admin_jobs(self, client):
        response = client.get("/api/v1/admin/jobs", headers=_auth(_mint(TEST_TENANT_A)))
        assert response.status_code == 403

    def test_secops_token_cannot_mint_tokens(self, client):
        response = client.put(
            f"/api/v1/admin/tenants/{TEST_TENANT_B}/api-token",
            headers=_auth(_mint(TEST_TENANT_A)),
        )
        assert response.status_code == 403

    def test_platform_admin_token_lists_registry(self, client):
        token = _mint(TEST_TENANT_A, platform_admin=True)
        response = client.get("/api/v1/admin/tenants", headers=_auth(token))
        assert response.status_code == 200
        tenants = response.json()["data"]
        assert any(t["tenant_id"] == TEST_TENANT_A for t in tenants)
        assert all("token_hash" not in t for t in tenants)

    def test_platform_admin_token_mints_and_rotates(self, client):
        admin_token = _mint(TEST_TENANT_A, platform_admin=True)
        first = client.put(f"/api/v1/admin/tenants/{TEST_TENANT_B}/api-token", headers=_auth(admin_token)).json()[
            "data"
        ]["api_token"]

        # O token recém-emitido autentica…
        assert client.get("/api/v1/inventory", headers=_auth(first)).status_code == 200

        # …e a rotação revoga o anterior imediatamente (hash substituído).
        client.put(f"/api/v1/admin/tenants/{TEST_TENANT_B}/api-token", headers=_auth(admin_token))
        assert client.get("/api/v1/inventory", headers=_auth(first)).status_code == 401


@pytest.mark.security
@pytest.mark.usefixtures("auth_enabled", "clean_registry")
class TestTenantIdentityFromToken:
    """A identidade vem do token verificado — header spoofado é sobrescrito."""

    def _run_middleware(self, token: str, spoofed_tenant: str) -> dict:
        captured: dict = {"called": False, "headers": None}

        async def inner_app(scope, receive, send):
            captured["called"] = True
            captured["headers"] = dict(scope["headers"])

        async def _noop_receive():
            return {}

        async def _noop_send(message):
            return None

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/inventory",
            "headers": [
                (b"x-tenant-id", spoofed_tenant.encode()),
                (b"authorization", f"Bearer {token}".encode()),
            ],
        }
        asyncio.run(TenantIdentityMiddleware(inner_app)(scope, _noop_receive, _noop_send))
        return captured

    def test_spoofed_tenant_header_is_overwritten(self):
        token = _mint(TEST_TENANT_A)
        captured = self._run_middleware(token, TEST_TENANT_B)
        assert captured["called"] is True
        assert captured["headers"][b"x-tenant-id"] == TEST_TENANT_A.encode()

    def test_user_id_header_is_overwritten_with_subject(self):
        token = _mint(TEST_TENANT_A)
        captured = self._run_middleware(token, TEST_TENANT_A)
        assert captured["headers"][b"x-user-id"] == f"tenant:{TEST_TENANT_A}".encode()

    def test_missing_token_short_circuits_without_calling_app(self):
        captured: dict = {"called": False}

        async def inner_app(scope, receive, send):
            captured["called"] = True

        async def _noop_receive():
            return {}

        async def _noop_send(message):
            return None

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/inventory",
            "headers": [(b"x-tenant-id", TEST_TENANT_A.encode())],
        }
        asyncio.run(TenantIdentityMiddleware(inner_app)(scope, _noop_receive, _noop_send))
        assert captured["called"] is False


@pytest.mark.security
class TestDevModePassthrough:
    """AUTH_ENABLED=false (default): comportamento dev preservado."""

    def test_legacy_headers_still_work_with_auth_off(self, client, db_tenant_a):
        response = client.get("/api/v1/inventory", headers={"X-Tenant-ID": TEST_TENANT_A})
        assert response.status_code == 200


@pytest.mark.security
class TestCDRAuthorization:
    """CDR-specific authorization: Tier 2 must never auto-execute."""

    @pytest.mark.skip(reason=CDR_NOT_BUILT)
    def test_tier2_action_without_approval_is_rejected(self):
        """Tier 2 containment must not execute without explicit approval."""

    @pytest.mark.skip(reason=CDR_NOT_BUILT)
    def test_tier2_approval_token_is_single_use(self):
        """An approval token used once must be invalidated — no replay."""

    @pytest.mark.skip(reason=CDR_NOT_BUILT)
    def test_every_cdr_action_creates_audit_entry(self):
        """Every executed CDR action must produce an audit log entry."""
