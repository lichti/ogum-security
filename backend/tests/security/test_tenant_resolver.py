"""US-06.10 — resolver estrito de tenant.

`get_tenant_db`: allowlist em `_system.tenants`, formato validado, **nunca
cria database** no caminho da request. Registrado (via `_registered_test_tenants`)
→ resolve; não registrado → 404 sem efeito colateral; formato inválido → 422.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import tenant_registry
from tests.conftest import TEST_TENANT_A

pytestmark = pytest.mark.security


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_unregistered_tenant_returns_404_without_side_effect(client, sys_db, _registered_test_tenants):
    ghost = "ghost-tenant-xyz"
    assert not tenant_registry.is_registered(ghost)
    response = client.get("/api/v1/inventory", headers={"X-Tenant-ID": ghost})
    assert response.status_code == 404
    assert "not registered" in response.json()["detail"]
    # Sem efeito colateral: nem registro, nem database
    assert not tenant_registry.is_registered(ghost)
    assert not sys_db.has_database(f"ogum_{ghost}")


def test_invalid_tenant_id_format_returns_422(client, _registered_test_tenants):
    response = client.get("/api/v1/inventory", headers={"X-Tenant-ID": "../etc/passwd"})
    assert response.status_code == 422


def test_registered_tenant_resolves(client, db_tenant_a, _registered_test_tenants):
    response = client.get("/api/v1/inventory", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert response.status_code == 200


def test_validate_tenant_id_rejects_injection_shapes():
    for bad in ("", "a" * 65, "has space", "dollar$sign", "sl/ash", "../x", "-leading-ok"):
        if bad == "-leading-ok":
            continue
        with pytest.raises(tenant_registry.InvalidTenantIdError):
            tenant_registry.validate_tenant_id(bad)
    tenant_registry.validate_tenant_id("dev")
    tenant_registry.validate_tenant_id("Tenant_01")
