"""US-02.13 (emenda do plano v1) — allowlist de coleções no console AQL.

O console nega acesso a `tenant_config` (referências de credencial), `audit_log`
e qualquer coleção fora da allowlist — por nome literal ou bind `@coll`.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import TEST_TENANT_A

pytestmark = pytest.mark.security

HEADERS = {"X-Tenant-Id": TEST_TENANT_A}


@pytest.fixture
def client(db_tenant_a, _registered_test_tenants) -> TestClient:
    return TestClient(app)


def test_tenant_config_is_denied(client):
    response = client.post(
        "/api/v1/graph/aql",
        json={"query": "FOR c IN tenant_config RETURN c"},
        headers=HEADERS,
    )
    assert response.status_code == 422
    assert "tenant_config" in response.json()["detail"]


def test_tenant_config_via_coll_bind_is_denied(client):
    response = client.post(
        "/api/v1/graph/aql",
        json={"query": "FOR c IN @@coll RETURN c", "bind_vars": {"@coll": "tenant_config"}},
        headers=HEADERS,
    )
    assert response.status_code == 422
    assert "tenant_config" in response.json()["detail"]


def test_audit_log_is_denied(client):
    response = client.post(
        "/api/v1/graph/aql",
        json={"query": "FOR a IN audit_log RETURN a"},
        headers=HEADERS,
    )
    assert response.status_code == 422


def test_allowed_collection_executes(client):
    response = client.post(
        "/api/v1/graph/aql",
        json={"query": "FOR r IN resources LIMIT 5 RETURN r._key"},
        headers=HEADERS,
    )
    assert response.status_code == 200
    assert response.json()["data"]["rows"] == []


def test_unknown_collection_returns_422(client):
    response = client.post(
        "/api/v1/graph/aql",
        json={"query": "FOR x IN nonexistent_collection RETURN x"},
        headers=HEADERS,
    )
    assert response.status_code == 422
