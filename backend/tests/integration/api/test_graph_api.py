"""Integration tests for Graph API (Crown Jewels, AQL Console, Saved Queries, Pathfinding)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

pytestmark = pytest.mark.integration

HEADERS = {"X-Tenant-Id": TEST_TENANT_A}


@pytest.fixture
def client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    c = TestClient(app)
    yield c
    app.dependency_overrides.clear()


@pytest.fixture
def seeded_client(db_tenant_a):
    """Client with a resource pre-inserted for tests that need existing data."""
    init_tenant_schema(db_tenant_a)
    db_tenant_a.collection("resources").insert(
        {
            "_key": "test-crown-res",
            "tenant_id": TEST_TENANT_A,
            "name": "My Crown Jewel",
            "resource_type": "s3_bucket",
            "provider": "aws",
            "is_public": False,
            "status": "active",
        }
    )
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    c = TestClient(app)
    yield c, db_tenant_a
    app.dependency_overrides.clear()


class TestCrownJewels:
    def test_set_crown_jewel_not_found(self, client: TestClient) -> None:
        resp = client.patch(
            "/api/v1/graph/resources/nonexistent-key/crown-jewel",
            json={"is_crown_jewel": True},
            headers=HEADERS,
        )
        assert resp.status_code == 404

    def test_list_crown_jewels_empty(self, client: TestClient) -> None:
        resp = client.get("/api/v1/graph/crown-jewels", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"] == []

    def test_set_and_list_crown_jewel(self, seeded_client) -> None:
        c, _ = seeded_client
        resp = c.patch(
            "/api/v1/graph/resources/test-crown-res/crown-jewel",
            json={"is_crown_jewel": True},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["is_crown_jewel"] is True

        list_resp = c.get("/api/v1/graph/crown-jewels", headers=HEADERS)
        assert list_resp.status_code == 200
        items = list_resp.json()["data"]
        assert any(i.get("_key") == "test-crown-res" for i in items)


class TestAqlConsole:
    def test_read_only_query_succeeds(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/graph/aql",
            json={"query": "RETURN 1"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["rows"] == [1]
        assert body["data"]["count"] == 1
        assert body["data"]["truncated"] is False

    def test_write_query_blocked(self, client: TestClient) -> None:
        for stmt in (
            "INSERT {_key: 'x'} INTO resources",
            "UPDATE {} IN resources",
            "REMOVE 'x' IN resources",
        ):
            resp = client.post(
                "/api/v1/graph/aql",
                json={"query": stmt},
                headers=HEADERS,
            )
            assert resp.status_code == 422, f"Expected 422 for: {stmt}"

    def test_invalid_aql_returns_422(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/graph/aql",
            json={"query": "THIS IS NOT VALID AQL !!!"},
            headers=HEADERS,
        )
        assert resp.status_code == 422

    def test_tenant_id_bind_var_injected(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/graph/aql",
            json={"query": "RETURN @tenant_id"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["rows"] == [TEST_TENANT_A]


class TestSavedQueries:
    def test_list_empty(self, client: TestClient) -> None:
        resp = client.get("/api/v1/graph/queries", headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"] == []

    def test_create_and_list_and_delete(self, client: TestClient) -> None:
        q = "FOR r IN resources FILTER r.tenant_id == @tenant_id RETURN r.name"
        resp = client.post(
            "/api/v1/graph/queries",
            json={"name": "All resource names", "query": q, "description": "test"},
            headers=HEADERS,
        )
        assert resp.status_code == 201
        key = resp.json()["data"]["key"]

        list_resp = client.get("/api/v1/graph/queries", headers=HEADERS)
        assert list_resp.status_code == 200
        names = [item["name"] for item in list_resp.json()["data"]]
        assert "All resource names" in names

        del_resp = client.delete(f"/api/v1/graph/queries/{key}", headers=HEADERS)
        assert del_resp.status_code == 200

    def test_write_query_not_saveable(self, client: TestClient) -> None:
        resp = client.post(
            "/api/v1/graph/queries",
            json={"name": "bad", "query": "INSERT {} INTO resources"},
            headers=HEADERS,
        )
        assert resp.status_code == 422

    def test_delete_nonexistent(self, client: TestClient) -> None:
        resp = client.delete("/api/v1/graph/queries/nonexistent-key", headers=HEADERS)
        assert resp.status_code == 404


class TestExposureSummary:
    def test_returns_valid_structure(self, client: TestClient) -> None:
        resp = client.get("/api/v1/graph/exposure", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "exposed_resources" in data
        assert "exposed_data_assets" in data
        assert "exposed_endpoints" in data
        assert "total" in data
        assert isinstance(data["total"], int)
