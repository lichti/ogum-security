"""Integration tests for the Saved Views API (/api/v1/views).

Rules:
- ArangoDB: real instance via Docker (never mocked)
- Views are scoped per-user in this phase (Epic 06/RBAC introduces shared views)
"""

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

TENANT_A_HEADERS = {"X-Tenant-ID": TEST_TENANT_A, "X-User-Id": "user-alice"}
TENANT_A_OTHER_USER_HEADERS = {"X-Tenant-ID": TEST_TENANT_A, "X-User-Id": "user-bob"}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _create_view(api_client, headers=TENANT_A_HEADERS, **overrides):
    payload = {
        "scope": "inventory",
        "name": "My Custom View",
        "filters": {"provider": ["aws"]},
        "columns": ["name", "risk_score"],
        **overrides,
    }
    resp = api_client.post("/api/v1/views", json=payload, headers=headers)
    assert resp.status_code == 201
    return resp.json()["data"]


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/views
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestListViewsEndpoint:
    def test_new_user_sees_only_system_views(self, api_client):
        resp = api_client.get("/api/v1/views", headers=TENANT_A_HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 3
        assert all(v["is_system"] for v in data)

    def test_missing_tenant_header_returns_422(self, api_client):
        resp = api_client.get("/api/v1/views", headers={"X-User-Id": "user-alice"})
        assert resp.status_code == 422

    def test_missing_user_header_returns_422(self, api_client):
        resp = api_client.get("/api/v1/views", headers={"X-Tenant-ID": TEST_TENANT_A})
        assert resp.status_code == 422

    def test_filters_by_scope(self, api_client):
        resp = api_client.get("/api/v1/views?scope=findings", headers=TENANT_A_HEADERS)
        assert resp.json()["data"] == []

    def test_user_sees_own_view_plus_system_views(self, api_client):
        _create_view(api_client)
        resp = api_client.get("/api/v1/views", headers=TENANT_A_HEADERS)
        data = resp.json()["data"]
        assert len(data) == 4
        assert any(v["name"] == "My Custom View" and not v["is_system"] for v in data)

    def test_user_does_not_see_another_users_view(self, api_client):
        _create_view(api_client, headers=TENANT_A_HEADERS)
        resp = api_client.get("/api/v1/views", headers=TENANT_A_OTHER_USER_HEADERS)
        data = resp.json()["data"]
        assert all(v["is_system"] for v in data)


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/v1/views
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestCreateViewEndpoint:
    def test_create_view_happy_path(self, api_client):
        view = _create_view(api_client)
        assert view["name"] == "My Custom View"
        assert view["scope"] == "inventory"
        assert view["is_system"] is False
        assert view["pinned"] is False
        assert view["owner"] == "user-alice"

    def test_create_view_invalid_scope_returns_422(self, api_client):
        resp = api_client.post(
            "/api/v1/views",
            json={"scope": "not-a-scope", "name": "Bad View"},
            headers=TENANT_A_HEADERS,
        )
        assert resp.status_code == 422

    def test_create_view_missing_name_returns_422(self, api_client):
        resp = api_client.post(
            "/api/v1/views",
            json={"scope": "inventory"},
            headers=TENANT_A_HEADERS,
        )
        assert resp.status_code == 422


# ──────────────────────────────────────────────────────────────────────────────
# PATCH /api/v1/views/{view_id}
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestUpdateViewEndpoint:
    def test_pin_own_view(self, api_client):
        view = _create_view(api_client)
        resp = api_client.patch(f"/api/v1/views/{view['key']}", json={"pinned": True}, headers=TENANT_A_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"]["pinned"] is True

    def test_rename_own_view(self, api_client):
        view = _create_view(api_client)
        resp = api_client.patch(f"/api/v1/views/{view['key']}", json={"name": "Renamed"}, headers=TENANT_A_HEADERS)
        assert resp.json()["data"]["name"] == "Renamed"

    def test_update_nonexistent_view_returns_404(self, api_client):
        resp = api_client.patch("/api/v1/views/ghost-view", json={"pinned": True}, headers=TENANT_A_HEADERS)
        assert resp.status_code == 404

    def test_cannot_update_another_users_view(self, api_client):
        view = _create_view(api_client, headers=TENANT_A_HEADERS)
        resp = api_client.patch(
            f"/api/v1/views/{view['key']}", json={"pinned": True}, headers=TENANT_A_OTHER_USER_HEADERS
        )
        assert resp.status_code == 404

    def test_cannot_update_system_view(self, api_client):
        resp = api_client.patch(
            "/api/v1/views/system-internet-facing-critical",
            json={"pinned": True},
            headers=TENANT_A_HEADERS,
        )
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# DELETE /api/v1/views/{view_id}
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestDeleteViewEndpoint:
    def test_delete_own_view(self, api_client):
        view = _create_view(api_client)
        resp = api_client.delete(f"/api/v1/views/{view['key']}", headers=TENANT_A_HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"]["deleted"] is True

        list_resp = api_client.get("/api/v1/views", headers=TENANT_A_HEADERS)
        assert all(v["is_system"] for v in list_resp.json()["data"])

    def test_delete_nonexistent_view_returns_404(self, api_client):
        resp = api_client.delete("/api/v1/views/ghost-view", headers=TENANT_A_HEADERS)
        assert resp.status_code == 404

    def test_cannot_delete_another_users_view(self, api_client):
        view = _create_view(api_client, headers=TENANT_A_HEADERS)
        resp = api_client.delete(f"/api/v1/views/{view['key']}", headers=TENANT_A_OTHER_USER_HEADERS)
        assert resp.status_code == 404

    def test_cannot_delete_system_view(self, api_client):
        resp = api_client.delete("/api/v1/views/system-unencrypted-data-storage", headers=TENANT_A_HEADERS)
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# Tenant isolation (security-critical)
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
@pytest.mark.security
class TestViewsTenantIsolation:
    def test_view_created_in_tenant_a_not_visible_in_tenant_b(self, api_client, db_tenant_b):
        _create_view(api_client, headers=TENANT_A_HEADERS)

        init_tenant_schema(db_tenant_b)
        app.dependency_overrides[get_tenant_db] = lambda: db_tenant_b
        client_b = TestClient(app)
        resp = client_b.get("/api/v1/views", headers={"X-Tenant-ID": TEST_TENANT_B, "X-User-Id": "user-alice"})
        data = resp.json()["data"]
        assert all(v["is_system"] for v in data), "Tenant B must never see Tenant A's saved views"
