"""Integration tests for GET /api/v1/identities and /api/v1/identities/{key}/permissions."""

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

HEADERS = {"X-Tenant-ID": TEST_TENANT_A}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed_identity(db, key: str, **kwargs) -> dict:
    doc = {
        "_key": key,
        "tenant_id": TEST_TENANT_A,
        "provider": "aws",
        "identity_type": "iam_role",
        "name": kwargs.get("name", key),
        "arn": kwargs.get("arn", f"arn:aws:iam::123456789012:role/{key}"),
        "account_id": "123456789012",
        "policies": kwargs.get("policies", []),
        "granted_actions": kwargs.get("granted_actions", []),
        "has_admin_policy": kwargs.get("has_admin_policy", False),
        "dangerous_permissions": kwargs.get("dangerous_permissions", []),
        "escalation_paths_count": kwargs.get("escalation_paths_count", 0),
        "risk_score": kwargs.get("risk_score", 0),
        "status": "active",
    }
    db.collection("identities").insert(doc, overwrite=True)
    return doc


@pytest.mark.integration
class TestListIdentities:
    def test_empty_returns_empty_list(self, api_client):
        resp = api_client.get("/api/v1/identities", headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"] == []

    def test_lists_seeded_identities(self, api_client, db_tenant_a):
        _seed_identity(db_tenant_a, "role-a", name="RoleA", risk_score=50)
        _seed_identity(db_tenant_a, "role-b", name="RoleB", risk_score=10)
        resp = api_client.get("/api/v1/identities", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 2

    def test_sorted_by_risk_score_desc(self, api_client, db_tenant_a):
        _seed_identity(db_tenant_a, "low-risk", name="LowRisk", risk_score=10)
        _seed_identity(db_tenant_a, "high-risk", name="HighRisk", risk_score=80)
        resp = api_client.get("/api/v1/identities", headers=HEADERS)
        items = resp.json()["data"]
        assert items[0]["key"] == "high-risk"
        assert items[1]["key"] == "low-risk"

    def test_filter_by_provider(self, api_client, db_tenant_a):
        _seed_identity(db_tenant_a, "aws-role", name="AWSRole")
        azure_doc = _seed_identity(db_tenant_a, "azure-sp", name="AzureSP")
        azure_doc["provider"] = "azure"
        db_tenant_a.collection("identities").update({"_key": "azure-sp", "provider": "azure"})

        resp = api_client.get("/api/v1/identities?provider=aws", headers=HEADERS)
        items = resp.json()["data"]
        assert all(i["provider"] == "aws" for i in items)

    def test_filter_only_dangerous(self, api_client, db_tenant_a):
        _seed_identity(db_tenant_a, "safe-role", name="SafeRole", dangerous_permissions=[])
        _seed_identity(
            db_tenant_a,
            "danger-role",
            name="DangerRole",
            dangerous_permissions=[{"action": "iam:*", "risk": "wildcard"}],
        )
        resp = api_client.get("/api/v1/identities?only_dangerous=true", headers=HEADERS)
        items = resp.json()["data"]
        assert len(items) == 1
        assert items[0]["key"] == "danger-role"

    def test_pagination_limit(self, api_client, db_tenant_a):
        for i in range(5):
            _seed_identity(db_tenant_a, f"role-{i}", name=f"Role{i}")
        resp = api_client.get("/api/v1/identities?limit=2&offset=0", headers=HEADERS)
        assert resp.status_code == 200
        assert len(resp.json()["data"]) == 2
        assert resp.json()["meta"]["total"] == 5

    def test_missing_tenant_header_returns_422(self, api_client):
        resp = api_client.get("/api/v1/identities")
        assert resp.status_code == 422


@pytest.mark.integration
class TestIdentityPermissions:
    def test_returns_404_for_nonexistent_identity(self, api_client):
        resp = api_client.get("/api/v1/identities/nonexistent-key/permissions", headers=HEADERS)
        assert resp.status_code == 404

    def test_returns_identity_with_no_dangerous_permissions(self, api_client, db_tenant_a):
        _seed_identity(db_tenant_a, "safe-role", name="SafeRole", granted_actions=["s3:GetObject"])
        resp = api_client.get("/api/v1/identities/safe-role/permissions", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["identity_key"] == "safe-role"
        assert data["dangerous_permissions"] == []
        assert data["dangerous_permissions_count"] == 0

    def test_detects_dangerous_permission_in_granted_actions(self, api_client, db_tenant_a):
        _seed_identity(
            db_tenant_a,
            "risky-role",
            name="RiskyRole",
            granted_actions=["iam:PassRole", "s3:GetObject"],
        )
        resp = api_client.get("/api/v1/identities/risky-role/permissions", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["dangerous_permissions_count"] >= 1
        actions = [p["action"] for p in data["dangerous_permissions"]]
        assert "iam:PassRole" in actions

    def test_detects_administrator_access_policy(self, api_client, db_tenant_a):
        _seed_identity(
            db_tenant_a,
            "admin-role",
            name="AdminRole",
            policies=["arn:aws:iam::aws:policy/AdministratorAccess"],
        )
        resp = api_client.get("/api/v1/identities/admin-role/permissions", headers=HEADERS)
        data = resp.json()["data"]
        assert data["dangerous_permissions_count"] >= 1

    def test_response_includes_all_expected_fields(self, api_client, db_tenant_a):
        _seed_identity(db_tenant_a, "full-role", name="FullRole")
        resp = api_client.get("/api/v1/identities/full-role/permissions", headers=HEADERS)
        data = resp.json()["data"]
        for field in (
            "identity_id",
            "identity_key",
            "name",
            "identity_type",
            "provider",
            "dangerous_permissions",
            "dangerous_permissions_count",
            "escalation_chains",
            "escalation_paths_count",
        ):
            assert field in data, f"Missing field: {field}"

    def test_missing_tenant_header_returns_422(self, api_client):
        resp = api_client.get("/api/v1/identities/any-key/permissions")
        assert resp.status_code == 422
