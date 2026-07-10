"""Integration tests for GET/POST /api/v1/inventory endpoints.

Rules:
- ArangoDB: real instance via Docker (never mocked)
- Cloud APIs: not involved here — inventory API reads from ArangoDB only
- Celery discover endpoint: discover_aws.delay is mocked (we're testing the HTTP layer, not the task)
"""

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from app.models.inventory import AWSResource, ResourceStatus
from tests.conftest import TEST_TENANT_A

HEADERS = {"X-Tenant-ID": TEST_TENANT_A}


@pytest.fixture
def seeded_db(db_tenant_a):
    """ArangoDB with 5 resources (4 active + 1 deleted)."""
    init_tenant_schema(db_tenant_a)

    resources = [
        AWSResource(
            tenant_id=TEST_TENANT_A,
            resource_type="ec2_instance",
            resource_id="i-001",
            name="web-server",
            arn="arn:aws:ec2:us-east-1:111111111111:instance/i-001",
            region="us-east-1",
            is_public=True,
            tags={"env": "prod"},
        ),
        AWSResource(
            tenant_id=TEST_TENANT_A,
            resource_type="vpc",
            resource_id="vpc-001",
            name="main-vpc",
            arn="arn:aws:ec2:us-east-1:111111111111:vpc/vpc-001",
            region="us-east-1",
        ),
        AWSResource(
            tenant_id=TEST_TENANT_A,
            resource_type="ec2_instance",
            resource_id="i-002",
            name="db-server",
            arn="arn:aws:ec2:eu-west-1:111111111111:instance/i-002",
            region="eu-west-1",
            is_public=False,
        ),
        AWSResource(
            tenant_id=TEST_TENANT_A,
            resource_type="rds_instance",
            resource_id="mydb",
            name="mydb",
            arn="arn:aws:rds:us-east-1:111111111111:db:mydb",
            region="us-east-1",
        ),
        AWSResource(
            tenant_id=TEST_TENANT_A,
            resource_type="ec2_instance",
            resource_id="i-deleted",
            name="old-server",
            arn="arn:aws:ec2:us-east-1:111111111111:instance/i-deleted",
            region="us-east-1",
            status=ResourceStatus.DELETED,
        ),
    ]

    col = db_tenant_a.collection("resources")
    for r in resources:
        doc = r.to_arango_doc()
        col.insert(doc, overwrite=True)

    return db_tenant_a


@pytest.fixture
def api_client(seeded_db):
    """FastAPI TestClient with the get_tenant_db dependency overridden to return the seeded DB."""
    app.dependency_overrides[get_tenant_db] = lambda: seeded_db
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.mark.integration
class TestInventoryListEndpoint:
    def test_list_returns_active_resources_only(self, api_client):
        resp = api_client.get("/api/v1/inventory", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["error"] is None
        assert len(body["data"]) == 4
        assert body["meta"]["total"] == 4

    def test_filter_by_provider(self, api_client):
        resp = api_client.get("/api/v1/inventory?provider=aws", headers=HEADERS)
        assert resp.status_code == 200
        assert all(r["provider"] == "aws" for r in resp.json()["data"])

    def test_filter_by_resource_type(self, api_client):
        resp = api_client.get("/api/v1/inventory?resource_type=ec2_instance", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert all(r["resource_type"] == "ec2_instance" for r in data)
        assert len(data) == 2

    def test_filter_by_region(self, api_client):
        resp = api_client.get("/api/v1/inventory?region=eu-west-1", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 1
        assert data[0]["name"] == "db-server"

    def test_filter_by_multiple_resource_types(self, api_client):
        resp = api_client.get(
            "/api/v1/inventory?resource_type=ec2_instance&resource_type=rds_instance",
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 3
        assert {r["resource_type"] for r in data} == {"ec2_instance", "rds_instance"}

    def test_filter_by_multiple_regions(self, api_client):
        resp = api_client.get(
            "/api/v1/inventory?region=eu-west-1&region=us-east-1",
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 4
        assert {r["region"] for r in data} == {"eu-west-1", "us-east-1"}

    def test_filter_by_multiple_providers_matches_single(self, api_client):
        single = api_client.get("/api/v1/inventory?provider=aws", headers=HEADERS)
        multi = api_client.get("/api/v1/inventory?provider=aws&provider=azure", headers=HEADERS)
        assert single.status_code == multi.status_code == 200
        assert single.json()["meta"]["total"] == multi.json()["meta"]["total"]

    def test_search_by_name_partial(self, api_client):
        resp = api_client.get("/api/v1/inventory?search=web", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 1
        assert data[0]["name"] == "web-server"

    def test_search_by_resource_id(self, api_client):
        resp = api_client.get("/api/v1/inventory?search=i-001", headers=HEADERS)
        assert resp.status_code == 200
        assert len(resp.json()["data"]) >= 1

    def test_pagination_limit_and_offset(self, api_client):
        resp1 = api_client.get("/api/v1/inventory?limit=2&offset=0&sort_by=name", headers=HEADERS)
        resp2 = api_client.get("/api/v1/inventory?limit=2&offset=2&sort_by=name", headers=HEADERS)
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert len(resp1.json()["data"]) == 2
        assert resp1.json()["meta"]["total"] == resp2.json()["meta"]["total"]
        keys1 = {r["key"] for r in resp1.json()["data"]}
        keys2 = {r["key"] for r in resp2.json()["data"]}
        assert keys1.isdisjoint(keys2)

    def test_missing_tenant_header_returns_422(self, api_client):
        resp = api_client.get("/api/v1/inventory")
        assert resp.status_code == 422

    def test_invalid_limit_returns_422(self, api_client):
        resp = api_client.get("/api/v1/inventory?limit=500", headers=HEADERS)
        assert resp.status_code == 422

    def test_filter_by_status_deleted(self, api_client):
        resp = api_client.get("/api/v1/inventory?status=deleted", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert all(r["status"] == "deleted" for r in data)
        assert len(data) == 1


@pytest.mark.integration
class TestInventoryDetailEndpoint:
    def test_get_resource_returns_full_detail(self, api_client):
        list_resp = api_client.get("/api/v1/inventory", headers=HEADERS)
        key = list_resp.json()["data"][0]["key"]
        resp = api_client.get(f"/api/v1/inventory/{key}", headers=HEADERS)
        assert resp.status_code == 200
        detail = resp.json()["data"]
        assert detail["key"] == key
        assert "edges" in detail
        assert isinstance(detail["edges"], list)
        assert "raw_metadata" in detail

    def test_nonexistent_resource_returns_404(self, api_client):
        resp = api_client.get("/api/v1/inventory/nonexistent_key_xyz_abc", headers=HEADERS)
        assert resp.status_code == 404


@pytest.mark.integration
class TestInventoryStatsEndpoint:
    def test_stats_returns_correct_counts(self, api_client):
        resp = api_client.get("/api/v1/inventory/stats", headers=HEADERS)
        assert resp.status_code == 200
        stats = resp.json()["data"]
        assert stats["by_provider"]["aws"] >= 4
        assert stats["by_resource_type"].get("ec2_instance", 0) == 2
        assert "rds_instance" in stats["by_resource_type"]

    def test_stats_returns_region_and_account_breakdown(self, api_client):
        resp = api_client.get("/api/v1/inventory/stats", headers=HEADERS)
        assert resp.status_code == 200
        stats = resp.json()["data"]
        assert stats["by_region"]["us-east-1"] == 3
        assert stats["by_region"]["eu-west-1"] == 1
        # deleted resource excluded from region/account breakdown
        assert sum(stats["by_region"].values()) == 4
        assert stats["by_account_id"]["111111111111"] == 4

    def test_stats_identity_and_data_asset_defaults(self, api_client):
        resp = api_client.get("/api/v1/inventory/stats", headers=HEADERS)
        assert resp.status_code == 200
        stats = resp.json()["data"]
        assert stats["identity_count"] == 0
        assert stats["data_asset_count"] == 0


@pytest.mark.integration
class TestInventoryDiscoverEndpoint:
    def test_trigger_aws_discovery_returns_202(self, api_client, mocker):
        mock_task = mocker.MagicMock()
        mock_task.id = "test-job-id-123"
        mocker.patch("app.api.v1.inventory.discover_aws.delay", return_value=mock_task)

        resp = api_client.post(
            "/api/v1/inventory/discover?provider=aws&regions=us-east-1",
            headers=HEADERS,
        )
        assert resp.status_code == 202
        assert resp.json()["data"]["job_id"] == "test-job-id-123"
        assert resp.json()["data"]["status"] == "queued"

    def test_unsupported_provider_returns_422(self, api_client):
        resp = api_client.post(
            "/api/v1/inventory/discover?provider=azure",
            headers=HEADERS,
        )
        assert resp.status_code == 422
