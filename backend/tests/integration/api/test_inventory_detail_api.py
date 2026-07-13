"""Integration tests for the per-resource detail endpoints added in Epic 14 Sprint 2:
GET /api/v1/inventory/{resource_key}/summary and .../blast-radius.

Rules:
- ArangoDB: real instance via Docker (never mocked)
"""

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from app.models.inventory import AWSResource
from tests.conftest import TEST_TENANT_A

HEADERS = {"X-Tenant-ID": TEST_TENANT_A}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def seeded_resource(db_tenant_a):
    resource = AWSResource(
        tenant_id=TEST_TENANT_A,
        resource_type="ec2_instance",
        resource_id="i-detail-001",
        name="web-server",
        arn="arn:aws:ec2:us-east-1:111111111111:instance/i-detail-001",
        region="us-east-1",
        is_public=True,
    )
    db_tenant_a.collection("resources").insert(resource.to_arango_doc())
    return resource.arango_key()


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/inventory/{resource_key}/summary
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestResourceSummaryEndpoint:
    def test_returns_404_for_unknown_resource(self, api_client):
        resp = api_client.get("/api/v1/inventory/does-not-exist/summary", headers=HEADERS)
        assert resp.status_code == 404

    def test_narrative_mentions_no_findings_when_clean(self, api_client, seeded_resource):
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/summary", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "No open findings" in data["narrative"]
        assert data["finding_counts"] == {}
        assert data["attack_path_count"] == 0
        assert data["deep_links"] == []

    def test_uses_deterministic_template_fallback(self, api_client, seeded_resource):
        """No LLM provider is wired up yet (Epic 05) — every summary is template-generated."""
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/summary", headers=HEADERS)
        assert resp.json()["data"]["generated_by"] == "template"

    def test_narrative_mentions_public_exposure(self, api_client, seeded_resource):
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/summary", headers=HEADERS)
        assert "publicly exposed" in resp.json()["data"]["narrative"]

    def test_narrative_includes_finding_breakdown_and_deep_link(self, api_client, seeded_resource, db_tenant_a):
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-1",
                "tenant_id": TEST_TENANT_A,
                "resource_id": "i-detail-001",
                "check_id": "ec2_public",
                "severity": "HIGH",
                "status": "FAIL",
            }
        )
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-2",
                "tenant_id": TEST_TENANT_A,
                "resource_id": "i-detail-001",
                "check_id": "ec2_encryption",
                "severity": "CRITICAL",
                "status": "FAIL",
            }
        )

        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/summary", headers=HEADERS)
        data = resp.json()["data"]
        assert data["finding_counts"] == {"HIGH": 1, "CRITICAL": 1}
        assert "2 open findings" in data["narrative"]
        assert any(
            link["tab"] == "risk" and link["subtab"] == "alerts" and link["count"] == 2 for link in data["deep_links"]
        )

    def test_findings_from_other_tenant_not_counted(self, api_client, seeded_resource, db_tenant_a):
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-other-tenant",
                "tenant_id": "some-other-tenant",
                "resource_id": "i-detail-001",
                "check_id": "ec2_public",
                "severity": "HIGH",
                "status": "FAIL",
            }
        )
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/summary", headers=HEADERS)
        assert resp.json()["data"]["finding_counts"] == {}

    def test_muted_findings_are_not_counted_as_open(self, api_client, seeded_resource, db_tenant_a):
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-muted",
                "tenant_id": TEST_TENANT_A,
                "resource_id": "i-detail-001",
                "check_id": "ec2_public",
                "severity": "HIGH",
                "status": "MUTED",
            }
        )
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/summary", headers=HEADERS)
        assert resp.json()["data"]["finding_counts"] == {}


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/inventory/{resource_key}/blast-radius
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestBlastRadiusEndpoint:
    def test_returns_404_for_unknown_resource(self, api_client):
        resp = api_client.get("/api/v1/inventory/does-not-exist/blast-radius", headers=HEADERS)
        assert resp.status_code == 404

    def test_empty_blast_radius_for_isolated_resource(self, api_client, seeded_resource):
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/blast-radius", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["grouped_counts"] == {}

    def test_blast_radius_includes_directly_connected_resource(self, api_client, seeded_resource, db_tenant_a):
        vpc = AWSResource(
            tenant_id=TEST_TENANT_A,
            resource_type="vpc",
            resource_id="vpc-blast-001",
            name="main-vpc",
            arn="arn:aws:ec2:us-east-1:111111111111:vpc/vpc-blast-001",
            region="us-east-1",
        )
        vpc_key = vpc.arango_key()
        db_tenant_a.collection("resources").insert(vpc.to_arango_doc())

        db_tenant_a.collection("BELONGS_TO").insert(
            {
                "_from": f"resources/{seeded_resource}",
                "_to": f"resources/{vpc_key}",
                "tenant_id": TEST_TENANT_A,
            }
        )

        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/blast-radius", headers=HEADERS)
        data = resp.json()["data"]
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["id"] == f"resources/{vpc_key}"
        assert data["nodes"][0]["resource_type"] == "vpc"
        assert data["grouped_counts"] == {"vpc": 1}
        assert data["edges"][0]["edge_type"] == "BELONGS_TO"

    def test_blast_radius_from_other_tenant_resource_not_visible(self, api_client, seeded_resource, db_tenant_a):
        """A BELONGS_TO edge pointing at another tenant's resource must not leak it into the graph."""
        db_tenant_a.collection("resources").insert(
            {
                "_key": "other-tenant-res",
                "tenant_id": "some-other-tenant",
                "resource_type": "vpc",
                "name": "not-yours",
            }
        )
        db_tenant_a.collection("BELONGS_TO").insert(
            {
                "_from": f"resources/{seeded_resource}",
                "_to": "resources/other-tenant-res",
                "tenant_id": TEST_TENANT_A,
            }
        )

        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/blast-radius", headers=HEADERS)
        assert resp.json()["data"]["nodes"] == []
