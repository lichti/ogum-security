"""Integration tests for Epic 14 Sprint 3 per-resource endpoints:
GET /api/v1/inventory/{resource_key}/software and .../compliance.

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
        resource_id="i-sw-001",
        name="web-server",
        arn="arn:aws:ec2:us-east-1:111111111111:instance/i-sw-001",
        region="us-east-1",
    )
    db_tenant_a.collection("resources").insert(resource.to_arango_doc())
    return resource.arango_key()


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/inventory/{resource_key}/software
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSoftwareInventoryEndpoint:
    def test_returns_404_for_unknown_resource(self, api_client):
        resp = api_client.get("/api/v1/inventory/does-not-exist/software", headers=HEADERS)
        assert resp.status_code == 404

    def test_no_sbom_returns_empty_response(self, api_client, seeded_resource):
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/software", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["installed_packages"] == []
        assert data["licenses"] == []
        assert data["sbom_generated_at"] is None

    def test_packages_and_licenses_derived_from_sbom(self, api_client, seeded_resource, db_tenant_a):
        sbom_doc = {
            "_key": "sbom-1",
            "tenant_id": TEST_TENANT_A,
            "resource_id": "i-sw-001",
            "format": "cyclonedx",
            "generated_at": "2026-07-01T00:00:00+00:00",
            "content": {
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": "2.31.0",
                        "licenses": [{"license": {"id": "Apache-2.0"}}],
                    },
                    {
                        "type": "library",
                        "name": "old-gpl-lib",
                        "version": "1.0.0",
                        "licenses": [{"license": {"id": "GPL-2.0"}}],
                        "properties": [{"name": "aquasecurity:trivy:FilePath", "value": "/usr/lib/old-gpl-lib"}],
                    },
                    {"type": "operating-system", "name": "debian", "version": "11"},
                ]
            },
        }
        db_tenant_a.collection("sboms").insert(sbom_doc)
        db_tenant_a.collection("HAS_SBOM").insert(
            {
                "_key": "sbom-edge-1",
                "_from": f"resources/{seeded_resource}",
                "_to": "sboms/sbom-1",
                "tenant_id": TEST_TENANT_A,
            }
        )
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-cve-1",
                "tenant_id": TEST_TENANT_A,
                "resource_id": "i-sw-001",
                "check_id": "side_scanning/cve/CVE-2024-1234",
                "severity": "HIGH",
                "status": "FAIL",
                "source": "side_scanning",
                "raw_output": {"package": "requests"},
            }
        )

        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/software", headers=HEADERS)
        data = resp.json()["data"]

        assert data["sbom_generated_at"] == "2026-07-01T00:00:00+00:00"
        packages_by_name = {p["name"]: p for p in data["installed_packages"]}
        assert set(packages_by_name) == {"requests", "old-gpl-lib"}
        assert packages_by_name["requests"]["cve_ids"] == ["CVE-2024-1234"]
        assert packages_by_name["old-gpl-lib"]["filesystem_path"] == "/usr/lib/old-gpl-lib"

        licenses_by_id = {lic["license_id"]: lic for lic in data["licenses"]}
        assert licenses_by_id["Apache-2.0"]["category"] == "permissive"
        assert licenses_by_id["Apache-2.0"]["deprecated"] is False
        assert licenses_by_id["GPL-2.0"]["category"] == "copyleft"
        assert licenses_by_id["GPL-2.0"]["deprecated"] is True


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/inventory/{resource_key}/compliance
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestResourceComplianceEndpoint:
    def test_returns_404_for_unknown_resource(self, api_client):
        resp = api_client.get("/api/v1/inventory/does-not-exist/compliance", headers=HEADERS)
        assert resp.status_code == 404

    def test_no_findings_returns_empty_frameworks(self, api_client, seeded_resource):
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/compliance", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available_frameworks"] == []
        assert data["selected_framework"] is None
        assert data["controls"] == []

    def test_defaults_to_first_available_framework_with_controls(self, api_client, seeded_resource, db_tenant_a):
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-compliance-1",
                "tenant_id": TEST_TENANT_A,
                "resource_id": "i-sw-001",
                "check_id": "ec2_public",
                "title": "EC2 instance is publicly reachable",
                "severity": "HIGH",
                "status": "FAIL",
                "framework_mapping": ["CIS-2.0/1.1"],
            }
        )

        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/compliance", headers=HEADERS)
        data = resp.json()["data"]

        assert len(data["available_frameworks"]) == 1
        assert data["available_frameworks"][0]["id"] == "CIS-2.0"
        assert data["selected_framework"] == "CIS-2.0"
        assert len(data["controls"]) == 1
        assert data["controls"][0]["finding_key"] == "find-compliance-1"
        assert data["controls"][0]["status"] == "FAIL"

    def test_findings_from_other_tenant_not_counted(self, api_client, seeded_resource, db_tenant_a):
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-other-tenant",
                "tenant_id": "some-other-tenant",
                "resource_id": "i-sw-001",
                "check_id": "ec2_public",
                "title": "EC2 instance is publicly reachable",
                "severity": "HIGH",
                "status": "FAIL",
                "framework_mapping": ["CIS-2.0/1.1"],
            }
        )
        resp = api_client.get(f"/api/v1/inventory/{seeded_resource}/compliance", headers=HEADERS)
        assert resp.json()["data"]["available_frameworks"] == []
