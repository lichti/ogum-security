"""Integration tests for Epic 14 Sprint 3 findings endpoints:
GET/PUT /api/v1/settings/sla, GET /api/v1/findings/sla-summary,
GET /api/v1/findings/{key}/exposure-path.

Rules:
- ArangoDB: real instance via Docker (never mocked)
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

HEADERS = {"X-Tenant-ID": TEST_TENANT_A, "X-Tenant-Id": TEST_TENANT_A}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed_finding(db, key: str, detected_at: str, severity: str = "CRITICAL", status: str = "FAIL", **overrides):
    doc = {
        "_key": key,
        "finding_id": key,
        "tenant_id": TEST_TENANT_A,
        "check_id": "check_s3_public",
        "title": "Public S3 Bucket",
        "description": "Bucket is publicly accessible",
        "resource_id": f"arn:aws:s3:::{key}",
        "resource_arn": f"arn:aws:s3:::{key}",
        "resource_type": "s3_bucket",
        "severity": severity,
        "status": status,
        "provider": "aws",
        "region": "us-east-1",
        "account_id": "123456789012",
        "framework_mapping": [],
        "source": "cspm",
        "detected_at": detected_at,
        "updated_at": detected_at,
        "remediation": None,
        "remediation_code": None,
        "mute_reason": None,
        "scan_job_id": None,
        "raw_output": {},
        **overrides,
    }
    db.collection("findings").insert(doc, overwrite=True)
    return doc


# ──────────────────────────────────────────────────────────────────────────────
# GET/PUT /api/v1/settings/sla
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSlaSettingsEndpoint:
    def test_get_returns_defaults_when_unset(self, api_client):
        resp = api_client.get("/api/v1/settings/sla", headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"] == {
            "critical_days": 7,
            "high_days": 30,
            "medium_days": 90,
            "low_days": 180,
        }

    def test_put_persists_partial_update(self, api_client):
        resp = api_client.put("/api/v1/settings/sla", json={"critical_days": 3}, headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"]["critical_days"] == 3
        assert resp.json()["data"]["high_days"] == 30

        resp = api_client.get("/api/v1/settings/sla", headers=HEADERS)
        assert resp.json()["data"]["critical_days"] == 3


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/findings/sla-summary
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestSlaSummaryEndpoint:
    def test_classifies_findings_by_sla_state(self, api_client, db_tenant_a):
        now = datetime.now(UTC)
        _seed_finding(db_tenant_a, "within", (now - timedelta(days=1)).isoformat(), severity="CRITICAL")
        _seed_finding(db_tenant_a, "overdue", (now - timedelta(days=10)).isoformat(), severity="CRITICAL")
        _seed_finding(db_tenant_a, "passed", (now - timedelta(days=10)).isoformat(), severity="CRITICAL", status="PASS")

        resp = api_client.get("/api/v1/findings/sla-summary", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["within_sla"] == 1
        assert data["overdue"] == 1
        assert data["at_risk"] == 0


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/findings/{finding_key}/exposure-path
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
class TestFindingExposurePathEndpoint:
    def test_returns_404_for_unknown_finding(self, api_client):
        resp = api_client.get("/api/v1/findings/does-not-exist/exposure-path", headers=HEADERS)
        assert resp.status_code == 404

    def test_empty_graph_when_resource_has_no_exposure_edges(self, api_client, db_tenant_a):
        from app.models.inventory import AWSResource

        resource = AWSResource(
            tenant_id=TEST_TENANT_A,
            resource_type="s3_bucket",
            resource_id="bucket-exposure-001",
            name="my-bucket",
            arn="arn:aws:s3:::bucket-exposure-001",
        )
        db_tenant_a.collection("resources").insert(resource.to_arango_doc())
        finding = _seed_finding(
            db_tenant_a, "find-exposure-1", datetime.now(UTC).isoformat(), resource_id="bucket-exposure-001"
        )

        resp = api_client.get(f"/api/v1/findings/{finding['_key']}/exposure-path", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["nodes"] == []
        assert data["edges"] == []
