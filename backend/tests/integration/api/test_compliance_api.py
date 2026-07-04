"""Integration tests for GET /api/v1/compliance/summary."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

HEADERS_A = {"X-Tenant-Id": TEST_TENANT_A}
HEADERS_B = {"X-Tenant-Id": TEST_TENANT_B}


@pytest.fixture
def api_client_a(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def api_client_b(db_tenant_b):
    init_tenant_schema(db_tenant_b)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_b
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed(
    db,
    tenant_id: str,
    check_id: str,
    title: str,
    severity: str,
    status: str,
    frameworks: list[str],
) -> None:
    db.collection("findings").insert(
        {
            "tenant_id": tenant_id,
            "check_id": check_id,
            "title": title,
            "description": "desc",
            "resource_id": "res-001",
            "resource_arn": None,
            "resource_type": "s3_bucket",
            "severity": severity,
            "status": status,
            "provider": "aws",
            "region": "us-east-1",
            "account_id": "111111111111",
            "framework_mapping": frameworks,
            "remediation": None,
            "remediation_code": None,
            "source": "cspm",
            "detected_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "mute_reason": None,
            "scan_job_id": None,
        },
        overwrite=False,
    )


@pytest.mark.integration
def test_compliance_summary_empty(api_client_a) -> None:
    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]
    assert body["frameworks"] == []
    assert isinstance(body["threat_score"], int)
    assert body["top_failing"] == []


@pytest.mark.integration
def test_compliance_summary_with_findings(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_s3_public", "S3 Public", "CRITICAL", "FAIL", ["CIS-AWS-2.0", "PCI_DSS"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_sg_open", "Open SG", "HIGH", "FAIL", ["CIS-AWS-2.0"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_mfa", "MFA Enabled", "MEDIUM", "PASS", ["CIS-AWS-2.0"])

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]

    fw_ids = {f["id"] for f in body["frameworks"]}
    assert "CIS-AWS-2.0" in fw_ids
    assert "PCI_DSS" in fw_ids

    cis = next(f for f in body["frameworks"] if f["id"] == "CIS-AWS-2.0")
    assert cis["fail"] == 2
    assert cis["pass"] == 1
    assert cis["total"] == 3

    pci = next(f for f in body["frameworks"] if f["id"] == "PCI_DSS")
    assert pci["fail"] == 1
    assert pci["pass"] == 0

    assert 0 <= body["threat_score"] <= 100
    assert len(body["top_failing"]) >= 1


@pytest.mark.integration
def test_compliance_summary_threat_score_max_when_all_pass(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_all_pass", "All Good", "LOW", "PASS", ["SOC2"])
    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    assert resp.status_code == 200
    # No FAIL findings → threat_score should be 100 (max)
    assert resp.json()["data"]["threat_score"] == 100


@pytest.mark.integration
def test_compliance_summary_tenant_isolation(api_client_b, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_a", "Finding A", "CRITICAL", "FAIL", ["CIS-AWS-2.0"])
    # tenant-b has no findings — api_client_b is scoped to tenant-b
    resp = api_client_b.get("/api/v1/compliance/summary", headers=HEADERS_B)
    assert resp.status_code == 200
    assert resp.json()["data"]["frameworks"] == []
