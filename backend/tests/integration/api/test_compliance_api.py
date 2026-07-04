"""Integration tests for GET /api/v1/compliance/summary."""

import pytest
from fastapi.testclient import TestClient


def _seed(db, tenant_id: str, check_id: str, title: str, severity: str, status: str, frameworks: list[str]) -> None:
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
def test_compliance_summary_empty(client: TestClient, db_tenant_a) -> None:
    resp = client.get("/api/v1/compliance/summary", headers={"X-Tenant-Id": "tenant-a"})
    assert resp.status_code == 200
    body = resp.json()["data"]
    assert body["frameworks"] == []
    assert isinstance(body["threat_score"], int)
    assert body["top_failing"] == []


@pytest.mark.integration
def test_compliance_summary_with_findings(client: TestClient, db_tenant_a) -> None:
    _seed(db_tenant_a, "tenant-a", "check_s3_public", "S3 Public", "CRITICAL", "FAIL", ["CIS-AWS-2.0", "PCI_DSS"])
    _seed(db_tenant_a, "tenant-a", "check_sg_open", "Open SG", "HIGH", "FAIL", ["CIS-AWS-2.0"])
    _seed(db_tenant_a, "tenant-a", "check_mfa", "MFA Enabled", "MEDIUM", "PASS", ["CIS-AWS-2.0"])

    resp = client.get("/api/v1/compliance/summary", headers={"X-Tenant-Id": "tenant-a"})
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
def test_compliance_summary_threat_score_zero_when_all_pass(client: TestClient, db_tenant_a) -> None:
    _seed(db_tenant_a, "tenant-a", "check_all_pass", "All Good", "LOW", "PASS", ["SOC2"])
    resp = client.get("/api/v1/compliance/summary", headers={"X-Tenant-Id": "tenant-a"})
    assert resp.status_code == 200
    # No FAIL findings → threat_score should be 100 (max)
    assert resp.json()["data"]["threat_score"] == 100


@pytest.mark.integration
def test_compliance_summary_tenant_isolation(client: TestClient, db_tenant_a, db_tenant_b) -> None:
    _seed(db_tenant_a, "tenant-a", "check_a", "Finding A", "CRITICAL", "FAIL", ["CIS-AWS-2.0"])
    # tenant-b has no findings
    resp = client.get("/api/v1/compliance/summary", headers={"X-Tenant-Id": "tenant-b"})
    assert resp.status_code == 200
    assert resp.json()["data"]["frameworks"] == []
