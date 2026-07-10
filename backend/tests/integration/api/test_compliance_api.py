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


def _find_family(body: dict, family_key: str) -> dict:
    return next(f for f in body["families"] if f["family"] == family_key)


def _find_version(family: dict, version_id: str) -> dict:
    return next(v for v in family["versions"] if v["id"] == version_id)


@pytest.mark.integration
def test_compliance_summary_empty(api_client_a) -> None:
    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]
    assert body["families"] == []
    assert isinstance(body["threat_score"], int)
    assert body["top_failing"] == []


@pytest.mark.integration
def test_compliance_summary_groups_controls_under_one_framework_entry(api_client_a, db_tenant_a) -> None:
    """Regression test for the core bug: each control used to become its own top-level
    "framework" (e.g. 2506 cards instead of ~45). One framework with 3 distinct
    controls must produce exactly one family with one version, not three."""
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "CRITICAL", "FAIL", ["CIS-7.0/1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "HIGH", "FAIL", ["CIS-7.0/2.3"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_3", "Check 3", "MEDIUM", "PASS", ["CIS-7.0/1.4"])

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]

    assert len(body["families"]) == 1
    family = body["families"][0]
    assert family["family"] == "cis-aws"
    assert family["label"] == "CIS AWS Foundations Benchmark"
    assert len(family["versions"]) == 1

    version = family["versions"][0]
    assert version["id"] == "CIS-7.0"
    assert version["pass"] == 1
    assert version["fail"] == 2
    assert version["total"] == 3


@pytest.mark.integration
def test_compliance_summary_unifies_multiple_versions_under_one_family(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_a", "Check A", "HIGH", "FAIL", ["CIS-1.4/1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_b", "Check B", "HIGH", "FAIL", ["CIS-7.0/1.1"])

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    body = resp.json()["data"]

    assert len(body["families"]) == 1
    family = body["families"][0]
    assert family["family"] == "cis-aws"
    version_ids = {v["id"] for v in family["versions"]}
    assert version_ids == {"CIS-1.4", "CIS-7.0"}
    # Latest-looking version first
    assert family["versions"][0]["id"] == "CIS-7.0"


@pytest.mark.integration
def test_compliance_summary_groups_controls_into_sections(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_ac", "AC check", "HIGH", "FAIL", ["NIST-800-53-Revision-5/ac_3"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_ac2", "AC check 2", "HIGH", "PASS", ["NIST-800-53-Revision-5/ac_6"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_cm", "CM check", "MEDIUM", "FAIL", ["NIST-800-53-Revision-5/cm_9_b"])

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    body = resp.json()["data"]

    family = _find_family(body, "nist-800-53")
    version = _find_version(family, "NIST-800-53-Revision-5")
    section_keys = {s["key"] for s in version["sections"]}
    assert section_keys == {"ac", "cm"}

    ac_section = next(s for s in version["sections"] if s["key"] == "ac")
    assert ac_section["pass"] == 1
    assert ac_section["fail"] == 1
    assert "Access Control" in ac_section["label"]


@pytest.mark.integration
def test_compliance_summary_bare_framework_mapping_lands_in_general_section(api_client_a, db_tenant_a) -> None:
    """Checkov/IaC findings map to a bare framework id with no /control suffix."""
    _seed(db_tenant_a, TEST_TENANT_A, "ckv_1", "IaC check", "HIGH", "FAIL", ["SOC2"])

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    body = resp.json()["data"]

    family = _find_family(body, "SOC2")
    version = family["versions"][0]
    assert version["id"] == "SOC2"
    assert version["sections"] == [
        {"key": "general", "label": "General", "pass": 0, "fail": 1, "total": 1, "score": 0.0}
    ]


@pytest.mark.integration
def test_compliance_summary_top_failing_scoped_by_framework(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "cis_check", "CIS failing check", "CRITICAL", "FAIL", ["CIS-7.0/1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "soc2_check", "SOC2 failing check", "CRITICAL", "FAIL", ["SOC2"])

    resp_all = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    all_check_ids = {t["check_id"] for t in resp_all.json()["data"]["top_failing"]}
    assert all_check_ids == {"cis_check", "soc2_check"}

    resp_scoped = api_client_a.get("/api/v1/compliance/summary?framework=CIS-7.0", headers=HEADERS_A)
    scoped_check_ids = {t["check_id"] for t in resp_scoped.json()["data"]["top_failing"]}
    assert scoped_check_ids == {"cis_check"}


@pytest.mark.integration
def test_compliance_summary_threat_score_max_when_all_pass(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_all_pass", "All Good", "LOW", "PASS", ["SOC2"])
    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    assert resp.status_code == 200
    # No FAIL findings → threat_score should be 100 (max)
    assert resp.json()["data"]["threat_score"] == 100


@pytest.mark.integration
def test_compliance_summary_tenant_isolation(api_client_b, db_tenant_a) -> None:
    # db_tenant_a schema may not be initialized; init it explicitly before seeding
    init_tenant_schema(db_tenant_a)
    _seed(db_tenant_a, TEST_TENANT_A, "check_a", "Finding A", "CRITICAL", "FAIL", ["CIS-7.0/1.1"])
    # tenant-b has no findings — api_client_b is scoped to tenant-b's database
    resp = api_client_b.get("/api/v1/compliance/summary", headers=HEADERS_B)
    assert resp.status_code == 200
    assert resp.json()["data"]["families"] == []
