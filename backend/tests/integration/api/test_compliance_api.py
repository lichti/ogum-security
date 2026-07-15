"""Integration tests for GET /api/v1/compliance/summary and /frameworks/{id}[/trend]."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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


@pytest.mark.integration
def test_framework_detail_score_by_control_diverges_from_score_by_asset(api_client_a, db_tenant_a) -> None:
    """One control with 2 PASS + 1 FAIL: by-asset it's 2/3 = 66.7%, but by-control the
    control counts as a single Fail (any asset failing it fails the control) = 0%."""
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "PASS", ["CIS-7.0/2.1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "HIGH", "PASS", ["CIS-7.0/2.1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_3", "Check 3", "HIGH", "FAIL", ["CIS-7.0/2.1.1"])

    resp = api_client_a.get("/api/v1/compliance/frameworks/CIS-7.0", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]

    assert body["id"] == "CIS-7.0"
    assert body["score_by_asset"] == 66.7
    assert body["score_by_control"] == 0.0
    assert body["pass_count"] == 0
    assert body["fail_count"] == 1
    assert body["catalog_available"] is True
    assert body["unscored_count"] > 0  # every other CIS-7.0 catalog control has no finding yet


@pytest.mark.integration
def test_framework_detail_unscored_controls_from_real_catalog(api_client_a, db_tenant_a) -> None:
    """GDPR has exactly 3 catalog controls (article_25/30/32) — seed 2, leave 1 untouched."""
    _seed(db_tenant_a, TEST_TENANT_A, "gdpr_pass", "Article 25 check", "MEDIUM", "PASS", ["GDPR/article_25"])
    _seed(db_tenant_a, TEST_TENANT_A, "gdpr_fail", "Article 30 check", "HIGH", "FAIL", ["GDPR/article_30"])

    resp = api_client_a.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]

    assert body["total_controls"] == 3
    assert body["pass_count"] == 1
    assert body["fail_count"] == 1
    assert body["unscored_count"] == 1
    assert body["score_by_control"] == 50.0

    all_requirements = [
        r
        for s in body["sections"]
        for r in (s["requirements"] + [rr for sub in s["subsections"] for rr in sub["requirements"]])
    ]
    unscored = next(r for r in all_requirements if r["control_id"] == "article_32")
    assert unscored["status"] == "UNSCORED"
    assert unscored["finding_key"] is None

    passing = next(r for r in all_requirements if r["control_id"] == "article_25")
    assert passing["status"] == "PASS"
    assert passing["finding_key"] is not None


@pytest.mark.integration
def test_framework_detail_unknown_slug_is_404(api_client_a) -> None:
    resp = api_client_a.get("/api/v1/compliance/frameworks/NOT-A-REAL-FRAMEWORK-999", headers=HEADERS_A)
    assert resp.status_code == 404


@pytest.mark.integration
def test_framework_detail_known_framework_with_no_findings_is_not_404(api_client_a) -> None:
    """A real framework nobody has scanned against yet is a full Unscored tree, not a 404."""
    resp = api_client_a.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]
    assert body["total_controls"] == 3
    assert body["unscored_count"] == 3


@pytest.mark.integration
def test_framework_trend_invalid_period_is_422(api_client_a) -> None:
    resp = api_client_a.get("/api/v1/compliance/frameworks/CIS-7.0/trend?period=bogus", headers=HEADERS_A)
    assert resp.status_code == 422


@pytest.mark.integration
def test_framework_detail_tenant_isolation(api_client_a, api_client_b, db_tenant_a) -> None:
    init_tenant_schema(db_tenant_a)
    _seed(db_tenant_a, TEST_TENANT_A, "gdpr_pass", "Article 25 check", "MEDIUM", "PASS", ["GDPR/article_25"])

    resp_b = api_client_b.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_B)
    assert resp_b.status_code == 200
    body_b = resp_b.json()["data"]
    assert body_b["pass_count"] == 0
    assert body_b["unscored_count"] == 3


@pytest.mark.integration
def test_framework_trend_filters_by_period(api_client_a, db_tenant_a) -> None:
    init_tenant_schema(db_tenant_a)
    today = datetime.now(UTC).date()
    old_date = today - timedelta(days=20)

    def _snapshot(snapshot_date, score):
        db_tenant_a.collection("compliance_score_snapshots").insert(
            {
                "_key": f"snap-{snapshot_date.isoformat()}",
                "tenant_id": TEST_TENANT_A,
                "framework_id": "CIS-7.0",
                "snapshot_date": snapshot_date.isoformat(),
                "score_by_control": score,
                "score_by_asset": score,
                "pass_count": 1,
                "fail_count": 0,
                "unscored_count": 0,
                "created_at": datetime.now(UTC).isoformat(),
            },
            overwrite=True,
        )

    _snapshot(old_date, 40.0)
    _snapshot(today, 90.0)

    resp = api_client_a.get("/api/v1/compliance/frameworks/CIS-7.0/trend?period=7d", headers=HEADERS_A)
    assert resp.status_code == 200
    points = resp.json()["data"]
    assert len(points) == 1
    assert points[0]["date"] == today.isoformat()
    assert points[0]["score_by_control"] == 90.0

    resp_1m = api_client_a.get("/api/v1/compliance/frameworks/CIS-7.0/trend?period=1m", headers=HEADERS_A)
    assert len(resp_1m.json()["data"]) == 2
