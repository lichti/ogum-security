"""Integration tests for GET/PUT /api/v1/settings/compliance (US-14.19)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

HEADERS_A = {"X-Tenant-Id": TEST_TENANT_A}


@pytest.fixture
def api_client_a(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
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
    resource_id: str = "res-001",
) -> None:
    db.collection("findings").insert(
        {
            "tenant_id": tenant_id,
            "check_id": check_id,
            "title": title,
            "description": "desc",
            "resource_id": resource_id,
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
def test_list_compliance_settings_defaults_untouched_families_to_enabled(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "FAIL", ["CIS-7.0/2.1.1"])

    resp = api_client_a.get("/api/v1/settings/compliance", headers=HEADERS_A)
    assert resp.status_code == 200
    rows = resp.json()["data"]

    cis = next(r for r in rows if r["family_key"] == "cis-aws")
    assert cis["family_label"] == "CIS AWS Foundations Benchmark"
    assert cis["enabled"] is True
    assert cis["target_by_control"] is None


@pytest.mark.integration
def test_update_compliance_settings_persists_targets_and_disabled_flag(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "FAIL", ["CIS-7.0/2.1.1"])

    resp = api_client_a.put(
        "/api/v1/settings/compliance/cis-aws",
        headers=HEADERS_A,
        json={"target_by_control": 90.0},
    )
    assert resp.status_code == 200
    updated = resp.json()["data"]
    assert updated["target_by_control"] == 90.0
    assert updated["enabled"] is True  # untouched field keeps its default

    # Persisted, not just echoed back.
    listed = api_client_a.get("/api/v1/settings/compliance", headers=HEADERS_A).json()["data"]
    cis = next(r for r in listed if r["family_key"] == "cis-aws")
    assert cis["target_by_control"] == 90.0


@pytest.mark.integration
def test_update_compliance_settings_partial_update_does_not_clobber_other_fields(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "FAIL", ["CIS-7.0/2.1.1"])

    api_client_a.put("/api/v1/settings/compliance/cis-aws", headers=HEADERS_A, json={"target_by_control": 90.0})
    resp = api_client_a.put("/api/v1/settings/compliance/cis-aws", headers=HEADERS_A, json={"enabled": False})

    updated = resp.json()["data"]
    assert updated["enabled"] is False
    assert updated["target_by_control"] == 90.0  # untouched by the second PUT


@pytest.mark.integration
def test_clear_target_flag_resets_a_previously_set_target(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "FAIL", ["CIS-7.0/2.1.1"])

    api_client_a.put("/api/v1/settings/compliance/cis-aws", headers=HEADERS_A, json={"target_by_control": 90.0})
    resp = api_client_a.put(
        "/api/v1/settings/compliance/cis-aws", headers=HEADERS_A, json={"clear_target_by_control": True}
    )
    assert resp.json()["data"]["target_by_control"] is None


@pytest.mark.integration
def test_disabling_a_framework_hides_it_from_summary_but_keeps_it_in_settings(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "CRITICAL", "FAIL", ["CIS-7.0/2.1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "LOW", "FAIL", ["GDPR/article_25"])

    api_client_a.put("/api/v1/settings/compliance/cis-aws", headers=HEADERS_A, json={"enabled": False})

    summary = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A).json()["data"]
    family_keys = {f["family"] for f in summary["families"]}
    assert "cis-aws" not in family_keys
    assert "GDPR" in family_keys  # unaffected

    # Still listed in settings — so it can be re-enabled — just flagged disabled.
    settings_rows = api_client_a.get("/api/v1/settings/compliance", headers=HEADERS_A).json()["data"]
    cis = next(r for r in settings_rows if r["family_key"] == "cis-aws")
    assert cis["enabled"] is False


@pytest.mark.integration
def test_disabling_a_framework_excludes_its_findings_from_threat_score(api_client_a, db_tenant_a) -> None:
    # Only a CRITICAL FAIL on the disabled framework — threat_score should read 100
    # (max) once CIS is disabled, since no *enabled* framework has a failing finding.
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "CRITICAL", "FAIL", ["CIS-7.0/2.1.1"])

    before = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A).json()["data"]
    assert before["threat_score"] < 100

    api_client_a.put("/api/v1/settings/compliance/cis-aws", headers=HEADERS_A, json={"enabled": False})

    after = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A).json()["data"]
    assert after["threat_score"] == 100


@pytest.mark.integration
def test_disabling_a_framework_does_not_exclude_findings_shared_with_an_enabled_one(api_client_a, db_tenant_a) -> None:
    # This finding maps to both CIS (disabled below) and GDPR (still enabled) — it
    # must still count toward threat_score via GDPR.
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_1",
        "Check 1",
        "CRITICAL",
        "FAIL",
        ["CIS-7.0/2.1.1", "GDPR/article_25"],
    )

    api_client_a.put("/api/v1/settings/compliance/cis-aws", headers=HEADERS_A, json={"enabled": False})

    after = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A).json()["data"]
    assert after["threat_score"] < 100


@pytest.mark.integration
def test_framework_detail_reports_configured_targets(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "PASS", ["CIS-7.0/2.1.1"])
    api_client_a.put(
        "/api/v1/settings/compliance/cis-aws",
        headers=HEADERS_A,
        json={"target_by_control": 95.0},
    )

    resp = api_client_a.get("/api/v1/compliance/frameworks/CIS-7.0", headers=HEADERS_A)
    body = resp.json()["data"]
    assert body["target_by_control"] == 95.0


@pytest.mark.integration
def test_framework_detail_target_is_null_when_unconfigured(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "gdpr_pass", "Article 25 check", "MEDIUM", "PASS", ["GDPR/article_25"])
    resp = api_client_a.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_A)
    body = resp.json()["data"]
    assert body["target_by_control"] is None
