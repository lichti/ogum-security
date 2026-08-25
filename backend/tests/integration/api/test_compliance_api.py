"""Integration tests for GET /api/v1/compliance/summary and /frameworks/{id}[/trend]."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from app.services.compliance_service import snapshot_compliance_scores
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
    resource_id: str = "res-001",
    detected_at: str = "2026-01-01T00:00:00Z",
    resource_type: str = "s3_bucket",
) -> None:
    db.collection("findings").insert(
        {
            "tenant_id": tenant_id,
            "check_id": check_id,
            "title": title,
            "description": "desc",
            "resource_id": resource_id,
            "resource_arn": None,
            "resource_type": resource_type,
            "severity": severity,
            "status": status,
            "provider": "aws",
            "region": "us-east-1",
            "account_id": "111111111111",
            "framework_mapping": frameworks,
            "remediation": None,
            "remediation_code": None,
            "source": "cspm",
            "detected_at": detected_at,
            "updated_at": detected_at,
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
    # pass/fail/total are control-level (score_by_control), not the raw finding tally —
    # 2 real Fail controls, 1 real Pass control, `total` is the full CIS-7.0 catalog
    # size (unscored controls included), not just the 3 controls seeded here.
    assert version["pass"] == 1
    assert version["fail"] == 2
    assert version["total"] > 3
    assert version["score"] == round((1 + (version["total"] - 3)) / version["total"] * 100, 1)


@pytest.mark.integration
def test_compliance_summary_headline_score_is_by_control_not_by_finding(api_client_a, db_tenant_a) -> None:
    """The version score shown in the sidebar/framework-detail header is
    score_by_control, not the raw finding tally — same divergence case as
    test_framework_detail_score_by_control_diverges_from_score_by_finding, asserted
    here against GET /api/v1/compliance/summary instead of /frameworks/{id}."""
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "PASS", ["CIS-7.0/2.1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "HIGH", "PASS", ["CIS-7.0/2.1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_3", "Check 3", "HIGH", "FAIL", ["CIS-7.0/2.1.1"])

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    body = resp.json()["data"]

    version = next(v for f in body["families"] for v in f["versions"] if v["id"] == "CIS-7.0")
    # By-finding this would be 2/3 = 66.7%; by-control the single control is Fail
    # (any asset failing it fails the control), but every other CIS-7.0 catalog
    # control is Unscored and counts toward Pass — high, not 0%.
    assert version["pass"] == 0
    assert version["fail"] == 1
    assert version["score"] == round((version["total"] - 1) / version["total"] * 100, 1)
    assert version["score"] != 66.7


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
def test_compliance_summary_top_assets_groups_by_resource_not_by_check(api_client_a, db_tenant_a) -> None:
    # res-a fails 2 different checks, res-b fails 1 — res-a should rank first.
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "FAIL", ["CIS-7.0/1.1"], resource_id="res-a")
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "HIGH", "FAIL", ["CIS-7.0/1.2"], resource_id="res-a")
    _seed(db_tenant_a, TEST_TENANT_A, "check_3", "Check 3", "HIGH", "FAIL", ["CIS-7.0/1.3"], resource_id="res-b")

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    items = resp.json()["data"]["top_assets"]
    assert items[0]["resource_id"] == "res-a"
    assert items[0]["count"] == 2
    assert items[1]["resource_id"] == "res-b"
    assert items[1]["count"] == 1


@pytest.mark.integration
def test_compliance_summary_top_assets_merges_same_resource_id_with_different_resource_type(
    api_client_a, db_tenant_a
) -> None:
    # Regression: account-level checks (IAM password policy, CloudTrail config, ...)
    # tag resource_id with the bare account ID, but different account-level checks can
    # report a different resource_type for that same pseudo-resource ("AwsCloudWatchAlarm"
    # vs "Other") — grouping by the full (resource_id, resource_type, ...) tuple split
    # one asset into two rows with a duplicate resource_id (React key collision, and a
    # wrong count for the asset).
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_1",
        "Check 1",
        "HIGH",
        "FAIL",
        ["CIS-7.0/1.1"],
        resource_id="111111111111",
        resource_type="AwsCloudWatchAlarm",
    )
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_2",
        "Check 2",
        "HIGH",
        "FAIL",
        ["CIS-7.0/1.2"],
        resource_id="111111111111",
        resource_type="Other",
    )

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    items = resp.json()["data"]["top_assets"]
    matching = [i for i in items if i["resource_id"] == "111111111111"]
    assert len(matching) == 1
    assert matching[0]["count"] == 2


@pytest.mark.integration
def test_compliance_summary_top_assets_prefers_a_real_resource_type_over_unknown(api_client_a, db_tenant_a) -> None:
    """ "unknown" is prowler_service._normalize's own fallback for a finding whose
    check result carried no metadata — not every check on the same resource_id hits
    that gap, so the representative row picked for display must not get stuck on an
    "unknown" one when a real type is available from another finding on that asset."""
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_1",
        "Check 1",
        "HIGH",
        "FAIL",
        ["CIS-7.0/1.1"],
        resource_id="MyManagedPolicy",
        resource_type="unknown",
    )
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_2",
        "Check 2",
        "HIGH",
        "FAIL",
        ["CIS-7.0/1.2"],
        resource_id="MyManagedPolicy",
        resource_type="AwsIamPolicy",
    )

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    items = resp.json()["data"]["top_assets"]
    matching = next(i for i in items if i["resource_id"] == "MyManagedPolicy")
    assert matching["resource_type"] == "AwsIamPolicy"


@pytest.mark.integration
def test_compliance_summary_top_lists_scoped_by_framework_exclude_other_frameworks(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "cis_check", "CIS", "CRITICAL", "FAIL", ["CIS-7.0/1.1"], resource_id="res-cis")
    _seed(db_tenant_a, TEST_TENANT_A, "soc2_check", "SOC2", "CRITICAL", "FAIL", ["SOC2"], resource_id="res-soc2")

    resp = api_client_a.get("/api/v1/compliance/summary?framework=CIS-7.0", headers=HEADERS_A)
    body = resp.json()["data"]
    assert {i["check_id"] for i in body["top_failing"]} == {"cis_check"}
    assert {i["resource_id"] for i in body["top_assets"]} == {"res-cis"}


@pytest.mark.integration
def test_compliance_summary_severity_filter_restricts_top_failing_only(api_client_a, db_tenant_a) -> None:
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "critical_check",
        "Critical",
        "CRITICAL",
        "FAIL",
        ["CIS-7.0/1.1"],
        resource_id="res-a",
    )
    _seed(db_tenant_a, TEST_TENANT_A, "low_check", "Low", "LOW", "FAIL", ["CIS-7.0/1.2"], resource_id="res-b")

    resp = api_client_a.get("/api/v1/compliance/summary?severity=CRITICAL", headers=HEADERS_A)
    body = resp.json()["data"]
    assert {i["check_id"] for i in body["top_failing"]} == {"critical_check"}
    # top_assets is never severity-filtered — both checks' resources still show up.
    assert len(body["top_assets"]) == 2


@pytest.mark.integration
def test_compliance_summary_severity_filter_combines_with_multiple_values(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "critical_check", "Critical", "CRITICAL", "FAIL", ["CIS-7.0/1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "high_check", "High", "HIGH", "FAIL", ["CIS-7.0/1.2"])
    _seed(db_tenant_a, TEST_TENANT_A, "low_check", "Low", "LOW", "FAIL", ["CIS-7.0/1.3"])

    resp = api_client_a.get("/api/v1/compliance/summary?severity=CRITICAL&severity=HIGH", headers=HEADERS_A)
    check_ids = {i["check_id"] for i in resp.json()["data"]["top_failing"]}
    assert check_ids == {"critical_check", "high_check"}


@pytest.mark.integration
def test_compliance_summary_severity_filter_with_no_matching_value_yields_empty_top_failing(
    api_client_a, db_tenant_a
) -> None:
    # This is exactly how the frontend represents "every severity toggle switched
    # off" — a value that matches no real severity, so top_failing comes back empty
    # without the backend needing to special-case "filter to nothing" vs "no filter".
    _seed(db_tenant_a, TEST_TENANT_A, "critical_check", "Critical", "CRITICAL", "FAIL", ["CIS-7.0/1.1"])

    resp = api_client_a.get("/api/v1/compliance/summary?severity=__none__", headers=HEADERS_A)
    body = resp.json()["data"]
    assert body["top_failing"] == []
    assert len(body["top_assets"]) == 1  # unaffected


@pytest.mark.integration
def test_compliance_summary_no_severity_param_means_no_filter(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "critical_check", "Critical", "CRITICAL", "FAIL", ["CIS-7.0/1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "low_check", "Low", "LOW", "FAIL", ["CIS-7.0/1.2"])

    resp = api_client_a.get("/api/v1/compliance/summary", headers=HEADERS_A)
    check_ids = {i["check_id"] for i in resp.json()["data"]["top_failing"]}
    assert check_ids == {"critical_check", "low_check"}


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
def test_framework_detail_score_by_control_is_not_naive_pooling(api_client_a, db_tenant_a) -> None:
    """3 findings on the same resource, same control — 2 PASS + 1 FAIL. The control
    counts as a single Fail (any asset failing it fails the control), but every other
    CIS-7.0 catalog control is Unscored and counts toward Pass, so score_by_control
    lands high (not 0%) despite the one real Fail — (Total - 1) / Total."""
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "PASS", ["CIS-7.0/2.1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "HIGH", "PASS", ["CIS-7.0/2.1.1"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_3", "Check 3", "HIGH", "FAIL", ["CIS-7.0/2.1.1"])

    resp = api_client_a.get("/api/v1/compliance/frameworks/CIS-7.0", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]

    assert body["id"] == "CIS-7.0"
    assert body["control_pass_count"] == 0
    assert body["control_fail_count"] == 1
    assert body["catalog_available"] is True
    assert body["control_unscored_count"] > 0  # every other CIS-7.0 catalog control has no finding yet
    # score_by_control = (Pass + Unscored) / Total — the single Fail is the only
    # thing dragging the score down from 100%.
    assert body["score_by_control"] == round(body["control_unscored_count"] / body["control_total"] * 100, 1)


@pytest.mark.integration
def test_framework_detail_unscored_controls_from_real_catalog(api_client_a, db_tenant_a) -> None:
    """GDPR has exactly 3 catalog controls (article_25/30/32) — seed 2, leave 1 untouched."""
    _seed(db_tenant_a, TEST_TENANT_A, "gdpr_pass", "Article 25 check", "MEDIUM", "PASS", ["GDPR/article_25"])
    _seed(db_tenant_a, TEST_TENANT_A, "gdpr_fail", "Article 30 check", "HIGH", "FAIL", ["GDPR/article_30"])

    resp = api_client_a.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]

    assert body["control_total"] == 3
    assert body["control_pass_count"] == 1
    assert body["control_fail_count"] == 1
    assert body["control_unscored_count"] == 1
    # (Pass + Unscored) / Total = (1 + 1) / 3, not Pass / (Pass + Fail) = 1 / 2.
    assert body["score_by_control"] == 66.7

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
def test_framework_detail_accepted_finding_folds_into_pass_for_control_view(api_client_a, db_tenant_a) -> None:
    """An ACCEPTED-risk finding (no real PASS/FAIL) satisfies the control."""
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "gdpr_accepted",
        "Article 25 risk accepted",
        "MEDIUM",
        "ACCEPTED",
        ["GDPR/article_25"],
    )

    resp = api_client_a.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_A)
    body = resp.json()["data"]

    assert body["control_pass_count"] == 1
    assert body["control_fail_count"] == 0
    assert body["control_unscored_count"] == 2  # article_30, article_32 — no findings at all
    assert body["score_by_control"] == 100.0  # (1 pass + 2 unscored) / 3, no Fail to drag it down

    all_requirements = [r for s in body["sections"] for r in s["requirements"]]
    accepted = next(r for r in all_requirements if r["control_id"] == "article_25")
    assert accepted["status"] == "PASS"
    assert accepted["accepted_count"] == 1
    assert accepted["finding_key"] is not None


@pytest.mark.integration
def test_framework_detail_muted_finding_folds_into_unscored_for_control_view(api_client_a, db_tenant_a) -> None:
    """A MUTED finding (no real PASS/FAIL/ACCEPTED) leaves the control Unscored, but
    the drill-down link still points at the muted finding — excluded from scoring,
    not from investigation."""
    _seed(db_tenant_a, TEST_TENANT_A, "gdpr_muted", "Article 25 muted check", "LOW", "MUTED", ["GDPR/article_25"])

    resp = api_client_a.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_A)
    body = resp.json()["data"]

    assert body["control_unscored_count"] == 3  # muted-only counts as unscored, same bucket as the other 2
    assert body["score_by_control"] == 100.0  # all 3 controls Unscored — (0+3)/3

    all_requirements = [r for s in body["sections"] for r in s["requirements"]]
    muted = next(r for r in all_requirements if r["control_id"] == "article_25")
    assert muted["status"] == "UNSCORED"
    assert muted["muted_count"] == 1
    assert muted["finding_key"] is not None  # still linkable, just not scored


@pytest.mark.integration
def test_framework_detail_unknown_slug_is_404(api_client_a) -> None:
    resp = api_client_a.get("/api/v1/compliance/frameworks/NOT-A-REAL-FRAMEWORK-999", headers=HEADERS_A)
    assert resp.status_code == 404


@pytest.mark.integration
def test_framework_detail_known_framework_with_no_findings_is_not_404(api_client_a) -> None:
    """A real framework nobody has scanned against yet is a full Unscored tree, not a
    404 — and, since Unscored counts toward Pass, it scores 100%, not 0%. Accepted
    tradeoff: an unscanned framework reads as compliant rather than as failing."""
    resp = api_client_a.get("/api/v1/compliance/frameworks/GDPR", headers=HEADERS_A)
    assert resp.status_code == 200
    body = resp.json()["data"]
    assert body["control_total"] == 3
    assert body["control_unscored_count"] == 3
    assert body["score_by_control"] == 100.0


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
    assert body_b["control_pass_count"] == 0
    assert body_b["control_unscored_count"] == 3
    assert body_b["score_by_control"] == 100.0


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


@pytest.mark.integration
def test_framework_trend_reflects_the_real_snapshot_writer(api_client_a, db_tenant_a) -> None:
    """`snapshot_compliance_scores` (called at the end of every CSPM scan) must
    populate `/trend` with the real By Control score, not a placeholder."""
    init_tenant_schema(db_tenant_a)
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "PASS", ["CIS-7.0/2.1.1"])

    written = snapshot_compliance_scores(db_tenant_a, TEST_TENANT_A)
    assert written > 0

    resp = api_client_a.get("/api/v1/compliance/frameworks/CIS-7.0/trend?period=7d", headers=HEADERS_A)
    points = resp.json()["data"]
    assert len(points) == 1
    assert points[0]["score_by_control"] > 0


@pytest.mark.integration
def test_control_assets_groups_pass_fail_by_resource(api_client_a, db_tenant_a) -> None:
    """Two resources evaluated against the same control — one all-PASS, one all-FAIL —
    land in separate rows, sorted by fail_count first (the riskier resource first)."""
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "PASS", ["GDPR/article_25"], resource_id="res-pass")
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "HIGH", "FAIL", ["GDPR/article_25"], resource_id="res-fail")

    resp = api_client_a.get(
        "/api/v1/compliance/frameworks/GDPR/control-assets?control_id=article_25", headers=HEADERS_A
    )
    assert resp.status_code == 200
    assets = resp.json()["data"]

    assert len(assets) == 2
    assert assets[0]["resource_id"] == "res-fail"
    assert assets[0]["fail_count"] == 1
    assert assets[0]["pass_count"] == 0
    assert assets[1]["resource_id"] == "res-pass"
    assert assets[1]["pass_count"] == 1
    assert assets[1]["fail_count"] == 0


@pytest.mark.integration
def test_control_assets_accepted_folds_into_pass(api_client_a, db_tenant_a) -> None:
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_1",
        "Check 1",
        "MEDIUM",
        "ACCEPTED",
        ["GDPR/article_25"],
        resource_id="res-accepted",
    )

    resp = api_client_a.get(
        "/api/v1/compliance/frameworks/GDPR/control-assets?control_id=article_25", headers=HEADERS_A
    )
    assets = resp.json()["data"]

    assert len(assets) == 1
    assert assets[0]["resource_id"] == "res-accepted"
    assert assets[0]["pass_count"] == 1
    assert assets[0]["fail_count"] == 0


@pytest.mark.integration
def test_control_assets_muted_excluded_from_pass_and_fail(api_client_a, db_tenant_a) -> None:
    _seed(
        db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "LOW", "MUTED", ["GDPR/article_25"], resource_id="res-muted"
    )

    resp = api_client_a.get(
        "/api/v1/compliance/frameworks/GDPR/control-assets?control_id=article_25", headers=HEADERS_A
    )
    assets = resp.json()["data"]

    assert len(assets) == 1
    assert assets[0]["pass_count"] == 0
    assert assets[0]["fail_count"] == 0


@pytest.mark.integration
def test_control_assets_prefers_a_real_resource_type_over_unknown(api_client_a, db_tenant_a) -> None:
    """Same resource, same control, two different underlying checks — one whose
    Prowler result carried no metadata (resource_type "unknown"), one with a real
    type. The asset's displayed resource_type must be the real one, not whichever
    finding happened to be read first."""
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_1",
        "Check 1",
        "HIGH",
        "FAIL",
        ["GDPR/article_25"],
        resource_id="MyManagedPolicy",
        resource_type="unknown",
    )
    _seed(
        db_tenant_a,
        TEST_TENANT_A,
        "check_2",
        "Check 2",
        "HIGH",
        "FAIL",
        ["GDPR/article_25"],
        resource_id="MyManagedPolicy",
        resource_type="AwsIamPolicy",
    )

    resp = api_client_a.get(
        "/api/v1/compliance/frameworks/GDPR/control-assets?control_id=article_25", headers=HEADERS_A
    )
    assets = resp.json()["data"]

    assert len(assets) == 1
    assert assets[0]["resource_type"] == "AwsIamPolicy"
    assert assets[0]["fail_count"] == 2


@pytest.mark.integration
def test_control_assets_scoped_to_exact_control_not_other_controls_in_same_framework(api_client_a, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "FAIL", ["GDPR/article_25"])
    _seed(db_tenant_a, TEST_TENANT_A, "check_2", "Check 2", "HIGH", "FAIL", ["GDPR/article_30"])

    resp = api_client_a.get(
        "/api/v1/compliance/frameworks/GDPR/control-assets?control_id=article_25", headers=HEADERS_A
    )
    assets = resp.json()["data"]

    assert len(assets) == 1
    assert assets[0]["fail_count"] == 1


@pytest.mark.integration
def test_control_assets_tenant_isolation(api_client_a, api_client_b, db_tenant_a) -> None:
    _seed(db_tenant_a, TEST_TENANT_A, "check_1", "Check 1", "HIGH", "FAIL", ["GDPR/article_25"])

    resp = api_client_b.get(
        "/api/v1/compliance/frameworks/GDPR/control-assets?control_id=article_25", headers=HEADERS_B
    )
    assert resp.json()["data"] == []
