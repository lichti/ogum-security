"""
Integration tests for attack_path_service.py and risk_score.py.

Requires a real ArangoDB instance (uses db_tenant_a fixture from conftest.py).
Graph seed data is loaded from tests/fixtures/graph/attack_path_seed.py.

Tests cover:
  - find_paths_from_internet: detects public EC2 → IAM Role → S3 path
  - find_privilege_escalation_paths: detects DevUser → AdminRole escalation
  - detect_all_toxic_combinations: detects TC-02 (public S3 w/ creds) + TC-04 (k8s hostnet)
  - run_attack_path_detection: full pipeline + attack_paths collection populated
  - Tenant isolation: paths from tenant A are not returned for a different tenant filter
"""

from __future__ import annotations

import pytest

from app.db.init import init_tenant_schema
from app.services.attack_path_service import (
    detect_all_toxic_combinations,
    find_paths_from_internet,
    find_privilege_escalation_paths,
    run_attack_path_detection,
)
from app.services.risk_score import calculate_resource_risk_score
from tests.fixtures.graph.attack_path_seed import TENANT_ID


@pytest.fixture(autouse=True)
def graph_seed(db_tenant_a):  # type: ignore[no-untyped-def]
    """Seed the test graph before each test, clean up after."""
    from tests.fixtures.graph.attack_path_seed import seed_graph, teardown_graph

    init_tenant_schema(db_tenant_a)
    seed_graph(db_tenant_a)
    yield db_tenant_a
    teardown_graph(db_tenant_a)


@pytest.mark.integration
def test_find_paths_from_internet_detects_ec2_to_s3(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    paths = find_paths_from_internet(db_tenant_a, TENANT_ID, max_depth=4)

    assert len(paths) >= 1, "Expected at least one internet→data_asset path"
    assert paths[0]["entry_point_id"] == "resources/ec2-public-001"
    target_ids = {p["target_id"] for p in paths}
    assert "data_assets/s3-creds-bucket" in target_ids or "data_assets/rds-prod-db" in target_ids


@pytest.mark.integration
def test_find_paths_from_internet_respects_tenant_isolation(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    paths = find_paths_from_internet(db_tenant_a, "different-tenant-xyz", max_depth=4)
    assert paths == [], "Other tenant's paths must not be returned"


@pytest.mark.integration
def test_find_privilege_escalation_detects_devuser_to_adminrole(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    paths = find_privilege_escalation_paths(db_tenant_a, TENANT_ID, max_depth=4)

    assert len(paths) >= 1, "Expected at least one privilege escalation path"
    entry_ids = {p["start_identity_id"] for p in paths}
    assert "identities/iam-user-overpriv" in entry_ids


@pytest.mark.integration
def test_find_privilege_escalation_respects_tenant_isolation(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    paths = find_privilege_escalation_paths(db_tenant_a, "different-tenant-xyz", max_depth=4)
    assert paths == []


@pytest.mark.integration
def test_detect_tc02_public_bucket_with_credentials(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    results = detect_all_toxic_combinations(db_tenant_a, TENANT_ID)

    tc02 = [r for r in results if r["rule"] == "TC-02"]
    assert len(tc02) >= 1, "Expected TC-02 (public S3 with credentials) to be detected"
    assert tc02[0]["entry_point_id"] == "data_assets/s3-creds-bucket"


@pytest.mark.integration
def test_detect_tc04_k8s_host_network(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    results = detect_all_toxic_combinations(db_tenant_a, TENANT_ID)

    tc04 = [r for r in results if r["rule"] == "TC-04"]
    assert len(tc04) >= 1, "Expected TC-04 (K8s hostNetwork pod) to be detected"
    assert tc04[0]["entry_point_id"] == "resources/k8s-pod-hostnet"


@pytest.mark.integration
def test_detect_tc03_overpermissioned_to_db(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    results = detect_all_toxic_combinations(db_tenant_a, TENANT_ID)

    tc03 = [r for r in results if r["rule"] == "TC-03"]
    assert len(tc03) >= 1, "Expected TC-03 (overpermissioned identity → database) to be detected"
    target_ids = {r["target_id"] for r in tc03}
    assert "data_assets/rds-prod-db" in target_ids


@pytest.mark.integration
def test_run_attack_path_detection_persists_paths(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    result = run_attack_path_detection(db_tenant_a, TENANT_ID, max_depth=4)

    assert result["total_persisted"] >= 1

    stored = list(
        db_tenant_a.aql.execute(
            "FOR p IN attack_paths FILTER p.tenant_id == @tid RETURN p",
            bind_vars={"tid": TENANT_ID},
        )
    )
    assert len(stored) >= 1
    path = stored[0]
    assert path["tenant_id"] == TENANT_ID
    assert "path_id" in path
    assert "hops" in path
    assert "severity" in path
    assert "is_toxic_combination" in path


@pytest.mark.integration
def test_run_attack_path_detection_idempotent(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    result1 = run_attack_path_detection(db_tenant_a, TENANT_ID)
    run_attack_path_detection(db_tenant_a, TENANT_ID)

    stored = list(
        db_tenant_a.aql.execute(
            "FOR p IN attack_paths FILTER p.tenant_id == @tid RETURN p",
            bind_vars={"tid": TENANT_ID},
        )
    )
    assert len(stored) == result1["total_persisted"], "Second run must not duplicate paths"


@pytest.mark.integration
def test_run_attack_path_detection_marks_resources_in_path(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    run_attack_path_detection(db_tenant_a, TENANT_ID, max_depth=4)

    ec2_doc = db_tenant_a.collection("resources").get("ec2-public-001")
    assert ec2_doc is not None
    assert ec2_doc.get("in_attack_path") is True


@pytest.mark.integration
def test_calculate_resource_risk_score_with_real_findings(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    # ec2-public-001 has 1 CRITICAL + 1 HIGH finding and is_public=True
    score = calculate_resource_risk_score(db_tenant_a, "ec2-public-001", TENANT_ID, collection="resources")

    # severity_base = min(10 + 7, 50) = 17
    # exposure_factor = 2.0 (is_public=True)
    # blast_factor ≥ 1.0
    # minimum: 17 * 2 * 1 = 34
    assert score >= 34.0, f"Expected score >= 34, got {score}"
    assert score <= 100.0


@pytest.mark.integration
def test_calculate_resource_risk_score_no_findings_returns_zero(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    # k8s-pod-hostnet has no findings in the seed
    score = calculate_resource_risk_score(db_tenant_a, "k8s-pod-hostnet", TENANT_ID, collection="resources")
    assert score == 0.0


@pytest.mark.integration
def test_attack_path_has_valid_severity_label(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    run_attack_path_detection(db_tenant_a, TENANT_ID, max_depth=4)

    stored = list(
        db_tenant_a.aql.execute(
            "FOR p IN attack_paths FILTER p.tenant_id == @tid RETURN p",
            bind_vars={"tid": TENANT_ID},
        )
    )
    valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
    for path in stored:
        assert path.get("severity") in valid_severities, f"Invalid severity: {path.get('severity')}"


@pytest.mark.integration
def test_toxic_combinations_flagged_correctly(db_tenant_a) -> None:  # type: ignore[no-untyped-def]
    run_attack_path_detection(db_tenant_a, TENANT_ID, max_depth=4)

    stored = list(
        db_tenant_a.aql.execute(
            "FOR p IN attack_paths FILTER p.tenant_id == @tid AND p.is_toxic_combination == true RETURN p",
            bind_vars={"tid": TENANT_ID},
        )
    )
    assert len(stored) >= 1, "Expected at least one toxic combination to be persisted"
    for path in stored:
        assert path.get("rule") in {"TC-02", "TC-03", "TC-04"}
