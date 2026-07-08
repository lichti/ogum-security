"""
Integration tests for attack-paths MITRE endpoints.

  GET /api/v1/attack-paths/{path_id}/mitre
  GET /api/v1/attack-paths?actively_exploited=...
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

HEADERS_A = {"X-Tenant-Id": TEST_TENANT_A}
HEADERS_B = {"X-Tenant-Id": TEST_TENANT_B}


@pytest.fixture
def client_a(db_tenant_a):  # type: ignore[no-untyped-def]
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed_path(db, key: str, tenant_id: str = TEST_TENANT_A, **overrides) -> dict:  # type: ignore[no-untyped-def]
    doc = {
        "_key": key,
        "path_id": key,
        "tenant_id": tenant_id,
        "rule": "TC-01",
        "entry_point_id": f"resources/{key}-ep",
        "entry_point_type": "aws_ec2_instance",
        "entry_point_name": f"ec2-{key}",
        "target_id": f"data_assets/{key}-tgt",
        "target_type": "aws_s3_bucket",
        "target_name": f"s3-{key}",
        "hops": 2,
        "path_vertex_ids": [f"resources/{key}-ep", f"data_assets/{key}-tgt"],
        "risk_score": 75.0,
        "severity": "HIGH",
        "is_toxic_combination": True,
        "mitre_ttps": ["T1190", "T1078.004", "T1537"],
        "mitre_chain": ["T1190", "T1078.004", "T1537"],
        "actively_exploited": False,
        "last_runtime_event_at": None,
        "detected_at": datetime.now(UTC).isoformat(),
        "status": "active",
        **overrides,
    }
    db.collection("attack_paths").insert(doc, overwrite=True)
    return doc


@pytest.mark.integration
class TestAttackPathMitreEndpoint:
    def test_returns_404_for_nonexistent_path(self, client_a) -> None:  # type: ignore[no-untyped-def]
        resp = client_a.get("/api/v1/attack-paths/nonexistent-path-key/mitre", headers=HEADERS_A)
        assert resp.status_code == 404

    def test_returns_404_for_wrong_tenant(self, client_a, db_tenant_a) -> None:  # type: ignore[no-untyped-def]
        _seed_path(db_tenant_a, "mitre-tenant-test", tenant_id=TEST_TENANT_B)
        resp = client_a.get("/api/v1/attack-paths/mitre-tenant-test/mitre", headers=HEADERS_A)
        assert resp.status_code == 404

    def test_returns_structure_with_mitre_chain(self, client_a, db_tenant_a) -> None:  # type: ignore[no-untyped-def]
        _seed_path(db_tenant_a, "mitre-chain-test")
        resp = client_a.get("/api/v1/attack-paths/mitre-chain-test/mitre", headers=HEADERS_A)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        data = body["data"]
        assert "techniques" in data
        assert "tactics" in data
        assert "apt_groups" in data
        assert "mitre_chain" in data
        # mitre_chain should be returned even if admin MITRE DB not populated
        assert data["mitre_chain"] == ["T1190", "T1078.004", "T1537"]

    def test_returns_empty_techniques_when_mitre_not_imported(self, client_a, db_tenant_a) -> None:  # type: ignore[no-untyped-def]
        """Gracefully returns empty lists when admin DB has no MITRE data yet."""
        _seed_path(db_tenant_a, "mitre-empty-test")
        resp = client_a.get("/api/v1/attack-paths/mitre-empty-test/mitre", headers=HEADERS_A)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert isinstance(data["techniques"], list)
        assert isinstance(data["apt_groups"], list)


@pytest.mark.integration
class TestAttackPathsActivelyExploitedFilter:
    def test_filter_false_returns_paths(self, client_a, db_tenant_a) -> None:  # type: ignore[no-untyped-def]
        _seed_path(db_tenant_a, "ae-false-path", actively_exploited=False)
        resp = client_a.get(
            "/api/v1/attack-paths",
            params={"actively_exploited": "false"},
            headers=HEADERS_A,
        )
        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        assert any(p["_key"] == "ae-false-path" for p in items)

    def test_filter_true_excludes_non_exploited(self, client_a, db_tenant_a) -> None:  # type: ignore[no-untyped-def]
        _seed_path(db_tenant_a, "ae-true-path", actively_exploited=True)
        _seed_path(db_tenant_a, "ae-false-path2", actively_exploited=False)
        resp = client_a.get(
            "/api/v1/attack-paths",
            params={"actively_exploited": "true"},
            headers=HEADERS_A,
        )
        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        keys = {p["_key"] for p in items}
        assert "ae-true-path" in keys
        assert "ae-false-path2" not in keys
