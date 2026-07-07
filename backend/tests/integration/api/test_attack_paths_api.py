"""
Integration tests for the Attack Paths API (/api/v1/attack-paths).

Rules:
- ArangoDB: real instance (db_tenant_a / db_tenant_b fixtures — never mocked)
- Data is seeded directly into the collection for each test
"""

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
def client_a(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_b(db_tenant_b):
    init_tenant_schema(db_tenant_b)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_b
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed_path(
    db,
    key: str,
    tenant_id: str = TEST_TENANT_A,
    *,
    severity: str = "CRITICAL",
    risk_score: float = 80.0,
    is_toxic_combination: bool = False,
    entry_point_type: str = "aws_ec2_instance",
    target_type: str = "aws_s3_bucket",
    detected_at: str | None = None,
    **overrides,
) -> dict:
    now = detected_at or datetime.now(UTC).isoformat()
    doc = {
        "_key": key,
        "path_id": key,
        "tenant_id": tenant_id,
        "rule": "internet_to_data",
        "entry_point_id": f"resources/{key}-ep",
        "entry_point_type": entry_point_type,
        "entry_point_name": f"ec2-{key}",
        "target_id": f"data_assets/{key}-tgt",
        "target_type": target_type,
        "target_name": f"s3-{key}",
        "hops": 2,
        "path_vertex_ids": [f"resources/{key}-ep", f"data_assets/{key}-tgt"],
        "risk_score": risk_score,
        "severity": severity,
        "is_toxic_combination": is_toxic_combination,
        "detected_at": now,
        "status": "active",
        **overrides,
    }
    db.collection("attack_paths").insert(doc, overwrite=True)
    return doc


# ─── GET /api/v1/attack-paths ─────────────────────────────────────────────────


@pytest.mark.integration
class TestListAttackPaths:
    def test_list_returns_paths_for_tenant(self, client_a, db_tenant_a):
        _seed_path(db_tenant_a, "path-001")
        _seed_path(db_tenant_a, "path-002", severity="HIGH", risk_score=60.0)

        resp = client_a.get("/api/v1/attack-paths", headers=HEADERS_A)

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["count"] == 2
        assert len(data["items"]) == 2

    def test_list_sorted_by_risk_score_desc(self, client_a, db_tenant_a):
        _seed_path(db_tenant_a, "low-risk", severity="LOW", risk_score=20.0)
        _seed_path(db_tenant_a, "high-risk", severity="CRITICAL", risk_score=95.0)
        _seed_path(db_tenant_a, "med-risk", severity="HIGH", risk_score=60.0)

        resp = client_a.get("/api/v1/attack-paths", headers=HEADERS_A)

        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        scores = [item["risk_score"] for item in items]
        assert scores == sorted(scores, reverse=True)

    def test_filter_by_severity(self, client_a, db_tenant_a):
        _seed_path(db_tenant_a, "crit-001", severity="CRITICAL")
        _seed_path(db_tenant_a, "high-001", severity="HIGH", risk_score=60.0)

        resp = client_a.get("/api/v1/attack-paths?severity=CRITICAL", headers=HEADERS_A)

        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        assert all(item["severity"] == "CRITICAL" for item in items)
        assert len(items) == 1

    def test_filter_by_is_toxic_combination(self, client_a, db_tenant_a):
        _seed_path(db_tenant_a, "toxic-001", is_toxic_combination=True)
        _seed_path(db_tenant_a, "normal-001", is_toxic_combination=False, risk_score=50.0)

        resp = client_a.get("/api/v1/attack-paths?is_toxic_combination=true", headers=HEADERS_A)

        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert items[0]["is_toxic_combination"] is True

    def test_filter_by_provider(self, client_a, db_tenant_a):
        _seed_path(db_tenant_a, "aws-path", entry_point_type="aws_ec2_instance")
        _seed_path(db_tenant_a, "azure-path", entry_point_type="azure_vm", risk_score=70.0)

        resp = client_a.get("/api/v1/attack-paths?provider=azure", headers=HEADERS_A)

        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert "azure" in items[0]["entry_point_type"].lower()

    def test_invalid_severity_returns_422(self, client_a):
        resp = client_a.get("/api/v1/attack-paths?severity=INVALID", headers=HEADERS_A)
        assert resp.status_code == 422

    def test_list_empty_returns_empty(self, client_a):
        resp = client_a.get("/api/v1/attack-paths", headers=HEADERS_A)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["count"] == 0
        assert data["items"] == []

    def test_cursor_pagination(self, client_a, db_tenant_a):
        for i in range(5):
            _seed_path(db_tenant_a, f"page-{i:03d}", risk_score=float(90 - i * 10))

        resp1 = client_a.get("/api/v1/attack-paths?limit=2", headers=HEADERS_A)
        assert resp1.status_code == 200
        page1 = resp1.json()["data"]
        assert page1["count"] == 2
        assert page1["next_cursor"] is not None

        resp2 = client_a.get(f"/api/v1/attack-paths?limit=2&cursor={page1['next_cursor']}", headers=HEADERS_A)
        assert resp2.status_code == 200
        page2 = resp2.json()["data"]
        assert page2["count"] == 2

        # No overlap between pages
        keys1 = {item["_key"] for item in page1["items"]}
        keys2 = {item["_key"] for item in page2["items"]}
        assert keys1.isdisjoint(keys2)

    def test_last_page_has_no_next_cursor(self, client_a, db_tenant_a):
        _seed_path(db_tenant_a, "only-one")

        resp = client_a.get("/api/v1/attack-paths?limit=10", headers=HEADERS_A)
        assert resp.status_code == 200
        assert resp.json()["data"]["next_cursor"] is None


# ─── GET /api/v1/attack-paths/stats ──────────────────────────────────────────


@pytest.mark.integration
class TestAttackPathStats:
    def test_stats_returns_counts_by_severity(self, client_a, db_tenant_a):
        _seed_path(db_tenant_a, "s-crit-1", severity="CRITICAL")
        _seed_path(db_tenant_a, "s-crit-2", severity="CRITICAL", risk_score=85.0)
        _seed_path(db_tenant_a, "s-high-1", severity="HIGH", risk_score=60.0)

        resp = client_a.get("/api/v1/attack-paths/stats", headers=HEADERS_A)

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total"] == 3
        assert data["by_severity"]["CRITICAL"] == 2
        assert data["by_severity"]["HIGH"] == 1
        assert data["by_severity"]["MEDIUM"] == 0

    def test_stats_counts_new_24h(self, client_a, db_tenant_a):
        recent = datetime.now(UTC).isoformat()
        old = (datetime.now(UTC) - timedelta(hours=48)).isoformat()

        _seed_path(db_tenant_a, "recent-path", detected_at=recent)
        _seed_path(db_tenant_a, "old-path", severity="HIGH", risk_score=60.0, detected_at=old)

        resp = client_a.get("/api/v1/attack-paths/stats", headers=HEADERS_A)

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["new_24h"] == 1
        assert data["total"] == 2

    def test_stats_empty_returns_zeros(self, client_a):
        resp = client_a.get("/api/v1/attack-paths/stats", headers=HEADERS_A)

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total"] == 0
        assert data["new_24h"] == 0
        assert all(v == 0 for v in data["by_severity"].values())


# ─── GET /api/v1/attack-paths/{path_id} ──────────────────────────────────────


@pytest.mark.integration
class TestAttackPathDetail:
    def test_detail_returns_path_and_nodes(self, client_a, db_tenant_a):
        # Seed vertex documents that the path references
        init_tenant_schema(db_tenant_a)
        db_tenant_a.collection("resources").insert(
            {
                "_key": "ep-resource",
                "tenant_id": TEST_TENANT_A,
                "name": "my-ec2",
                "resource_type": "aws_ec2_instance",
            },
            overwrite=True,
        )
        db_tenant_a.collection("data_assets").insert(
            {
                "_key": "tgt-data",
                "tenant_id": TEST_TENANT_A,
                "name": "my-s3",
                "resource_type": "aws_s3_bucket",
            },
            overwrite=True,
        )
        doc = _seed_path(
            db_tenant_a,
            "detail-001",
            path_vertex_ids=["resources/ep-resource", "data_assets/tgt-data"],
        )

        resp = client_a.get(f"/api/v1/attack-paths/{doc['_key']}", headers=HEADERS_A)

        assert resp.status_code == 200
        detail = resp.json()["data"]
        assert detail["path"]["_key"] == doc["_key"]
        assert len(detail["nodes"]) == 2
        assert detail["nodes"][0]["name"] == "my-ec2"

    def test_detail_not_found_returns_404(self, client_a):
        resp = client_a.get("/api/v1/attack-paths/nonexistent-path", headers=HEADERS_A)
        assert resp.status_code == 404

    def test_detail_includes_associated_findings(self, client_a, db_tenant_a):
        init_tenant_schema(db_tenant_a)
        db_tenant_a.collection("findings").insert(
            {
                "_key": "find-abc",
                "tenant_id": TEST_TENANT_A,
                "resource_id": "resources/ep-resource",
                "check_id": "ec2_public",
                "severity": "CRITICAL",
            },
            overwrite=True,
        )
        doc = _seed_path(
            db_tenant_a,
            "with-findings",
            path_vertex_ids=["resources/ep-resource"],
        )

        resp = client_a.get(f"/api/v1/attack-paths/{doc['_key']}", headers=HEADERS_A)

        assert resp.status_code == 200
        detail = resp.json()["data"]
        assert len(detail["findings"]) == 1
        assert detail["findings"][0]["check_id"] == "ec2_public"


# ─── Security: tenant isolation ───────────────────────────────────────────────


@pytest.mark.security
class TestTenantIsolation:
    def test_tenant_a_cannot_list_tenant_b_paths(self, client_a, client_b, db_tenant_b):
        """Tenant B's paths are in a separate database — tenant A sees empty list."""
        _seed_path(db_tenant_b, "b-path-001", tenant_id=TEST_TENANT_B)

        resp = client_a.get("/api/v1/attack-paths", headers=HEADERS_A)

        assert resp.status_code == 200
        # Tenant A's DB has no paths → empty
        assert resp.json()["data"]["count"] == 0

    def test_tenant_a_cannot_get_tenant_b_path_detail(self, client_a, client_b, db_tenant_b):
        """Path seeded in tenant B's DB is not accessible via tenant A's client."""
        doc = _seed_path(db_tenant_b, "b-secret-path", tenant_id=TEST_TENANT_B)

        resp = client_a.get(f"/api/v1/attack-paths/{doc['_key']}", headers=HEADERS_A)

        assert resp.status_code == 404

    def test_each_tenant_sees_only_their_paths(self, db_tenant_a, db_tenant_b):
        """Seed different paths in each tenant DB and verify isolation.

        Uses sequential dependency overrides to avoid fixture conflict — two
        TestClient fixtures active simultaneously both write the same
        dependency_overrides key, causing the second to clobber the first.
        """
        init_tenant_schema(db_tenant_a)
        init_tenant_schema(db_tenant_b)
        _seed_path(db_tenant_a, "a-path", tenant_id=TEST_TENANT_A)
        _seed_path(db_tenant_b, "b-path", tenant_id=TEST_TENANT_B)

        app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
        resp_a = TestClient(app).get("/api/v1/attack-paths", headers=HEADERS_A)

        app.dependency_overrides[get_tenant_db] = lambda: db_tenant_b
        resp_b = TestClient(app).get("/api/v1/attack-paths", headers=HEADERS_B)

        app.dependency_overrides.clear()

        assert resp_a.json()["data"]["count"] == 1
        assert resp_b.json()["data"]["count"] == 1
        assert resp_a.json()["data"]["items"][0]["_key"] == "a-path"
        assert resp_b.json()["data"]["items"][0]["_key"] == "b-path"
