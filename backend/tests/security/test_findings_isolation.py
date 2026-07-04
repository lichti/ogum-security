"""
Security tests — tenant isolation for the Findings API.

Tenant A findings must never be visible to Tenant B and vice versa.
These tests are blocking in CI.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B


def _seed_finding(db, key: str, tenant_id: str, **overrides) -> None:
    doc = {
        "_key": key,
        "finding_id": key,
        "tenant_id": tenant_id,
        "check_id": "check_001",
        "title": "Test Finding",
        "description": "desc",
        "resource_id": f"res-{key}",
        "resource_type": "s3_bucket",
        "severity": "HIGH",
        "status": "FAIL",
        "provider": "aws",
        "region": "us-east-1",
        "account_id": "123456789012",
        "framework_mapping": [],
        "source": "cspm",
        "detected_at": "2026-07-03T10:00:00+00:00",
        "updated_at": "2026-07-03T10:00:00+00:00",
        "raw_output": {},
        **overrides,
    }
    db.collection("findings").insert(doc, overwrite=True)


@pytest.mark.security
class TestFindingsTenantIsolation:
    """Findings of Tenant A must never appear in Tenant B's responses."""

    def test_list_findings_does_not_leak_cross_tenant(self, db_tenant_a, db_tenant_b):
        """Tenant B's list endpoint must not return Tenant A's findings."""
        init_tenant_schema(db_tenant_a)
        init_tenant_schema(db_tenant_b)
        _seed_finding(db_tenant_a, "secret-a", TEST_TENANT_A)

        app.dependency_overrides[get_tenant_db] = lambda: db_tenant_b
        client = TestClient(app)
        resp = client.get("/api/v1/findings", headers={"X-Tenant-Id": TEST_TENANT_B})
        app.dependency_overrides.clear()

        assert resp.status_code == 200
        assert resp.json()["data"]["count"] == 0

    def test_get_finding_wrong_tenant_returns_404(self, db_tenant_a, db_tenant_b):
        """Tenant B cannot read a finding that belongs to Tenant A."""
        init_tenant_schema(db_tenant_a)
        init_tenant_schema(db_tenant_b)
        _seed_finding(db_tenant_a, "tenant-a-finding", TEST_TENANT_A)

        # Tenant B queries Tenant A's DB (simulates row-level isolation — same physical DB)
        app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
        client = TestClient(app)
        # Authenticates as Tenant B but tries to access Tenant A's finding
        resp = client.get(
            "/api/v1/findings/tenant-a-finding",
            headers={"X-Tenant-Id": TEST_TENANT_B},
        )
        app.dependency_overrides.clear()

        assert resp.status_code == 404

    def test_patch_finding_wrong_tenant_returns_404(self, db_tenant_a, db_tenant_b):
        """Tenant B cannot mute a finding owned by Tenant A."""
        init_tenant_schema(db_tenant_a)
        init_tenant_schema(db_tenant_b)
        _seed_finding(db_tenant_a, "tenant-a-secret", TEST_TENANT_A)

        app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
        client = TestClient(app)
        resp = client.patch(
            "/api/v1/findings/tenant-a-secret",
            json={"status": "MUTED", "reason": "unauthorized attempt"},
            headers={"X-Tenant-Id": TEST_TENANT_B},
        )
        app.dependency_overrides.clear()

        assert resp.status_code == 404
        # Verify the finding was NOT modified
        doc = db_tenant_a.collection("findings").get("tenant-a-secret")
        assert doc["status"] == "FAIL"

    def test_list_findings_returns_only_own_tenant_data(self, db_tenant_a):
        """Even if findings for multiple tenants live in the same DB, the filter works."""
        init_tenant_schema(db_tenant_a)
        _seed_finding(db_tenant_a, "a-finding", TEST_TENANT_A)
        _seed_finding(db_tenant_a, "b-finding", TEST_TENANT_B)

        app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
        client = TestClient(app)
        resp = client.get("/api/v1/findings", headers={"X-Tenant-Id": TEST_TENANT_A})
        app.dependency_overrides.clear()

        items = resp.json()["data"]["items"]
        assert all(f["tenant_id"] == TEST_TENANT_A for f in items)
        assert len(items) == 1
