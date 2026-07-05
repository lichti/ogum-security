"""
Integration tests for the dev seed endpoint and seed_findings() function.

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
- DEV_MODE semantics tested via direct function calls, not via HTTP routing
- HTTP 404 when DEV_MODE=False verified via monkeypatch
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.dev import (
    DEMO_ACCOUNT_ID,
    DEMO_PROVIDER_KEY,
    _FINDINGS,
    seed_findings,
)
from app.db.init import init_tenant_schema
from app.main import app

TENANT = "test-tenant-aaa"
HEADERS = {"X-Tenant-Id": TENANT, "X-Tenant-ID": TENANT}


@pytest.mark.integration
class TestSeedFindings:
    """seed_findings() inserts correct data directly into ArangoDB."""

    def test_returns_correct_summary(self, db_tenant_a) -> None:
        result = seed_findings(db_tenant_a, TENANT)

        assert result["seeded"] is True
        assert result["tenant_id"] == TENANT
        assert result["findings_inserted"] == len(_FINDINGS)
        assert result["account_id"] == DEMO_ACCOUNT_ID
        assert result["scan_job_id"] == "demo-scan-job-001"

    def test_fail_pass_muted_counts(self, db_tenant_a) -> None:
        result = seed_findings(db_tenant_a, TENANT)

        total = result["findings_fail"] + result["findings_pass"] + result["findings_muted"]
        assert total == result["findings_inserted"]
        assert result["findings_fail"] > 0
        assert result["findings_pass"] > 0
        assert result["findings_muted"] > 0

    def test_findings_persisted_in_arango(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)

        count = db_tenant_a.aql.execute(
            "FOR f IN findings FILTER f.tenant_id == @tid COLLECT WITH COUNT INTO c RETURN c",
            bind_vars={"tid": TENANT},
        ).next()
        assert count == len(_FINDINGS)

    def test_all_findings_have_required_fields(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)

        docs = list(
            db_tenant_a.aql.execute(
                "FOR f IN findings FILTER f.tenant_id == @tid RETURN f",
                bind_vars={"tid": TENANT},
            )
        )
        required = {"check_id", "title", "severity", "status", "provider", "account_id",
                    "framework_mapping", "detected_at", "scan_job_id", "raw_output"}
        for doc in docs:
            missing = required - set(doc.keys())
            assert not missing, f"Finding {doc.get('check_id')} missing fields: {missing}"

    def test_status_extended_stored_in_raw_output(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)

        docs = list(
            db_tenant_a.aql.execute(
                "FOR f IN findings FILTER f.tenant_id == @tid RETURN f.raw_output",
                bind_vars={"tid": TENANT},
            )
        )
        for raw_output in docs:
            assert "status_extended" in raw_output
            assert isinstance(raw_output["status_extended"], str)
            assert len(raw_output["status_extended"]) > 0

    def test_framework_mapping_not_empty_for_fail_findings(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)

        docs = list(
            db_tenant_a.aql.execute(
                "FOR f IN findings FILTER f.tenant_id == @tid AND f.status == 'FAIL' RETURN f.framework_mapping",
                bind_vars={"tid": TENANT},
            )
        )
        for mapping in docs:
            assert isinstance(mapping, list) and len(mapping) > 0

    def test_scan_job_persisted(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)

        job = db_tenant_a.collection("scan_jobs").get("demo-scan-job-001")
        assert job is not None
        assert job["status"] == "completed"
        assert job["tenant_id"] == TENANT
        assert job["provider"] == "aws"
        assert job["findings_fail"] > 0

    def test_idempotent_second_call_does_not_duplicate(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)
        seed_findings(db_tenant_a, TENANT)

        count = db_tenant_a.aql.execute(
            "FOR f IN findings FILTER f.tenant_id == @tid COLLECT WITH COUNT INTO c RETURN c",
            bind_vars={"tid": TENANT},
        ).next()
        assert count == len(_FINDINGS)

    def test_muted_finding_has_mute_reason(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)

        muted = list(
            db_tenant_a.aql.execute(
                "FOR f IN findings FILTER f.tenant_id == @tid AND f.status == 'MUTED' RETURN f",
                bind_vars={"tid": TENANT},
            )
        )
        assert len(muted) > 0
        for doc in muted:
            assert doc.get("mute_reason"), f"Muted finding {doc.get('check_id')} missing mute_reason"

    def test_tenant_isolation_no_cross_leak(self, db_tenant_a, db_tenant_b) -> None:
        """Findings seeded into tenant A must not appear in tenant B."""
        init_tenant_schema(db_tenant_a)
        init_tenant_schema(db_tenant_b)
        seed_findings(db_tenant_a, TENANT)

        count_b = db_tenant_b.aql.execute(
            "FOR f IN findings FILTER f.tenant_id == @tid COLLECT WITH COUNT INTO c RETURN c",
            bind_vars={"tid": "test-tenant-bbb"},
        ).next()
        assert count_b == 0


@pytest.mark.integration
class TestDevEndpointDevModeOff:
    """When DEV_MODE is False the endpoint returns 404."""

    def test_seed_returns_404_when_dev_mode_off(self, monkeypatch) -> None:
        import app.api.v1.dev as dev_module

        monkeypatch.setattr(dev_module.settings, "DEV_MODE", False)
        client = TestClient(app)
        resp = client.post("/api/v1/dev/seed", headers=HEADERS)
        assert resp.status_code == 404

    def test_clear_returns_404_when_dev_mode_off(self, monkeypatch) -> None:
        import app.api.v1.dev as dev_module

        monkeypatch.setattr(dev_module.settings, "DEV_MODE", False)
        client = TestClient(app)
        resp = client.delete("/api/v1/dev/seed", headers=HEADERS)
        assert resp.status_code == 404


@pytest.mark.integration
class TestDevEndpointDevModeOn:
    """Endpoint returns 200 and correct payload when DEV_MODE is True."""

    def test_seed_endpoint_returns_summary(self, db_tenant_a, monkeypatch) -> None:
        import app.api.v1.dev as dev_module

        monkeypatch.setattr(dev_module.settings, "DEV_MODE", True)
        client = TestClient(app)
        resp = client.post("/api/v1/dev/seed", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["seeded"] is True
        assert body["data"]["findings_inserted"] == len(_FINDINGS)

    def test_clear_endpoint_removes_findings(self, db_tenant_a, monkeypatch) -> None:
        import app.api.v1.dev as dev_module

        monkeypatch.setattr(dev_module.settings, "DEV_MODE", True)
        init_tenant_schema(db_tenant_a)
        seed_findings(db_tenant_a, TENANT)

        client = TestClient(app)
        resp = client.delete("/api/v1/dev/seed", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["data"]["cleared"] is True
        assert body["data"]["deleted_findings"] == len(_FINDINGS)
