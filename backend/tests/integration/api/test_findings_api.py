"""
Integration tests for the Findings API (/api/v1/findings).

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
- Celery: not involved — findings are seeded directly for these API tests
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

HEADERS = {"X-Tenant-Id": TEST_TENANT_A}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed_finding(db, key: str, tenant_id: str = TEST_TENANT_A, **overrides) -> dict:
    doc = {
        "_key": key,
        "finding_id": key,
        "tenant_id": tenant_id,
        "check_id": "check_s3_public",
        "title": "Public S3 Bucket",
        "description": "Bucket is publicly accessible",
        "resource_id": f"arn:aws:s3:::{key}",
        "resource_arn": f"arn:aws:s3:::{key}",
        "resource_type": "s3_bucket",
        "severity": "CRITICAL",
        "status": "FAIL",
        "provider": "aws",
        "region": "us-east-1",
        "account_id": "123456789012",
        "framework_mapping": ["CIS-AWS-2.0", "SOC2"],
        "source": "cspm",
        "detected_at": "2026-07-03T10:00:00+00:00",
        "updated_at": "2026-07-03T10:00:00+00:00",
        "remediation": "Make bucket private",
        "remediation_code": None,
        "mute_reason": None,
        "scan_job_id": None,
        "raw_output": {},
        **overrides,
    }
    db.collection("findings").insert(doc, overwrite=True)
    return doc


# ─── GET /api/v1/findings ─────────────────────────────────────────────────────


@pytest.mark.integration
class TestListFindings:
    def test_list_returns_findings_for_tenant(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "find-001")
        _seed_finding(db_tenant_a, "find-002")

        resp = api_client.get("/api/v1/findings", headers=HEADERS)

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["count"] == 2
        assert len(data["items"]) == 2

    def test_list_empty_returns_empty(self, api_client):
        resp = api_client.get("/api/v1/findings", headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"]["count"] == 0

    def test_filter_by_severity(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "crit-001", severity="CRITICAL")
        _seed_finding(db_tenant_a, "high-001", severity="HIGH")

        resp = api_client.get("/api/v1/findings?severity=CRITICAL", headers=HEADERS)

        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert items[0]["severity"] == "CRITICAL"

    def test_filter_by_status(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "fail-001", status="FAIL")
        _seed_finding(db_tenant_a, "muted-001", status="MUTED")

        resp = api_client.get("/api/v1/findings?status=FAIL", headers=HEADERS)

        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert items[0]["status"] == "FAIL"

    def test_filter_by_provider(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "aws-001", provider="aws")
        _seed_finding(db_tenant_a, "gcp-001", provider="gcp")

        resp = api_client.get("/api/v1/findings?provider=aws", headers=HEADERS)

        items = resp.json()["data"]["items"]
        assert all(f["provider"] == "aws" for f in items)

    def test_filter_by_framework(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "cis-001", framework_mapping=["CIS-AWS-2.0"])
        _seed_finding(db_tenant_a, "pci-001", framework_mapping=["PCI_DSS"])

        resp = api_client.get("/api/v1/findings?framework=PCI_DSS", headers=HEADERS)

        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert "PCI_DSS" in items[0]["framework_mapping"]

    def test_text_search_by_title(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "s3-001", title="Public S3 Bucket")
        _seed_finding(db_tenant_a, "sg-001", title="Overly Permissive Security Group")

        resp = api_client.get("/api/v1/findings?q=s3", headers=HEADERS)

        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert "S3" in items[0]["title"]

    def test_combined_filters(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "match", severity="HIGH", status="FAIL", provider="aws")
        _seed_finding(db_tenant_a, "no-match", severity="LOW", status="FAIL", provider="aws")

        resp = api_client.get("/api/v1/findings?severity=HIGH&status=FAIL", headers=HEADERS)

        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert items[0]["_key"] == "match"

    def test_invalid_provider_returns_422(self, api_client):
        resp = api_client.get("/api/v1/findings?provider=invalid", headers=HEADERS)
        assert resp.status_code == 422

    def test_missing_header_returns_422(self, api_client):
        resp = api_client.get("/api/v1/findings")
        assert resp.status_code == 422

    def test_pagination_cursor_returns_next_page(self, api_client, db_tenant_a):
        """With limit=1 and 2 findings, first page has cursor, second page has none."""
        _seed_finding(db_tenant_a, "page-001", detected_at="2026-07-04T00:00:00+00:00")
        _seed_finding(db_tenant_a, "page-002", detected_at="2026-07-03T00:00:00+00:00")

        resp1 = api_client.get("/api/v1/findings?limit=1", headers=HEADERS)
        data1 = resp1.json()["data"]
        assert data1["count"] == 1
        assert data1["next_cursor"] is not None

        resp2 = api_client.get(f"/api/v1/findings?limit=1&cursor={data1['next_cursor']}", headers=HEADERS)
        data2 = resp2.json()["data"]
        assert data2["count"] == 1
        assert data2["next_cursor"] is None
        # Two pages return different items
        assert data1["items"][0]["_key"] != data2["items"][0]["_key"]

    def test_pagination_no_cursor_when_single_page(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "only-001")

        resp = api_client.get("/api/v1/findings?limit=50", headers=HEADERS)
        data = resp.json()["data"]
        assert data["next_cursor"] is None


# ─── GET /api/v1/findings/{finding_key} ──────────────────────────────────────


@pytest.mark.integration
class TestGetFinding:
    def test_get_existing_finding_returns_200(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "detail-001")

        resp = api_client.get("/api/v1/findings/detail-001", headers=HEADERS)

        assert resp.status_code == 200
        doc = resp.json()["data"]
        assert doc["_key"] == "detail-001"
        assert "attack_paths" in doc
        assert doc["attack_paths"] == []

    def test_get_nonexistent_returns_404(self, api_client):
        resp = api_client.get("/api/v1/findings/does-not-exist", headers=HEADERS)
        assert resp.status_code == 404

    def test_get_finding_includes_cli_command(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "cli-001", provider="aws", resource_type="s3_bucket")

        resp = api_client.get("/api/v1/findings/cli-001", headers=HEADERS)

        doc = resp.json()["data"]
        assert "cli_command" in doc
        assert doc["cli_command"] is not None
        assert "aws" in doc["cli_command"]


# ─── PATCH /api/v1/findings/{finding_key} ────────────────────────────────────


@pytest.mark.integration
class TestUpdateFindingStatus:
    def test_mute_finding_with_reason(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "mute-me")

        resp = api_client.patch(
            "/api/v1/findings/mute-me",
            json={"status": "MUTED", "reason": "Accepted by security team"},
            headers=HEADERS,
        )

        assert resp.status_code == 200
        doc = resp.json()["data"]
        assert doc["status"] == "MUTED"
        assert doc["mute_reason"] == "Accepted by security team"

    def test_accept_finding(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "accept-me")

        resp = api_client.patch(
            "/api/v1/findings/accept-me",
            json={"status": "ACCEPTED", "reason": "Risk accepted"},
            headers=HEADERS,
        )

        assert resp.status_code == 200
        assert resp.json()["data"]["status"] == "ACCEPTED"

    def test_mute_without_reason_returns_422(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "need-reason")

        resp = api_client.patch(
            "/api/v1/findings/need-reason",
            json={"status": "MUTED"},
            headers=HEADERS,
        )

        assert resp.status_code == 422

    def test_patch_nonexistent_returns_404(self, api_client):
        resp = api_client.patch(
            "/api/v1/findings/ghost",
            json={"status": "MUTED", "reason": "test"},
            headers=HEADERS,
        )
        assert resp.status_code == 404

    def test_cannot_patch_to_fail_status(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "no-reopen")

        resp = api_client.patch(
            "/api/v1/findings/no-reopen",
            json={"status": "FAIL"},
            headers=HEADERS,
        )

        assert resp.status_code == 422

    def test_audit_log_entry_created_on_mute(self, api_client, db_tenant_a):
        _seed_finding(db_tenant_a, "audit-me")

        api_client.patch(
            "/api/v1/findings/audit-me",
            json={"status": "MUTED", "reason": "Compliance exception"},
            headers=HEADERS,
        )

        logs = list(db_tenant_a.aql.execute("FOR l IN audit_log FILTER l.finding_key == 'audit-me' RETURN l"))
        assert len(logs) == 1
        assert logs[0]["action"] == "status_changed_to_MUTED"
