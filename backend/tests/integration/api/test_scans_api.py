"""
Integration tests for the Scans API (/api/v1/scans).

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
- run_cspm_scan.delay: mocked — Celery broker not needed in API tests
- Celery: task dispatch is mocked; actual task is tested in test_cspm_scan.py
"""

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


def _seed_provider(db, provider_id: str = "aws-111111111111", account_id: str = "111111111111"):
    """Insert a minimal provider doc directly into tenant_config."""
    if not db.has_collection("tenant_config"):
        db.create_collection("tenant_config")
    db.collection("tenant_config").insert(
        {
            "_key": provider_id,
            "provider": "aws",
            "display_name": "Test AWS",
            "account_id": account_id,
            "regions": ["us-east-1"],
            "enabled": True,
            "status": "active",
            "credential_type": "static",
            "role_arn": None,
            "external_id": "ext-001",
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "test-secret",
            "azure_client_secret": None,
            "gcp_service_account_json": None,
            "kubeconfig": None,
        },
        overwrite=True,
    )


def _seed_scan_job(db, job_id: str, tenant_id: str = TEST_TENANT_A, status: str = "completed"):
    db.collection("scan_jobs").insert(
        {
            "_key": job_id,
            "job_id": job_id,
            "tenant_id": tenant_id,
            "provider_id": "aws-111111111111",
            "provider": "aws",
            "frameworks": ["CIS-AWS-2.0"],
            "regions": ["us-east-1"],
            "status": status,
            "checks_total": 5,
            "checks_completed": 5,
            "findings_found": 2,
            "findings_fail": 1,
            "created_at": "2026-07-03T00:00:00+00:00",
        },
        overwrite=True,
    )


# ─── POST /api/v1/scans ───────────────────────────────────────────────────────


@pytest.mark.integration
class TestTriggerScan:
    def test_trigger_scan_happy_path(self, api_client, db_tenant_a, mocker):
        """POST /api/v1/scans with valid provider returns 202 and a job_id."""
        _seed_provider(db_tenant_a)
        mock_task = mocker.MagicMock()
        mock_task.id = "job-001"
        mocker.patch("app.api.v1.scans.run_cspm_scan.delay", return_value=mock_task)

        resp = api_client.post(
            "/api/v1/scans",
            json={"provider_id": "aws-111111111111", "frameworks": ["CIS-AWS-2.0"]},
            headers=HEADERS,
        )

        assert resp.status_code == 202
        data = resp.json()["data"]
        assert data["job_id"] == "job-001"
        assert data["status"] == "queued"

    def test_trigger_scan_provider_not_found_returns_404(self, api_client, mocker):
        """POST with unknown provider_id must return 404."""
        mocker.patch("app.api.v1.scans.run_cspm_scan.delay")

        resp = api_client.post(
            "/api/v1/scans",
            json={"provider_id": "nonexistent-provider", "frameworks": ["CIS-AWS-2.0"]},
            headers=HEADERS,
        )

        assert resp.status_code == 404

    def test_trigger_scan_missing_header_returns_422(self, api_client, mocker):
        """POST without X-Tenant-Id header returns 422."""
        mocker.patch("app.api.v1.scans.run_cspm_scan.delay")

        resp = api_client.post(
            "/api/v1/scans",
            json={"provider_id": "aws-111111111111", "frameworks": ["CIS-AWS-2.0"]},
        )

        assert resp.status_code == 422

    def test_trigger_scan_missing_provider_id_returns_422(self, api_client, mocker):
        """POST without required provider_id field returns 422."""
        mocker.patch("app.api.v1.scans.run_cspm_scan.delay")

        resp = api_client.post(
            "/api/v1/scans",
            json={"frameworks": ["CIS-AWS-2.0"]},
            headers=HEADERS,
        )

        assert resp.status_code == 422

    def test_trigger_scan_dispatches_task_with_correct_args(self, api_client, db_tenant_a, mocker):
        """Verify run_cspm_scan.delay is called with the correct parameters."""
        _seed_provider(db_tenant_a)
        mock_task = mocker.MagicMock()
        mock_task.id = "job-abc"
        mock_delay = mocker.patch("app.api.v1.scans.run_cspm_scan.delay", return_value=mock_task)

        api_client.post(
            "/api/v1/scans",
            json={"provider_id": "aws-111111111111", "frameworks": ["CIS-AWS-2.0"]},
            headers=HEADERS,
        )

        mock_delay.assert_called_once()
        call_kwargs = mock_delay.call_args.kwargs
        assert call_kwargs["tenant_id"] == TEST_TENANT_A
        assert call_kwargs["provider"] == "aws"
        assert call_kwargs["frameworks"] == ["CIS-AWS-2.0"]
        assert call_kwargs["account_id"] == "111111111111"


# ─── GET /api/v1/scans/{job_id} ───────────────────────────────────────────────


@pytest.mark.integration
class TestGetScanStatus:
    def test_get_existing_job_returns_200(self, api_client, db_tenant_a):
        """GET with valid job_id returns 200 and job metadata."""
        _seed_scan_job(db_tenant_a, "job-abc")

        resp = api_client.get("/api/v1/scans/job-abc", headers=HEADERS)

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["job_id"] == "job-abc"
        assert data["status"] == "completed"
        assert data["findings_found"] == 2

    def test_get_nonexistent_job_returns_404(self, api_client):
        """GET with unknown job_id returns 404."""
        resp = api_client.get("/api/v1/scans/does-not-exist", headers=HEADERS)
        assert resp.status_code == 404

    def test_get_job_wrong_tenant_returns_403(self, api_client, db_tenant_a):
        """Tenant B cannot read a job created by Tenant A."""
        _seed_scan_job(db_tenant_a, "job-tenant-a", tenant_id=TEST_TENANT_A)

        resp = api_client.get(
            "/api/v1/scans/job-tenant-a",
            headers={"X-Tenant-Id": "other-tenant-bbb"},
        )
        assert resp.status_code == 403


# ─── GET /api/v1/scans ────────────────────────────────────────────────────────


@pytest.mark.integration
class TestListScans:
    def test_list_scans_returns_only_tenant_jobs(self, api_client, db_tenant_a):
        """GET /api/v1/scans returns only jobs for the requesting tenant."""
        _seed_scan_job(db_tenant_a, "job-001", tenant_id=TEST_TENANT_A)
        _seed_scan_job(db_tenant_a, "job-002", tenant_id=TEST_TENANT_A)
        _seed_scan_job(db_tenant_a, "job-other", tenant_id="other-tenant")

        resp = api_client.get("/api/v1/scans", headers=HEADERS)

        assert resp.status_code == 200
        jobs = resp.json()["data"]
        assert len(jobs) == 2
        for job in jobs:
            assert job["tenant_id"] == TEST_TENANT_A

    def test_list_scans_empty_returns_empty_list(self, api_client):
        """GET /api/v1/scans with no jobs returns empty list."""
        resp = api_client.get("/api/v1/scans", headers=HEADERS)

        assert resp.status_code == 200
        assert resp.json()["data"] == []
