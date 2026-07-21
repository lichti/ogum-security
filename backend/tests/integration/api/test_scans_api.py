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
            "task_name": "cspm_scan/aws",
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

    def test_omitted_frameworks_dispatches_full_catalog(self, api_client, db_tenant_a, mocker):
        """No frameworks in the request body -> frameworks=None (Prowler's full
        check catalog), not a curated default subset."""
        _seed_provider(db_tenant_a)
        mock_task = mocker.MagicMock()
        mock_task.id = "job-full"
        mock_delay = mocker.patch("app.api.v1.scans.run_cspm_scan.delay", return_value=mock_task)

        api_client.post(
            "/api/v1/scans",
            json={"provider_id": "aws-111111111111"},
            headers=HEADERS,
        )

        mock_delay.assert_called_once()
        assert mock_delay.call_args.kwargs["frameworks"] is None


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
        body = resp.json()["data"]
        assert len(body["items"]) == 2
        for job in body["items"]:
            assert job["tenant_id"] == TEST_TENANT_A

    def test_list_scans_empty_returns_empty_list(self, api_client):
        """GET /api/v1/scans with no jobs returns empty list."""
        resp = api_client.get("/api/v1/scans", headers=HEADERS)

        assert resp.status_code == 200
        assert resp.json()["data"] == {"items": [], "next_cursor": None}

    def test_list_scans_excludes_side_scan_jobs(self, api_client, db_tenant_a):
        """`scan_jobs` is shared with side-scanning (`task_name` "side_scan/*", no
        `frameworks` field at all) — mixing one into the CSPM list used to 500 the
        whole endpoint (ValidationError: frameworks Field required)."""
        _seed_scan_job(db_tenant_a, "job-cspm")
        db_tenant_a.collection("scan_jobs").insert(
            {
                "_key": "job-side-scan",
                "job_id": "job-side-scan",
                "tenant_id": TEST_TENANT_A,
                "task_name": "side_scan/ec2",
                "status": "completed",
                "created_at": "2026-07-04T00:00:00+00:00",
            },
            overwrite=True,
        )

        resp = api_client.get("/api/v1/scans", headers=HEADERS)

        assert resp.status_code == 200
        job_ids = [j["job_id"] for j in resp.json()["data"]["items"]]
        assert job_ids == ["job-cspm"]

    def test_get_scan_status_404s_for_a_side_scan_job_id(self, api_client, db_tenant_a):
        """GET /{job_id} scoped to CSPM jobs — a side-scan job id is out of scope
        for this endpoint (it has its own registry, the Side Scanning page)."""
        db_tenant_a.collection("scan_jobs").insert(
            {
                "_key": "job-side-scan",
                "job_id": "job-side-scan",
                "tenant_id": TEST_TENANT_A,
                "task_name": "side_scan/ec2",
                "status": "completed",
                "created_at": "2026-07-04T00:00:00+00:00",
            },
            overwrite=True,
        )

        resp = api_client.get("/api/v1/scans/job-side-scan", headers=HEADERS)
        assert resp.status_code == 404

    def test_list_scans_filters_by_status(self, api_client, db_tenant_a):
        _seed_scan_job(db_tenant_a, "job-completed", status="completed")
        _seed_scan_job(db_tenant_a, "job-failed", status="failed")

        resp = api_client.get("/api/v1/scans?status=failed", headers=HEADERS)

        body = resp.json()["data"]
        assert len(body["items"]) == 1
        assert body["items"][0]["job_id"] == "job-failed"

    def test_list_scans_filters_by_provider_id(self, api_client, db_tenant_a):
        _seed_scan_job(db_tenant_a, "job-a")
        db_tenant_a.collection("scan_jobs").update({"_key": "job-a", "provider_id": "aws-222222222222"})
        _seed_scan_job(db_tenant_a, "job-b")

        resp = api_client.get("/api/v1/scans?provider_id=aws-222222222222", headers=HEADERS)

        body = resp.json()["data"]
        assert len(body["items"]) == 1
        assert body["items"][0]["job_id"] == "job-a"

    def test_list_scans_paginates_with_cursor(self, api_client, db_tenant_a):
        for i in range(3):
            _seed_scan_job(db_tenant_a, f"job-{i}")
            db_tenant_a.collection("scan_jobs").update(
                {"_key": f"job-{i}", "created_at": f"2026-07-0{i + 1}T00:00:00+00:00"}
            )

        first_page = api_client.get("/api/v1/scans?limit=2", headers=HEADERS).json()["data"]
        assert len(first_page["items"]) == 2
        assert first_page["items"][0]["job_id"] == "job-2"  # newest first
        assert first_page["next_cursor"] is not None

        second_page = api_client.get(
            f"/api/v1/scans?limit=2&cursor={first_page['next_cursor']}", headers=HEADERS
        ).json()["data"]
        assert len(second_page["items"]) == 1
        assert second_page["items"][0]["job_id"] == "job-0"
        assert second_page["next_cursor"] is None

    def test_get_scan_status_includes_new_summary_fields(self, api_client, db_tenant_a):
        """The counts the Scans page needs (US-14.23) round-trip through the API."""
        _seed_scan_job(db_tenant_a, "job-summary")
        db_tenant_a.collection("scan_jobs").update(
            {
                "_key": "job-summary",
                "findings_new": 3,
                "findings_updated": 5,
                "findings_removed": 1,
                "assets_total": 12,
                "assets_removed": 2,
                "duration_seconds": 45.5,
            }
        )

        resp = api_client.get("/api/v1/scans/job-summary", headers=HEADERS)
        data = resp.json()["data"]
        assert data["findings_new"] == 3
        assert data["findings_updated"] == 5
        assert data["findings_removed"] == 1
        assert data["assets_total"] == 12
        assert data["assets_removed"] == 2
        assert data["duration_seconds"] == 45.5


# ─── GET /api/v1/scans/{job_id}/logs ───────────────────────────────────────────


@pytest.mark.integration
class TestGetScanLogs:
    def test_get_logs_returns_lines(self, api_client, db_tenant_a):
        _seed_scan_job(db_tenant_a, "job-logs")
        db_tenant_a.collection("scan_jobs").update({"_key": "job-logs", "logs": ["line 1", "line 2"]})

        resp = api_client.get("/api/v1/scans/job-logs/logs", headers=HEADERS)

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["job_id"] == "job-logs"
        assert data["logs"] == ["line 1", "line 2"]

    def test_get_logs_defaults_to_empty_list(self, api_client, db_tenant_a):
        """A job with no `logs` field yet (still running) returns [], not an error."""
        _seed_scan_job(db_tenant_a, "job-no-logs")

        resp = api_client.get("/api/v1/scans/job-no-logs/logs", headers=HEADERS)

        assert resp.status_code == 200
        assert resp.json()["data"]["logs"] == []

    def test_get_logs_nonexistent_job_returns_404(self, api_client):
        resp = api_client.get("/api/v1/scans/does-not-exist/logs", headers=HEADERS)
        assert resp.status_code == 404

    def test_get_logs_wrong_tenant_returns_403(self, api_client, db_tenant_a):
        _seed_scan_job(db_tenant_a, "job-tenant-a", tenant_id=TEST_TENANT_A)

        resp = api_client.get(
            "/api/v1/scans/job-tenant-a/logs",
            headers={"X-Tenant-Id": "other-tenant-bbb"},
        )
        assert resp.status_code == 403
