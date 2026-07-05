"""
Integration tests for the Admin Jobs API (/api/v1/admin/jobs).

Rules:
- ArangoDB: real instance via db_tenant_a / db_tenant_b fixtures — never mocked
- Celery dispatch (run_cspm_scan.delay, control.revoke): mocked via pytest-mock
- Redis llen: mocked in queue-depth tests
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A


@pytest.fixture
def api_client(db_tenant_a, db_tenant_b):
    init_tenant_schema(db_tenant_a)
    init_tenant_schema(db_tenant_b)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed_job(db, job_id: str, tenant_id: str, status: str = "completed", provider: str = "aws") -> None:
    db.collection("scan_jobs").insert(
        {
            "_key": job_id,
            "job_id": job_id,
            "tenant_id": tenant_id,
            "provider_id": f"{provider}-111",
            "provider": provider,
            "frameworks": ["CIS-AWS-2.0"],
            "status": status,
            "checks_total": 10,
            "checks_completed": 10,
            "findings_found": 3,
            "findings_fail": 2,
            "created_at": "2026-07-05T10:00:00+00:00",
        },
        overwrite=True,
    )


# ─── GET /api/v1/admin/jobs ───────────────────────────────────────────────────


@pytest.mark.integration
class TestListAdminJobs:
    def test_list_jobs_scoped_to_tenant(self, api_client, db_tenant_a, mocker):
        """GET /admin/jobs?tenant_id=X returns only that tenant's jobs."""
        mocker.patch("app.services.admin_service.get_tenant_db_direct", return_value=db_tenant_a)
        mocker.patch("app.services.admin_service._all_tenant_ids", return_value=[TEST_TENANT_A])
        _seed_job(db_tenant_a, "job-001", TEST_TENANT_A)
        _seed_job(db_tenant_a, "job-002", TEST_TENANT_A)

        resp = api_client.get(f"/api/v1/admin/jobs?tenant_id={TEST_TENANT_A}")

        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        assert len(items) == 2
        for item in items:
            assert item["tenant_id"] == TEST_TENANT_A

    def test_list_jobs_filter_by_status(self, api_client, db_tenant_a, mocker):
        """GET /admin/jobs?status=failed returns only failed jobs."""
        mocker.patch("app.services.admin_service.get_tenant_db_direct", return_value=db_tenant_a)
        mocker.patch("app.services.admin_service._all_tenant_ids", return_value=[TEST_TENANT_A])
        _seed_job(db_tenant_a, "job-pass", TEST_TENANT_A, status="completed")
        _seed_job(db_tenant_a, "job-fail", TEST_TENANT_A, status="failed")

        resp = api_client.get(f"/api/v1/admin/jobs?tenant_id={TEST_TENANT_A}&status=failed")

        assert resp.status_code == 200
        items = resp.json()["data"]["items"]
        assert len(items) == 1
        assert items[0]["job_id"] == "job-fail"

    def test_list_jobs_respects_limit(self, api_client, db_tenant_a, mocker):
        """GET /admin/jobs?limit=1 returns at most 1 item."""
        mocker.patch("app.services.admin_service.get_tenant_db_direct", return_value=db_tenant_a)
        mocker.patch("app.services.admin_service._all_tenant_ids", return_value=[TEST_TENANT_A])
        _seed_job(db_tenant_a, "job-a", TEST_TENANT_A)
        _seed_job(db_tenant_a, "job-b", TEST_TENANT_A)

        resp = api_client.get(f"/api/v1/admin/jobs?tenant_id={TEST_TENANT_A}&limit=1")

        assert resp.status_code == 200
        assert len(resp.json()["data"]["items"]) == 1


# ─── GET /api/v1/admin/jobs/{job_id} ─────────────────────────────────────────


@pytest.mark.integration
class TestGetAdminJobDetail:
    def test_get_existing_job_returns_detail(self, api_client, db_tenant_a, mocker):
        """GET /admin/jobs/{id} with valid job_id and tenant_id returns 200."""
        mocker.patch("app.services.admin_service.get_tenant_db_direct", return_value=db_tenant_a)
        _seed_job(db_tenant_a, "job-detail-001", TEST_TENANT_A)

        resp = api_client.get(f"/api/v1/admin/jobs/job-detail-001?tenant_id={TEST_TENANT_A}")

        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["job_id"] == "job-detail-001"
        assert data["findings_found"] == 3

    def test_get_nonexistent_job_returns_404(self, api_client, db_tenant_a, mocker):
        """GET /admin/jobs/{id} with unknown job_id returns 404."""
        mocker.patch("app.services.admin_service.get_tenant_db_direct", return_value=db_tenant_a)

        resp = api_client.get(f"/api/v1/admin/jobs/does-not-exist?tenant_id={TEST_TENANT_A}")

        assert resp.status_code == 404


# ─── POST /api/v1/admin/jobs/{job_id}/retry ──────────────────────────────────


@pytest.mark.integration
class TestRetryAdminJob:
    def test_retry_job_creates_new_task(self, api_client, db_tenant_a, mocker):
        """POST /admin/jobs/{id}/retry dispatches a new Celery task and returns new_job_id."""
        mocker.patch("app.services.admin_service.get_tenant_db_direct", return_value=db_tenant_a)
        mocker.patch("app.services.admin_service.get_admin_db", return_value=db_tenant_a)
        _seed_job(db_tenant_a, "job-to-retry", TEST_TENANT_A, status="failed")

        mock_task = mocker.MagicMock()
        mock_task.id = "new-job-abc"
        mocker.patch("app.services.admin_service.run_cspm_scan.delay", return_value=mock_task)

        resp = api_client.post(
            "/api/v1/admin/jobs/job-to-retry/retry",
            json={"actor_email": "admin@example.com", "tenant_id": TEST_TENANT_A},
        )

        assert resp.status_code == 202
        data = resp.json()["data"]
        assert data["original_job_id"] == "job-to-retry"
        assert data["new_job_id"] == "new-job-abc"

    def test_retry_nonexistent_job_returns_404(self, api_client, db_tenant_a, mocker):
        """POST retry on unknown job_id returns 404."""
        mocker.patch("app.services.admin_service.get_tenant_db_direct", return_value=db_tenant_a)

        resp = api_client.post(
            "/api/v1/admin/jobs/nonexistent/retry",
            json={"actor_email": "admin@example.com", "tenant_id": TEST_TENANT_A},
        )

        assert resp.status_code == 404


# ─── DELETE /api/v1/admin/jobs/{job_id} ──────────────────────────────────────


@pytest.mark.integration
class TestRevokeAdminJob:
    def test_revoke_job_calls_celery_revoke(self, api_client, mocker):
        """DELETE /admin/jobs/{id} calls celery_app.control.revoke and returns 204."""
        mock_revoke = mocker.patch("app.services.admin_service.celery_app.control.revoke")
        mocker.patch("app.services.admin_service.get_admin_db")
        mocker.patch("app.services.admin_service.AdminAuditEntry")

        resp = api_client.delete(
            f"/api/v1/admin/jobs/job-abc?tenant_id={TEST_TENANT_A}&actor_email=admin@example.com"
        )

        assert resp.status_code == 204
        mock_revoke.assert_called_once_with("job-abc", terminate=False)


# ─── GET /api/v1/admin/workers ───────────────────────────────────────────────


@pytest.mark.integration
class TestAdminWorkers:
    def test_workers_returns_list(self, api_client, mocker):
        """GET /admin/workers returns a list (may be empty if no workers running)."""
        mocker.patch(
            "app.services.admin_service.celery_app.control.inspect",
            return_value=mocker.MagicMock(active=lambda: {}, stats=lambda: {}),
        )

        resp = api_client.get("/api/v1/admin/workers")

        assert resp.status_code == 200
        assert isinstance(resp.json()["data"], list)


# ─── GET /api/v1/admin/queue-depth ───────────────────────────────────────────


@pytest.mark.integration
class TestAdminQueueDepth:
    def test_queue_depth_returns_all_queues(self, api_client, mocker):
        """GET /admin/queue-depth returns depth for each known queue."""
        mock_redis = mocker.MagicMock()
        queue_depths = {"celery": 5, "default": 0, "discovery": 2, "scanning": 1, "iac": 0}
        mock_redis.llen.side_effect = lambda q: queue_depths.get(q, 0)
        mocker.patch("app.services.admin_service.redis_lib.from_url", return_value=mock_redis)

        resp = api_client.get("/api/v1/admin/queue-depth")

        assert resp.status_code == 200
        queues = {q["queue"]: q["depth"] for q in resp.json()["data"]}
        assert queues["celery"] == 5
        assert queues["discovery"] == 2
