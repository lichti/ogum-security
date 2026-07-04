"""Integration tests for POST /api/v1/scans/iac."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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


@pytest.mark.integration
def test_trigger_iac_scan_returns_202_with_job_id(api_client) -> None:
    mock_task = MagicMock()
    mock_task.id = "mock-task-id-001"

    with patch("app.api.v1.iac_scans.run_iac_scan") as mock_celery:
        mock_celery.delay.return_value = mock_task
        resp = api_client.post(
            "/api/v1/scans/iac",
            json={"repo_url": "https://github.com/example/infra", "branch": "main", "path": "."},
            headers=HEADERS,
        )

    assert resp.status_code == 202
    body = resp.json()["data"]
    assert body["job_id"] == "mock-task-id-001"
    assert body["status"] == "queued"


@pytest.mark.integration
def test_trigger_iac_scan_passes_all_params_to_task(api_client) -> None:
    mock_task = MagicMock()
    mock_task.id = "task-002"

    with patch("app.api.v1.iac_scans.run_iac_scan") as mock_celery:
        mock_celery.delay.return_value = mock_task
        api_client.post(
            "/api/v1/scans/iac",
            json={
                "repo_url": "https://github.com/example/infra",
                "branch": "develop",
                "path": "terraform/aws",
                "account_id": "111111111111",
                "repo_token": "ghp_secret",
            },
            headers=HEADERS,
        )
        mock_celery.delay.assert_called_once_with(
            tenant_id=TEST_TENANT_A,
            repo_url="https://github.com/example/infra",
            branch="develop",
            path="terraform/aws",
            account_id="111111111111",
            repo_token="ghp_secret",
        )


@pytest.mark.integration
def test_trigger_iac_scan_rejects_invalid_url(api_client) -> None:
    resp = api_client.post(
        "/api/v1/scans/iac",
        json={"repo_url": "not-a-url"},
        headers=HEADERS,
    )
    assert resp.status_code == 422


@pytest.mark.integration
def test_trigger_iac_scan_requires_tenant_header(api_client) -> None:
    resp = api_client.post(
        "/api/v1/scans/iac",
        json={"repo_url": "https://github.com/example/infra"},
    )
    assert resp.status_code == 422


@pytest.mark.integration
def test_get_iac_scan_job_not_found(api_client) -> None:
    resp = api_client.get("/api/v1/scans/iac/nonexistent-job-id", headers=HEADERS)
    assert resp.status_code == 404
