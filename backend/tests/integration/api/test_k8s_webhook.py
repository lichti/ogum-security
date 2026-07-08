"""
Integration tests for POST /api/v1/side-scans/webhooks/k8s-scan.

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
- scan_k8s_container.delay: mocked — Celery broker not needed in API tests
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

_SCANNER_TOKEN = "test-scanner-token-abc123"

_VALID_HEADERS = {
    "X-Tenant-ID": TEST_TENANT_A,
    "x-ogum-tenant-id": TEST_TENANT_A,
    "x-ogum-token": _SCANNER_TOKEN,
}

_VALID_PAYLOAD = {
    "pod_name": "my-app-pod",
    "pod_namespace": "default",
    "container_name": "app",
    "pid": 12345,
    "node_name": "node-1",
    "resource_id": "pods_default_my-app-pod",
    "provider_id": "k8s-provider",
}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)

    # Seed tenant_config with scanner_token
    db_tenant_a.collection("tenant_config").insert(
        {
            "_key": "config",
            "tenant_id": TEST_TENANT_A,
            "scanner_token": _SCANNER_TOKEN,
        },
        overwrite=True,
    )

    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


@pytest.mark.integration
def test_valid_token_enqueues_task(api_client: TestClient, db_tenant_a, monkeypatch) -> None:
    """Valid token → 202, scan_jobs record created, task enqueued."""
    task_calls: list[dict] = []

    def _fake_delay(**kwargs):
        task_calls.append(kwargs)

    monkeypatch.setattr(
        "app.api.v1.side_scans.scan_k8s_container.delay",
        lambda **kw: task_calls.append(kw),
    )

    resp = api_client.post(
        "/api/v1/side-scans/webhooks/k8s-scan",
        json=_VALID_PAYLOAD,
        headers=_VALID_HEADERS,
    )

    assert resp.status_code == 202
    data = resp.json()
    assert "job_id" in data
    assert data["status"] == "queued"

    # scan_jobs record created
    job_id = data["job_id"]
    assert db_tenant_a.collection("scan_jobs").has(job_id)

    # task was dispatched
    assert len(task_calls) == 1


@pytest.mark.integration
def test_invalid_token_returns_401(api_client: TestClient) -> None:
    """Wrong scanner token → 401."""
    headers = {**_VALID_HEADERS, "x-ogum-token": "wrong-token"}
    resp = api_client.post(
        "/api/v1/side-scans/webhooks/k8s-scan",
        json=_VALID_PAYLOAD,
        headers=headers,
    )
    assert resp.status_code == 401


@pytest.mark.integration
def test_missing_token_returns_422(api_client: TestClient) -> None:
    """Missing x-ogum-token header → 422 (required header not provided)."""
    headers = {k: v for k, v in _VALID_HEADERS.items() if k != "x-ogum-token"}
    resp = api_client.post(
        "/api/v1/side-scans/webhooks/k8s-scan",
        json=_VALID_PAYLOAD,
        headers=headers,
    )
    assert resp.status_code == 422
