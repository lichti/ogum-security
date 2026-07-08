"""
Integration tests for Sprint 4 endpoints:
  POST /api/v1/side-scans/webhooks/ecr
  GET  /api/v1/side-scans/jobs
  GET  /api/v1/side-scans/jobs/{job_id}
  POST /api/v1/side-scans/jobs/{job_id}/retry
  GET  /api/v1/side-scans/images/{digest}/security

Rules:
- ArangoDB: real instance via db_tenant_a / db_tenant_b (never mocked)
- scan_container_image.delay: monkeypatched — no Celery broker needed
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

_SCANNER_TOKEN = "test-scanner-token-ecr-abc"

_HEADERS_A = {
    "X-Tenant-ID": TEST_TENANT_A,
    "x-ogum-tenant-id": TEST_TENANT_A,
    "x-ogum-token": _SCANNER_TOKEN,
}

_ECR_PAYLOAD = {
    "image_uri": "123456789.dkr.ecr.us-east-1.amazonaws.com/my-app",
    "image_digest": "sha256:deadbeefcafe0123",
    "repository_name": "my-app",
    "registry_id": "123456789",
    "provider_id": "aws-provider-001",
}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
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


# ─── ECR webhook ─────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_ecr_webhook_enqueues_task(api_client: TestClient, db_tenant_a, monkeypatch) -> None:
    """Valid ECR push event → 202, scan_jobs record created, task dispatched."""
    calls: list[dict] = []
    monkeypatch.setattr("app.api.v1.side_scans.scan_container_image.delay", lambda **kw: calls.append(kw))

    resp = api_client.post("/api/v1/side-scans/webhooks/ecr", json=_ECR_PAYLOAD, headers=_HEADERS_A)

    assert resp.status_code == 202
    data = resp.json()
    assert "job_id" in data
    assert data["status"] == "queued"

    job_id = data["job_id"]
    assert db_tenant_a.collection("scan_jobs").has(job_id)
    job_doc = db_tenant_a.collection("scan_jobs").get(job_id)
    assert job_doc["tenant_id"] == TEST_TENANT_A
    assert job_doc["type"] == "ecr"
    assert len(calls) == 1
    assert calls[0]["image_digest"] == _ECR_PAYLOAD["image_digest"]


@pytest.mark.integration
def test_ecr_webhook_invalid_token_401(api_client: TestClient) -> None:
    bad_headers = {**_HEADERS_A, "x-ogum-token": "wrong"}
    resp = api_client.post("/api/v1/side-scans/webhooks/ecr", json=_ECR_PAYLOAD, headers=bad_headers)
    assert resp.status_code == 401


# ─── Jobs list ────────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_list_scan_jobs_returns_tenant_jobs(api_client: TestClient, db_tenant_a) -> None:
    """GET /jobs returns only jobs belonging to the requesting tenant."""
    # Seed two jobs for tenant A
    db_tenant_a.collection("scan_jobs").insert(
        {"_key": "job-a-001", "tenant_id": TEST_TENANT_A, "type": "ecr", "status": "completed", "created_at": "1000"},
        overwrite=True,
    )
    db_tenant_a.collection("scan_jobs").insert(
        {"_key": "job-a-002", "tenant_id": TEST_TENANT_A, "type": "ec2", "status": "failed", "created_at": "999"},
        overwrite=True,
    )
    # Seed one job for tenant B (must NOT appear)
    db_tenant_a.collection("scan_jobs").insert(
        {"_key": "job-b-001", "tenant_id": TEST_TENANT_B, "type": "ecr", "status": "completed", "created_at": "998"},
        overwrite=True,
    )

    resp = api_client.get("/api/v1/side-scans/jobs", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    returned_ids = {j["_key"] for j in data["items"]}
    assert "job-a-001" in returned_ids
    assert "job-a-002" in returned_ids
    assert "job-b-001" not in returned_ids


@pytest.mark.integration
def test_list_scan_jobs_status_filter(api_client: TestClient, db_tenant_a) -> None:
    """GET /jobs?status=completed returns only completed jobs."""
    db_tenant_a.collection("scan_jobs").insert(
        {"_key": "j-comp", "tenant_id": TEST_TENANT_A, "type": "ecr", "status": "completed", "created_at": "1"},
        overwrite=True,
    )
    db_tenant_a.collection("scan_jobs").insert(
        {"_key": "j-fail", "tenant_id": TEST_TENANT_A, "type": "ec2", "status": "failed", "created_at": "2"},
        overwrite=True,
    )

    resp = api_client.get("/api/v1/side-scans/jobs?status=completed", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert resp.status_code == 200
    items = resp.json()["items"]
    for item in items:
        assert item["status"] == "completed"


# ─── Job detail ──────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_get_scan_job_returns_correct_doc(api_client: TestClient, db_tenant_a) -> None:
    db_tenant_a.collection("scan_jobs").insert(
        {"_key": "job-detail-001", "tenant_id": TEST_TENANT_A, "type": "ecr", "status": "running", "created_at": "1"},
        overwrite=True,
    )
    resp = api_client.get("/api/v1/side-scans/jobs/job-detail-001", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert resp.status_code == 200
    assert resp.json()["_key"] == "job-detail-001"


@pytest.mark.integration
def test_get_scan_job_wrong_tenant_returns_404(api_client: TestClient, db_tenant_a) -> None:
    """Job belonging to another tenant_id in the doc must return 404, not the real doc."""
    db_tenant_a.collection("scan_jobs").insert(
        {
            "_key": "job-other-tenant",
            "tenant_id": TEST_TENANT_B,
            "type": "ecr",
            "status": "completed",
            "created_at": "1",
        },
        overwrite=True,
    )
    resp = api_client.get("/api/v1/side-scans/jobs/job-other-tenant", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert resp.status_code == 404


@pytest.mark.integration
def test_get_scan_job_not_found_404(api_client: TestClient) -> None:
    resp = api_client.get("/api/v1/side-scans/jobs/nonexistent-job-id", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert resp.status_code == 404


# ─── Retry ───────────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_retry_failed_job_creates_new_job(api_client: TestClient, db_tenant_a, monkeypatch) -> None:
    calls: list[dict] = []
    monkeypatch.setattr("app.api.v1.side_scans.scan_container_image.delay", lambda **kw: calls.append(kw))

    db_tenant_a.collection("scan_jobs").insert(
        {
            "_key": "job-fail-001",
            "tenant_id": TEST_TENANT_A,
            "type": "ecr",
            "status": "failed",
            "image_uri": "123.dkr.ecr.us-east-1.amazonaws.com/app",
            "image_digest": "sha256:abc",
            "provider_id": "aws-001",
            "created_at": "1",
        },
        overwrite=True,
    )

    resp = api_client.post("/api/v1/side-scans/jobs/job-fail-001/retry", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "queued"
    new_id = data["job_id"]
    assert new_id != "job-fail-001"
    assert db_tenant_a.collection("scan_jobs").has(new_id)
    assert len(calls) == 1


@pytest.mark.integration
def test_retry_non_failed_job_returns_422(api_client: TestClient, db_tenant_a) -> None:
    db_tenant_a.collection("scan_jobs").insert(
        {"_key": "job-running-001", "tenant_id": TEST_TENANT_A, "type": "ecr", "status": "running", "created_at": "1"},
        overwrite=True,
    )
    resp = api_client.post("/api/v1/side-scans/jobs/job-running-001/retry", headers={"X-Tenant-ID": TEST_TENANT_A})
    assert resp.status_code == 422


# ─── Image security badge ────────────────────────────────────────────────────


@pytest.mark.integration
def test_image_security_badge_fail_on_critical(api_client: TestClient, db_tenant_a) -> None:
    """Image with CRITICAL findings → overall_status = fail."""
    digest = "sha256:testdigest001"
    resource_id = digest.replace(":", "_").replace("/", "_")[:120]
    db_tenant_a.collection("findings").insert(
        {
            "_key": "f-crit-001",
            "tenant_id": TEST_TENANT_A,
            "resource_id": resource_id,
            "severity": "CRITICAL",
            "status": "FAIL",
        },
        overwrite=True,
    )
    from urllib.parse import quote

    resp = api_client.get(
        f"/api/v1/side-scans/images/{quote(digest, safe='')}/security",
        headers={"X-Tenant-ID": TEST_TENANT_A},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_status"] == "fail"
    assert data["critical"] >= 1


@pytest.mark.integration
def test_image_security_badge_pass_on_no_findings(api_client: TestClient, db_tenant_a) -> None:
    """Image with no findings → overall_status = pass."""
    from urllib.parse import quote

    digest = "sha256:cleanimage000"
    resp = api_client.get(
        f"/api/v1/side-scans/images/{quote(digest, safe='')}/security",
        headers={"X-Tenant-ID": TEST_TENANT_A},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["overall_status"] == "pass"
    assert data["critical"] == 0
    assert data["high"] == 0
