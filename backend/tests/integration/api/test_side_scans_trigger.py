"""
Integration tests for POST /api/v1/side-scans/trigger (manual "Scan Now") and the
ec2/lambda branches of POST /api/v1/side-scans/jobs/{job_id}/retry, which were a
silent no-op before this change.

Rules:
- ArangoDB: real instance via db_tenant_a / db_tenant_b (never mocked)
- scan_ec2_instance_v2.delay / scan_lambda_function.delay: monkeypatched
- resolve_ec2_scan_metadata / _get_aws_session: monkeypatched — no real AWS/moto
  needed here, that lookup itself is covered by test_ec2_metadata.py
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A, TEST_TENANT_B

_HEADERS_A = {"X-Tenant-ID": TEST_TENANT_A}

_EC2_METADATA = {"i-0abc123": {"availability_zone": "us-east-1a", "volume_id": "vol-0abc123"}}


@pytest.fixture
def api_client(db_tenant_a, monkeypatch):
    init_tenant_schema(db_tenant_a)
    monkeypatch.setattr(
        "app.services.side_scanning.trigger.resolve_ec2_scan_metadata",
        lambda ec2_client, instance_ids: _EC2_METADATA,
    )
    monkeypatch.setattr("app.services.side_scanning.trigger._get_aws_session", lambda **kw: MagicMock())
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _seed_provider(db, account_id: str = "590608352058") -> None:
    db.collection("tenant_config").insert(
        {
            "_key": f"aws-{account_id}",
            "tenant_id": TEST_TENANT_A,
            "provider": "aws",
            "display_name": "Test AWS Account",
            "account_id": account_id,
            "role_arn": "arn:aws:iam::590608352058:role/OgumScanner",
        },
        overwrite=True,
    )


def _seed_ec2_resource(db, key: str = "ec2-res-1", tenant_id: str = TEST_TENANT_A, status: str = "active") -> None:
    db.collection("resources").insert(
        {
            "_key": key,
            "tenant_id": tenant_id,
            "provider": "aws",
            "resource_type": "ec2_instance",
            "resource_id": "arn:aws:ec2:us-east-1:590608352058:instance/i-0abc123",
            "arn": "arn:aws:ec2:us-east-1:590608352058:instance/i-0abc123",
            "name": "i-0abc123",
            "region": "us-east-1",
            "account_id": "590608352058",
            "status": status,
        },
        overwrite=True,
    )


def _seed_lambda_resource(db, key: str = "lambda-res-1") -> None:
    db.collection("resources").insert(
        {
            "_key": key,
            "tenant_id": TEST_TENANT_A,
            "provider": "aws",
            "resource_type": "lambda_function",
            "resource_id": "arn:aws:lambda:us-east-1:590608352058:function:my-fn",
            "arn": "arn:aws:lambda:us-east-1:590608352058:function:my-fn",
            "name": "my-fn",
            "region": "us-east-1",
            "account_id": "590608352058",
            "status": "active",
        },
        overwrite=True,
    )


# ─── POST /trigger ────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_trigger_ec2_resource_enqueues_scan(api_client: TestClient, db_tenant_a, monkeypatch) -> None:
    _seed_provider(db_tenant_a)
    _seed_ec2_resource(db_tenant_a)

    calls: list[dict] = []
    monkeypatch.setattr("app.services.side_scanning.trigger.scan_ec2_instance_v2.delay", lambda **kw: calls.append(kw))

    resp = api_client.post("/api/v1/side-scans/trigger", json={"resource_key": "ec2-res-1"}, headers=_HEADERS_A)

    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "queued"
    job_id = data["job_id"]

    assert db_tenant_a.collection("scan_jobs").has(job_id)
    job_doc = db_tenant_a.collection("scan_jobs").get(job_id)
    assert job_doc["type"] == "ec2"
    assert job_doc["resource_id"] == "ec2-res-1"

    assert len(calls) == 1
    assert calls[0]["instance_id"] == "i-0abc123"
    assert calls[0]["volume_id"] == "vol-0abc123"
    assert calls[0]["availability_zone"] == "us-east-1a"


@pytest.mark.integration
def test_trigger_lambda_resource_enqueues_scan(api_client: TestClient, db_tenant_a, monkeypatch) -> None:
    _seed_provider(db_tenant_a)
    _seed_lambda_resource(db_tenant_a)

    calls: list[dict] = []
    monkeypatch.setattr("app.services.side_scanning.trigger.scan_lambda_function.delay", lambda **kw: calls.append(kw))

    resp = api_client.post("/api/v1/side-scans/trigger", json={"resource_key": "lambda-res-1"}, headers=_HEADERS_A)

    assert resp.status_code == 202
    job_doc = db_tenant_a.collection("scan_jobs").get(resp.json()["job_id"])
    assert job_doc["type"] == "lambda"

    assert len(calls) == 1
    assert calls[0]["function_name"] == "my-fn"


@pytest.mark.integration
def test_trigger_resource_not_found_404(api_client: TestClient) -> None:
    resp = api_client.post("/api/v1/side-scans/trigger", json={"resource_key": "does-not-exist"}, headers=_HEADERS_A)
    assert resp.status_code == 404


@pytest.mark.security
def test_trigger_resource_wrong_tenant_404(api_client: TestClient, db_tenant_a) -> None:
    """Resource belonging to another tenant must not be triggerable or leak existence."""
    _seed_ec2_resource(db_tenant_a, key="ec2-tenant-b", tenant_id=TEST_TENANT_B)

    resp = api_client.post("/api/v1/side-scans/trigger", json={"resource_key": "ec2-tenant-b"}, headers=_HEADERS_A)

    assert resp.status_code == 404


@pytest.mark.integration
def test_trigger_non_scannable_resource_type_422(api_client: TestClient, db_tenant_a) -> None:
    db_tenant_a.collection("resources").insert(
        {
            "_key": "s3-res-1",
            "tenant_id": TEST_TENANT_A,
            "provider": "aws",
            "resource_type": "s3_bucket",
            "arn": "arn:aws:s3:::my-bucket",
            "status": "active",
        }
    )

    resp = api_client.post("/api/v1/side-scans/trigger", json={"resource_key": "s3-res-1"}, headers=_HEADERS_A)

    assert resp.status_code == 422


@pytest.mark.integration
def test_trigger_deleted_resource_422(api_client: TestClient, db_tenant_a) -> None:
    _seed_provider(db_tenant_a)
    _seed_ec2_resource(db_tenant_a, status="deleted")

    resp = api_client.post("/api/v1/side-scans/trigger", json={"resource_key": "ec2-res-1"}, headers=_HEADERS_A)

    assert resp.status_code == 422


@pytest.mark.integration
def test_trigger_ec2_account_level_pseudo_resource_422(api_client: TestClient, db_tenant_a) -> None:
    """Prowler's account-level check results misclassified as ec2_instance (no
    ":instance/" in the ARN) must not be passed to describe_instances."""
    _seed_provider(db_tenant_a)
    db_tenant_a.collection("resources").insert(
        {
            "_key": "ec2-account-pseudo",
            "tenant_id": TEST_TENANT_A,
            "provider": "aws",
            "resource_type": "ec2_instance",
            "arn": "arn:aws:ec2:us-east-1:590608352058:account",
            "region": "us-east-1",
            "account_id": "590608352058",
            "status": "active",
        }
    )

    resp = api_client.post(
        "/api/v1/side-scans/trigger", json={"resource_key": "ec2-account-pseudo"}, headers=_HEADERS_A
    )

    assert resp.status_code == 422


# ─── Retry — ec2/lambda job types ─────────────────────────────────────────────


@pytest.mark.integration
def test_retry_ec2_job_reenqueues_scan(api_client: TestClient, db_tenant_a, monkeypatch) -> None:
    """Retrying a failed ec2 job must actually re-enqueue — previously a silent no-op."""
    _seed_provider(db_tenant_a)
    _seed_ec2_resource(db_tenant_a)
    db_tenant_a.collection("scan_jobs").insert(
        {
            "_key": "failed-ec2-job",
            "tenant_id": TEST_TENANT_A,
            "type": "ec2",
            "status": "failed",
            "resource_id": "ec2-res-1",
            "provider_id": "aws-590608352058",
        }
    )

    calls: list[dict] = []
    monkeypatch.setattr("app.services.side_scanning.trigger.scan_ec2_instance_v2.delay", lambda **kw: calls.append(kw))

    resp = api_client.post("/api/v1/side-scans/jobs/failed-ec2-job/retry", headers=_HEADERS_A)

    assert resp.status_code == 200
    assert len(calls) == 1
    new_job_id = resp.json()["job_id"]
    assert db_tenant_a.collection("scan_jobs").get(new_job_id)["type"] == "ec2"


@pytest.mark.integration
def test_retry_lambda_job_reenqueues_scan(api_client: TestClient, db_tenant_a, monkeypatch) -> None:
    _seed_provider(db_tenant_a)
    _seed_lambda_resource(db_tenant_a)
    db_tenant_a.collection("scan_jobs").insert(
        {
            "_key": "failed-lambda-job",
            "tenant_id": TEST_TENANT_A,
            "type": "lambda",
            "status": "failed",
            "resource_id": "lambda-res-1",
            "provider_id": "aws-590608352058",
        }
    )

    calls: list[dict] = []
    monkeypatch.setattr("app.services.side_scanning.trigger.scan_lambda_function.delay", lambda **kw: calls.append(kw))

    resp = api_client.post("/api/v1/side-scans/jobs/failed-lambda-job/retry", headers=_HEADERS_A)

    assert resp.status_code == 200
    assert len(calls) == 1
