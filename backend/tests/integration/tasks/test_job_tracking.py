"""
Integration tests for discovery job tracking (_job_tracking.py helpers).

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
- Helpers must not raise even when scan_jobs collection is missing
- State transitions: running → completed | failed
"""

import pytest

from app.db.init import init_tenant_schema
from app.workers.tasks._job_tracking import (
    complete_discovery_job,
    fail_discovery_job,
    start_discovery_job,
)


@pytest.mark.integration
class TestStartDiscoveryJob:
    """start_discovery_job inserts a running doc and returns a usable job_id."""

    def test_creates_running_doc(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        job_id = start_discovery_job(db_tenant_a, "tenant-a", "aws", "aws-key-1", ["us-east-1"])

        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert doc is not None
        assert doc["status"] == "running"
        assert doc["provider"] == "aws"
        assert doc["tenant_id"] == "tenant-a"
        assert doc["provider_id"] == "aws-key-1"
        assert doc["regions"] == ["us-east-1"]
        assert doc["task_name"] == "discovery/aws"
        assert "started_at" in doc
        assert "created_at" in doc

    def test_returns_unique_job_ids(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        id1 = start_discovery_job(db_tenant_a, "tenant-a", "aws", "key-1")
        id2 = start_discovery_job(db_tenant_a, "tenant-a", "aws", "key-1")
        assert id1 != id2

    def test_works_without_regions(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        job_id = start_discovery_job(db_tenant_a, "tenant-a", "gcp", "gcp-key")
        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert doc["regions"] == []

    def test_does_not_raise_when_collection_missing(self, db_tenant_a) -> None:
        """No init_tenant_schema — collection does not exist. Must not raise."""
        job_id = start_discovery_job(db_tenant_a, "tenant-a", "aws", "key")
        assert isinstance(job_id, str)
        assert len(job_id) == 36  # UUID4


@pytest.mark.integration
class TestCompleteDiscoveryJob:
    """complete_discovery_job transitions status to completed."""

    def test_marks_job_completed(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        job_id = start_discovery_job(db_tenant_a, "tenant-a", "azure", "az-key")

        complete_discovery_job(db_tenant_a, job_id, resources_discovered=42)

        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert doc["status"] == "completed"
        assert doc["checks_total"] == 42
        assert doc["checks_completed"] == 42
        assert "completed_at" in doc

    def test_does_not_raise_when_collection_missing(self, db_tenant_a) -> None:
        complete_discovery_job(db_tenant_a, "nonexistent-job-id", resources_discovered=0)

    def test_does_not_raise_for_unknown_job_id(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        complete_discovery_job(db_tenant_a, "does-not-exist", resources_discovered=5)


@pytest.mark.integration
class TestFailDiscoveryJob:
    """fail_discovery_job transitions status to failed with error message."""

    def test_marks_job_failed(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        job_id = start_discovery_job(db_tenant_a, "tenant-a", "k8s", "k8s-key")

        fail_discovery_job(db_tenant_a, job_id, "connection refused")

        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert doc["status"] == "failed"
        assert doc["error_message"] == "connection refused"
        assert "completed_at" in doc

    def test_truncates_long_error_message(self, db_tenant_a) -> None:
        init_tenant_schema(db_tenant_a)
        job_id = start_discovery_job(db_tenant_a, "tenant-a", "gcp", "key")
        long_msg = "x" * 5000

        fail_discovery_job(db_tenant_a, job_id, long_msg)

        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert len(doc["error_message"]) <= 2000

    def test_does_not_raise_when_collection_missing(self, db_tenant_a) -> None:
        fail_discovery_job(db_tenant_a, "nonexistent-job-id", "error")


@pytest.mark.integration
class TestDiscoveryJobLifecycle:
    """End-to-end state transitions within a single test."""

    def test_full_success_lifecycle(self, db_tenant_a) -> None:
        """running → completed with correct field values throughout."""
        init_tenant_schema(db_tenant_a)
        job_id = start_discovery_job(db_tenant_a, "t1", "aws", "key-123", ["eu-west-1"])

        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert doc["status"] == "running"
        assert doc["completed_at"] is None or "completed_at" not in doc

        complete_discovery_job(db_tenant_a, job_id, 7)
        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert doc["status"] == "completed"
        assert doc["checks_total"] == 7

    def test_full_failure_lifecycle(self, db_tenant_a) -> None:
        """running → failed preserves error message."""
        init_tenant_schema(db_tenant_a)
        job_id = start_discovery_job(db_tenant_a, "t1", "azure", "az-key")

        fail_discovery_job(db_tenant_a, job_id, "SomeException: timeout after 30s")
        doc = db_tenant_a.collection("scan_jobs").get(job_id)
        assert doc["status"] == "failed"
        assert "timeout" in doc["error_message"]
