"""Unit tests for Finding and ScanJob Pydantic models."""

import pytest

from app.models.finding import Finding, FindingStatus, ScanJob, ScanJobStatus, SeverityLevel


@pytest.mark.unit
class TestFindingModel:
    def _make_finding(self, **overrides):
        defaults = {
            "finding_id": "f-001",
            "tenant_id": "tenant-a",
            "check_id": "iam_root_mfa_enabled",
            "title": "Root MFA not enabled",
            "description": "The root account has no MFA device configured.",
            "resource_id": "arn:aws:iam::111111111111:root",
            "resource_type": "iam_user",
            "severity": SeverityLevel.CRITICAL,
            "status": FindingStatus.FAIL,
            "provider": "aws",
            "account_id": "111111111111",
        }
        defaults.update(overrides)
        return Finding(**defaults)

    def test_finding_creation_defaults(self):
        f = self._make_finding()
        assert f.finding_id == "f-001"
        assert f.severity == SeverityLevel.CRITICAL
        assert f.status == FindingStatus.FAIL
        assert f.framework_mapping == []
        assert f.source == "cspm"

    def test_severity_values(self):
        for severity in SeverityLevel:
            f = self._make_finding(severity=severity)
            assert f.severity == severity

    def test_finding_status_pass_serializes_correctly(self):
        f = self._make_finding(status=FindingStatus.PASS_)
        doc = f.to_arango_doc()
        assert doc["status"] == "PASS"

    def test_finding_status_fail_serializes_correctly(self):
        f = self._make_finding(status=FindingStatus.FAIL)
        doc = f.to_arango_doc()
        assert doc["status"] == "FAIL"

    def test_arango_key_uniqueness(self):
        f1 = self._make_finding(check_id="check_a", resource_id="res-1", tenant_id="t1")
        f2 = self._make_finding(check_id="check_b", resource_id="res-1", tenant_id="t1")
        f3 = self._make_finding(check_id="check_a", resource_id="res-1", tenant_id="t2")
        assert f1.arango_key() != f2.arango_key()
        assert f1.arango_key() != f3.arango_key()

    def test_arango_key_no_slashes(self):
        f = self._make_finding(
            check_id="iam_root_mfa_enabled",
            resource_id="arn:aws:iam::111111111111:root",
            tenant_id="tenant-a",
        )
        key = f.arango_key()
        assert "/" not in key
        assert ":" not in key

    def test_to_arango_doc_has_key(self):
        f = self._make_finding()
        doc = f.to_arango_doc()
        assert "_key" in doc
        assert doc["_key"] == f.arango_key()

    def test_to_arango_update_fields(self):
        f = self._make_finding(framework_mapping=["CIS-2.0/1.1"])
        update = f.to_arango_update()
        assert "status" in update
        assert "severity" in update
        assert "framework_mapping" in update
        assert update["framework_mapping"] == ["CIS-2.0/1.1"]


@pytest.mark.unit
class TestScanJobModel:
    def _make_job(self, **overrides):
        defaults = {
            "job_id": "job-001",
            "tenant_id": "tenant-a",
            "provider_id": "aws-111111111111",
            "provider": "aws",
            "frameworks": ["CIS-AWS-2.0"],
        }
        defaults.update(overrides)
        return ScanJob(**defaults)

    def test_scan_job_creation_defaults(self):
        job = self._make_job()
        assert job.status == ScanJobStatus.QUEUED
        assert job.checks_total == 0
        assert job.findings_found == 0
        assert job.findings_fail == 0
        assert job.regions == []

    def test_to_arango_doc_key_is_job_id(self):
        job = self._make_job()
        doc = job.to_arango_doc()
        assert doc["_key"] == "job-001"

    def test_completed_job_fields(self):
        from datetime import UTC, datetime

        job = self._make_job(
            status=ScanJobStatus.COMPLETED,
            findings_found=10,
            findings_fail=3,
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
        )
        assert job.findings_found == 10
        assert job.findings_fail == 3
        assert job.status == ScanJobStatus.COMPLETED

    def test_failed_job_has_error_message(self):
        job = self._make_job(status=ScanJobStatus.FAILED, error_message="AWS credentials expired")
        assert job.error_message == "AWS credentials expired"
        assert job.status == ScanJobStatus.FAILED
