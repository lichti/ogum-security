"""
Integration tests for CSPM scan Celery task.

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
- ProwlerService: mocked entirely — Prowler never calls real cloud APIs in CI
- Celery: task.apply() runs synchronously — no broker required
"""

from unittest.mock import MagicMock

import pytest

from app.db.init import init_tenant_schema
from app.models.finding import FindingStatus, SeverityLevel
from app.workers.tasks.cspm_scan import run_cspm_scan

TEST_TENANT = "test-tenant-aaa"
PROVIDER_ID = "aws-111111111111"
ACCOUNT_ID = "111111111111"
FRAMEWORKS = ["CIS-AWS-2.0"]

_TASK_KWARGS = {
    "tenant_id": TEST_TENANT,
    "provider_id": PROVIDER_ID,
    "provider": "aws",
    "frameworks": FRAMEWORKS,
    "credentials": {"aws_access_key_id": None, "aws_secret_access_key": None},
    "account_id": ACCOUNT_ID,
    "regions": ["us-east-1"],
}


def _make_mock_finding(
    check_id: str = "iam_root_mfa_enabled",
    resource_id: str = "arn:aws:iam::111111111111:root",
    status=FindingStatus.FAIL,
):
    from app.models.finding import Finding, FindingSource

    return Finding(
        finding_id=f"test-{check_id}",
        tenant_id=TEST_TENANT,
        check_id=check_id,
        title=f"Test {check_id}",
        description="Test description",
        resource_id=resource_id,
        resource_type="iam_user",
        severity=SeverityLevel.CRITICAL,
        status=status,
        provider="aws",
        account_id=ACCOUNT_ID,
        source=FindingSource.CSPM,
    )


@pytest.mark.integration
class TestCSPMScanTask:
    def test_scan_creates_scan_job_and_findings(self, db_tenant_a, mocker):
        """Happy path: ProwlerService returns 2 findings, both are persisted."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        findings = [
            _make_mock_finding("iam_root_mfa_enabled"),
            _make_mock_finding("s3_bucket_public_read", "my-bucket", FindingStatus.PASS_),
        ]
        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = findings
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert result["provider"] == "aws"
        assert result["findings_found"] == 2
        assert result["findings_fail"] == 1
        assert "job_id" in result

        jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
        assert len(jobs) == 1
        job = jobs[0]
        assert job["status"] == "completed"
        assert job["tenant_id"] == TEST_TENANT
        assert job["findings_found"] == 2

        stored_findings = list(db_tenant_a.aql.execute("FOR f IN findings RETURN f"))
        assert len(stored_findings) == 2

    def test_scan_job_created_before_findings_persisted(self, db_tenant_a, mocker):
        """scan_job document must exist before ProwlerService runs (status: running)."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        captured_status = {}

        def check_job_exists(*args, **kwargs):
            jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
            if jobs:
                captured_status["status"] = jobs[0]["status"]
            return []

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.side_effect = check_job_exists
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        assert captured_status.get("status") == "running"

    def test_scan_with_zero_findings(self, db_tenant_a, mocker):
        """Empty findings list must result in completed job with 0 findings."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = []
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert result["findings_found"] == 0
        assert result["findings_fail"] == 0
        jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
        assert jobs[0]["status"] == "completed"

    def test_finding_upsert_is_idempotent(self, db_tenant_a, mocker):
        """Running the same scan twice must not duplicate findings."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        findings = [_make_mock_finding("iam_root_mfa_enabled")]
        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = findings
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        stored = list(db_tenant_a.aql.execute("FOR f IN findings RETURN f"))
        assert len(stored) == 1

    def test_unsupported_provider_produces_empty_findings(self, db_tenant_a, mocker):
        """GCP provider (not yet implemented) must create a completed job with 0 findings."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "gcp"}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["findings_found"] == 0
        mock_prowler.run_aws_scan.assert_not_called()
