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
from app.services.prowler_service import ScanResult
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


def _scan_result(findings):
    """Wrap findings in a ScanResult (raw_outputs empty — inventory extraction skipped)."""
    return ScanResult(findings=findings, raw_outputs=[])


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
        mock_prowler.run_aws_scan.return_value = _scan_result(findings)
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
            return _scan_result([])

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
        mock_prowler.run_aws_scan.return_value = _scan_result([])
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
        mock_prowler.run_aws_scan.return_value = _scan_result(findings)
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        stored = list(db_tenant_a.aql.execute("FOR f IN findings RETURN f"))
        assert len(stored) == 1

    def test_unsupported_provider_produces_empty_findings(self, db_tenant_a, mocker):
        """GCP scan returns empty ScanResult when credentials are not provided."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_gcp_scan.return_value = _scan_result([])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "gcp"}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["findings_found"] == 0
        mock_prowler.run_aws_scan.assert_not_called()

    def test_azure_scan_dispatch(self, db_tenant_a, mocker):
        """Azure provider routes to run_azure_scan (not run_aws_scan)."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_azure_scan.return_value = _scan_result([])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "azure", "frameworks": ["CIS-AZURE-2.0"]}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["provider"] == "azure"
        assert result["findings_found"] == 0
        mock_prowler.run_azure_scan.assert_called_once()
        mock_prowler.run_aws_scan.assert_not_called()

    def test_k8s_scan_dispatch(self, db_tenant_a, mocker):
        """Kubernetes provider routes to run_kubernetes_scan."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_kubernetes_scan.return_value = _scan_result([])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "k8s", "frameworks": ["CIS-K8S-1.12"]}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["provider"] == "k8s"
        assert result["findings_found"] == 0
        mock_prowler.run_kubernetes_scan.assert_called_once()
        mock_prowler.run_aws_scan.assert_not_called()

    def test_unknown_provider_falls_back_to_empty(self, db_tenant_a, mocker):
        """Unrecognized provider returns completed job with zero findings."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "oracle"}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["findings_found"] == 0
        jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
        assert jobs[0]["status"] == "completed"

    def test_inventory_extracted_from_raw_outputs(self, db_tenant_a, mocker):
        """Inventory extraction runs when scan produces raw OutputFinding objects."""
        from types import SimpleNamespace

        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        # EC2 instance routes to "resources" collection (not data_assets like S3)
        resource_uid = "arn:aws:ec2:us-east-1:111111111111:instance/i-abc123"
        meta = SimpleNamespace(
            CheckID="ec2_instance_imdsv2_enabled",
            CheckTitle="EC2 IMDSv2 Enabled",
            Description="desc",
            Severity="high",
            ResourceType="aws_ec2_instance",
            Remediation=None,
        )
        raw_output = SimpleNamespace(
            status="FAIL",
            status_extended="IMDSv2 not enabled",
            resource_uid=resource_uid,
            resource_name="my-ec2",
            region="us-east-1",
            account_uid=ACCOUNT_ID,
            metadata=meta,
            compliance={},
            resource_metadata={},
        )

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[_make_mock_finding("ec2_instance_imdsv2_enabled", resource_uid)],
            raw_outputs=[raw_output],
        )
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert result["findings_found"] == 1
        assert result["inventory_upserted"] >= 1

        resources = list(db_tenant_a.aql.execute("FOR r IN resources RETURN r"))
        assert len(resources) >= 1
        assert resources[0]["resource_id"] == resource_uid
