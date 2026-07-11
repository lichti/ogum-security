"""Unit tests for ProwlerService._normalize — status/severity mapping from raw
prowler-core OutputFinding objects into our Finding model.

Uses the real prowler.lib.outputs.common.Status enum (not a mock/stub) because
the regression this guards against is specific to how that enum stringifies —
a fake status string would not have caught it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from prowler.lib.outputs.common import Status

from app.models.finding import FindingStatus, SeverityLevel
from app.services.prowler_service import ProwlerService


def _make_result(status: Status, severity: str = "high") -> SimpleNamespace:
    return SimpleNamespace(
        status=status,
        status_extended="some status detail",
        metadata=SimpleNamespace(
            CheckID="s3_bucket_public_access",
            CheckTitle="S3 bucket is not publicly accessible",
            Description="Checks whether S3 buckets are publicly accessible",
            ResourceType="AwsS3Bucket",
            Severity=severity,
            Remediation=None,
        ),
        resource_uid="arn:aws:s3:::my-bucket",
        resource_name="my-bucket",
        region="us-east-1",
        account_uid="111111111111",
        compliance={},
    )


@pytest.mark.unit
class TestNormalizeStatus:
    """Regression coverage for the Status(str, Enum) stringification bug.

    prowler.lib.outputs.common.Status subclasses (str, Enum) but does not
    override __str__, so str(Status.PASS) == "Status.PASS" — not "PASS". That
    string never matched the old `_STATUS_MAP.get(status_str, FAIL)` lookup,
    so every result (PASS, FAIL, and MANUAL alike) silently fell through to
    the FAIL default.
    """

    def test_pass_status_is_not_misclassified_as_fail(self):
        service = ProwlerService()
        finding = service._normalize(
            result=_make_result(Status.PASS),
            cloud_provider="aws",
            tenant_id="tenant-a",
            account_id="111111111111",
            scan_job_id="job-1",
        )
        assert finding is not None
        assert finding.status == FindingStatus.PASS_

    def test_fail_status_is_still_fail(self):
        service = ProwlerService()
        finding = service._normalize(
            result=_make_result(Status.FAIL),
            cloud_provider="aws",
            tenant_id="tenant-a",
            account_id="111111111111",
            scan_job_id="job-1",
        )
        assert finding is not None
        assert finding.status == FindingStatus.FAIL

    def test_manual_status_maps_to_pass(self):
        service = ProwlerService()
        finding = service._normalize(
            result=_make_result(Status.MANUAL),
            cloud_provider="aws",
            tenant_id="tenant-a",
            account_id="111111111111",
            scan_job_id="job-1",
        )
        assert finding is not None
        assert finding.status == FindingStatus.PASS_

    def test_missing_status_attribute_defaults_to_fail(self):
        service = ProwlerService()
        result = _make_result(Status.PASS)
        del result.status
        finding = service._normalize(
            result=result,
            cloud_provider="aws",
            tenant_id="tenant-a",
            account_id="111111111111",
            scan_job_id="job-1",
        )
        assert finding is not None
        assert finding.status == FindingStatus.FAIL

    def test_severity_mapped_correctly_alongside_status(self):
        service = ProwlerService()
        finding = service._normalize(
            result=_make_result(Status.PASS, severity="critical"),
            cloud_provider="aws",
            tenant_id="tenant-a",
            account_id="111111111111",
            scan_job_id="job-1",
        )
        assert finding is not None
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.status == FindingStatus.PASS_
