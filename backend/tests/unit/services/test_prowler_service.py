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


@pytest.mark.unit
class TestRunScanFrameworksOptional:
    """frameworks=None must run prowler's full check catalog (no compliances=
    filter passed to Scan()) instead of the old hard requirement to resolve at
    least one recognized framework slug."""

    def test_no_frameworks_does_not_pass_compliances_filter(self, mocker):
        mock_scan_cls = mocker.patch("prowler.lib.scan.scan.Scan")
        mock_scan_cls.return_value.scan.return_value = iter([])

        service = ProwlerService()
        service._run_scan(
            provider=mocker.MagicMock(),
            compliance_slugs=None,
            cloud_provider="aws",
            tenant_id="t1",
            account_id="123",
            scan_job_id="job-1",
        )

        mock_scan_cls.assert_called_once()
        _args, kwargs = mock_scan_cls.call_args
        assert "compliances" not in kwargs

    def test_explicit_frameworks_still_passes_compliances_filter(self, mocker):
        mock_scan_cls = mocker.patch("prowler.lib.scan.scan.Scan")
        mock_scan_cls.return_value.scan.return_value = iter([])

        service = ProwlerService()
        service._run_scan(
            provider=mocker.MagicMock(),
            compliance_slugs=["cis_2.0_aws"],
            cloud_provider="aws",
            tenant_id="t1",
            account_id="123",
            scan_job_id="job-1",
        )

        mock_scan_cls.assert_called_once()
        _args, kwargs = mock_scan_cls.call_args
        assert kwargs.get("compliances") == ["cis_2.0_aws"]


@pytest.mark.unit
class TestEnrichLambdaExecutionRoles:
    """prowler's Function model has no execution-role field at all — this
    supplementary lambda:list_functions call is the only source for it."""

    def _lambda_result(self, arn: str) -> SimpleNamespace:
        return SimpleNamespace(
            metadata=SimpleNamespace(ResourceType="AwsLambdaFunction"),
            resource_uid=arn,
            resource_metadata={"name": "my-fn"},
        )

    def test_fills_execution_role_arn_on_matching_result(self, mocker):
        arn = "arn:aws:lambda:us-east-1:123:function:my-fn"
        result = self._lambda_result(arn)

        client = mocker.MagicMock()
        client.get_paginator.return_value.paginate.return_value = [
            {"Functions": [{"FunctionArn": arn, "Role": "arn:aws:iam::123:role/lambda-exec"}]}
        ]
        provider = mocker.MagicMock()
        provider.generate_regional_clients.return_value = {"us-east-1": client}

        service = ProwlerService()
        service._enrich_lambda_execution_roles(provider, [result])

        assert result.resource_metadata["execution_role_arn"] == "arn:aws:iam::123:role/lambda-exec"

    def test_no_lambda_results_skips_client_creation(self, mocker):
        provider = mocker.MagicMock()
        service = ProwlerService()

        non_lambda = SimpleNamespace(metadata=SimpleNamespace(ResourceType="AwsS3Bucket"))
        service._enrich_lambda_execution_roles(provider, [non_lambda])

        provider.generate_regional_clients.assert_not_called()

    def test_client_creation_failure_does_not_raise(self, mocker):
        result = self._lambda_result("arn:aws:lambda:us-east-1:123:function:my-fn")
        provider = mocker.MagicMock()
        provider.generate_regional_clients.side_effect = RuntimeError("no credentials")

        service = ProwlerService()
        service._enrich_lambda_execution_roles(provider, [result])  # must not raise

        assert "execution_role_arn" not in result.resource_metadata

    def test_unmatched_function_arn_leaves_metadata_untouched(self, mocker):
        result = self._lambda_result("arn:aws:lambda:us-east-1:123:function:my-fn")

        client = mocker.MagicMock()
        client.get_paginator.return_value.paginate.return_value = [
            {
                "Functions": [
                    {
                        "FunctionArn": "arn:aws:lambda:us-east-1:123:function:other-fn",
                        "Role": "arn:aws:iam::123:role/other",
                    }
                ]
            }
        ]
        provider = mocker.MagicMock()
        provider.generate_regional_clients.return_value = {"us-east-1": client}

        service = ProwlerService()
        service._enrich_lambda_execution_roles(provider, [result])

        assert "execution_role_arn" not in result.resource_metadata
