"""Unit tests for CheckovService normalization logic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.models.finding import FindingSource, FindingStatus, SeverityLevel
from app.services.checkov_service import (
    CheckovService,
    _map_severity,
    _provider_from_resource,
    _resource_type,
)


@pytest.mark.unit
class TestHelpers:
    def test_map_severity_critical(self):
        assert _map_severity("CRITICAL") == SeverityLevel.CRITICAL

    def test_map_severity_high(self):
        assert _map_severity("HIGH") == SeverityLevel.HIGH

    def test_map_severity_info(self):
        assert _map_severity("INFO") == SeverityLevel.INFORMATIONAL

    def test_map_severity_none_defaults_medium(self):
        assert _map_severity(None) == SeverityLevel.MEDIUM

    def test_map_severity_unknown_defaults_medium(self):
        assert _map_severity("UNKNOWN_LEVEL") == SeverityLevel.MEDIUM

    def test_provider_from_resource_aws(self):
        assert _provider_from_resource("aws_s3_bucket.my_bucket") == "aws"

    def test_provider_from_resource_azure(self):
        assert _provider_from_resource("azurerm_storage_account.sa") == "azure"

    def test_provider_from_resource_gcp(self):
        assert _provider_from_resource("google_storage_bucket.bucket") == "gcp"

    def test_provider_from_resource_unknown(self):
        assert _provider_from_resource("kubernetes_deployment.app") == "iac"

    def test_resource_type_extracts_prefix(self):
        assert _resource_type("aws_s3_bucket.my_bucket") == "aws_s3_bucket"

    def test_resource_type_no_dot(self):
        assert _resource_type("aws_s3_bucket") == "aws_s3_bucket"


@pytest.mark.unit
class TestCheckovService:
    def _make_check(self, check_id="CKV_AWS_1", name="Test", resource="aws_s3_bucket.b", severity="HIGH"):
        check_obj = MagicMock()
        check_obj.check_id = check_id
        check_obj.name = name
        check_obj.guideline = "https://example.com/guide"
        check_obj.bc_check_mappings = {"CIS-AWS-2.0": "1.1"}

        result = MagicMock()
        result.check_id = check_id
        result.check = check_obj
        result.resource = resource
        result.file_path = "main.tf"
        result.file_line_range = [1, 5]
        result.severity = severity
        return result

    def _make_runner(self, failed=None, passed=None):
        report = MagicMock()
        report.failed_checks = failed or []
        report.passed_checks = passed or []

        runner = MagicMock()
        runner.run.return_value = report
        return runner

    def test_run_scan_returns_fail_finding(self, tmp_path):
        service = CheckovService()
        failed_check = self._make_check(check_id="CKV_AWS_1")
        tf_runner = self._make_runner(failed=[failed_check])

        with patch("app.services.checkov_service.CheckovService.run_scan") as mock_run:
            mock_run.return_value = [service.__class__.__new__(service.__class__)]

        # Direct test via mocking the imports
        with patch.dict(
            "sys.modules",
            {
                "checkov.terraform.runner": MagicMock(Runner=lambda: tf_runner),
                "checkov.cloudformation.runner": MagicMock(Runner=lambda: self._make_runner()),
                "checkov.kubernetes.runner": MagicMock(Runner=lambda: self._make_runner()),
                "checkov.runner_helper": MagicMock(RunnerFilter=MagicMock),
            },
        ):
            findings = service.run_scan(tmp_path, "tenant-test", account_id="123456789012")

        assert len(findings) == 1
        f = findings[0]
        assert f.status == FindingStatus.FAIL
        assert f.severity == SeverityLevel.HIGH
        assert f.source == FindingSource.IAC
        assert f.provider == "aws"
        assert f.check_id == "CKV_AWS_1"
        assert "framework_mapping" in f.model_dump()

    def test_run_scan_returns_pass_finding(self, tmp_path):
        service = CheckovService()
        passed_check = self._make_check(check_id="CKV_AWS_2")
        tf_runner = self._make_runner(passed=[passed_check])

        with patch.dict(
            "sys.modules",
            {
                "checkov.terraform.runner": MagicMock(Runner=lambda: tf_runner),
                "checkov.cloudformation.runner": MagicMock(Runner=lambda: self._make_runner()),
                "checkov.kubernetes.runner": MagicMock(Runner=lambda: self._make_runner()),
                "checkov.runner_helper": MagicMock(RunnerFilter=MagicMock),
            },
        ):
            findings = service.run_scan(tmp_path, "tenant-test", account_id="123456789012")

        assert len(findings) == 1
        assert findings[0].status == FindingStatus.PASS_

    def test_run_scan_handles_import_error(self, tmp_path):
        service = CheckovService()
        with patch.dict("sys.modules", {"checkov": None, "checkov.terraform": None, "checkov.terraform.runner": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                findings = service.run_scan(tmp_path, "tenant-test")
        assert findings == []

    def test_run_scan_handles_runner_exception(self, tmp_path):
        service = CheckovService()
        broken_runner = MagicMock()
        broken_runner.run.side_effect = Exception("broken")

        with patch.dict(
            "sys.modules",
            {
                "checkov.terraform.runner": MagicMock(Runner=lambda: broken_runner),
                "checkov.cloudformation.runner": MagicMock(Runner=lambda: self._make_runner()),
                "checkov.kubernetes.runner": MagicMock(Runner=lambda: self._make_runner()),
                "checkov.runner_helper": MagicMock(RunnerFilter=MagicMock),
            },
        ):
            findings = service.run_scan(tmp_path, "tenant-test")

        # Other runners still produce 0 findings (all are empty mocks)
        assert isinstance(findings, list)
