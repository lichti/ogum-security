"""Checkov IaC scanning service — programmatic wrapper for Terraform, CFN, K8s."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.models.finding import Finding, FindingSource, FindingStatus, SeverityLevel

logger = logging.getLogger(__name__)

_SEV_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "INFO": SeverityLevel.INFORMATIONAL,
    "INFORMATIONAL": SeverityLevel.INFORMATIONAL,
}


def _map_severity(raw: Any) -> SeverityLevel:
    if raw is None:
        return SeverityLevel.MEDIUM
    return _SEV_MAP.get(str(raw).upper(), SeverityLevel.MEDIUM)


def _provider_from_resource(resource_id: str) -> str:
    r = resource_id.lower()
    if r.startswith("aws_"):
        return "aws"
    if r.startswith("azurerm_") or r.startswith("azure_"):
        return "azure"
    if r.startswith("google_"):
        return "gcp"
    return "iac"


def _resource_type(resource_id: str) -> str:
    """Extract resource type from Checkov resource id.

    e.g. "aws_s3_bucket.my_bucket" → "aws_s3_bucket"
    """
    return resource_id.split(".")[0] if "." in resource_id else resource_id


def _normalize_check(
    check: Any,
    status: FindingStatus,
    tenant_id: str,
    account_id: str,
    scan_job_id: str | None,
) -> Finding | None:
    try:
        resource_id = str(getattr(check, "resource", "") or "")
        check_obj = check.check if hasattr(check, "check") else check
        framework_mapping = list(getattr(check_obj, "bc_check_mappings", {}).keys())
        return Finding(
            finding_id=f"{check.check_id}_{resource_id}_{tenant_id}",
            tenant_id=tenant_id,
            check_id=check.check_id,
            title=getattr(check_obj, "name", check.check_id),
            description=getattr(check_obj, "guideline", None) or getattr(check_obj, "name", check.check_id),
            resource_id=resource_id or check.check_id,
            resource_type=_resource_type(resource_id) if resource_id else "unknown",
            severity=_map_severity(getattr(check, "severity", None)),
            status=status,
            provider=_provider_from_resource(resource_id),
            account_id=account_id,
            framework_mapping=framework_mapping,
            remediation=getattr(check_obj, "guideline", None),
            source=FindingSource.IAC,
            scan_job_id=scan_job_id,
            raw_output={
                "file_path": getattr(check, "file_path", None),
                "file_line_range": getattr(check, "file_line_range", None),
                "runner": type(check_obj).__name__,
            },
        )
    except Exception:
        logger.exception("Failed to normalize Checkov check %s", getattr(check, "check_id", "?"))
        return None


class CheckovService:
    """Run Checkov IaC checks against a directory and return normalized findings."""

    def run_scan(
        self,
        directory: Path,
        tenant_id: str,
        account_id: str = "iac",
        scan_job_id: str | None = None,
    ) -> list[Finding]:
        try:
            from checkov.cloudformation.runner import Runner as CFNRunner
            from checkov.kubernetes.runner import Runner as K8sRunner
            from checkov.runner_helper import RunnerFilter
            from checkov.terraform.runner import Runner as TFRunner
        except ImportError:
            logger.error("checkov package not available; IaC scan skipped")
            return []

        runners: list[Any] = [TFRunner(), CFNRunner(), K8sRunner()]
        findings: list[Finding] = []

        for runner in runners:
            try:
                report = runner.run(root_folder=str(directory), runner_filter=RunnerFilter())
            except Exception:
                logger.exception("Checkov %s runner failed on %s", type(runner).__name__, directory)
                continue

            for check in report.failed_checks:
                f = _normalize_check(check, FindingStatus.FAIL, tenant_id, account_id, scan_job_id)
                if f:
                    findings.append(f)
            for check in report.passed_checks:
                f = _normalize_check(check, FindingStatus.PASS_, tenant_id, account_id, scan_job_id)
                if f:
                    findings.append(f)

        logger.info(
            "Checkov scan on %s: %d findings (%d FAIL)",
            directory,
            len(findings),
            sum(1 for f in findings if f.status == FindingStatus.FAIL),
        )
        return findings
