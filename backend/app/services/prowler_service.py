"""
Prowler v5 scan service.

Wraps the prowler-core programmatic API. In tests, ProwlerService is mocked
entirely — Prowler never runs against real cloud APIs in CI.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from app.models.finding import Finding, FindingSource, FindingStatus, SeverityLevel

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "informational": SeverityLevel.INFORMATIONAL,
    "info": SeverityLevel.INFORMATIONAL,
}

_STATUS_MAP: dict[str, FindingStatus] = {
    "FAIL": FindingStatus.FAIL,
    "PASS": FindingStatus.PASS_,
    "MANUAL": FindingStatus.PASS_,
}


class ProwlerService:
    """Run Prowler v5 checks and return normalized Finding objects."""

    def run_aws_scan(
        self,
        *,
        tenant_id: str,
        account_id: str,
        role_arn: str | None = None,
        external_id: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        regions: list[str] | None = None,
        frameworks: list[str],
        scan_job_id: str,
    ) -> list[Finding]:
        """
        Execute Prowler v5 checks against an AWS account.

        Credentials are ephemeral — never persisted beyond this call.
        Returns Finding objects ready for ArangoDB upsert.
        """
        try:
            from prowler.lib.check.check import execute, recover_checks_from_provider  # noqa: PLC0415
            from prowler.providers.aws.aws_provider import AwsProvider  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("prowler-core is not installed") from exc

        audit_config: dict[str, Any] = {
            "session_duration": 3600,
            "scan_unused_services": False,
        }
        if role_arn:
            audit_config["role"] = role_arn
        if external_id:
            audit_config["external_id"] = external_id
        if regions:
            audit_config["scan_regions"] = regions

        if aws_access_key_id and aws_secret_access_key:
            import boto3  # noqa: PLC0415

            boto3.setup_default_session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=(regions[0] if regions else "us-east-1"),
            )

        provider = AwsProvider(audit_config=audit_config)

        check_ids: set[str] = set()
        for framework in frameworks:
            try:
                checks = recover_checks_from_provider("aws", framework)
                check_ids.update(checks.keys())
            except Exception:
                logger.warning("Framework %s not recognized by Prowler — skipping", framework)

        if not check_ids:
            logger.warning("No checks found for frameworks=%s", frameworks)
            return []

        findings: list[Finding] = []
        for check_id in check_ids:
            try:
                results = execute(check_id, provider)
                for result in results:
                    finding = self._normalize_aws_result(
                        result=result,
                        tenant_id=tenant_id,
                        account_id=account_id,
                        scan_job_id=scan_job_id,
                    )
                    if finding is not None:
                        findings.append(finding)
            except Exception:
                logger.exception("Check %s failed — skipping", check_id)

        return findings

    def _normalize_aws_result(
        self,
        result: Any,
        tenant_id: str,
        account_id: str,
        scan_job_id: str,
    ) -> Finding | None:
        """Convert a Prowler CheckReport to a Finding model."""
        try:
            metadata = getattr(result, "check_metadata", None)

            severity_str = "medium"
            if metadata:
                severity_str = str(getattr(metadata, "Severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

            status_str = str(getattr(result, "status", "FAIL")).upper()
            status = _STATUS_MAP.get(status_str, FindingStatus.FAIL)

            check_id = str(getattr(result, "check_id", "unknown"))
            resource_id = str(getattr(result, "resource_id", ""))
            resource_arn = str(getattr(result, "resource_arn", "")) or None
            region = str(getattr(result, "region", "")) or None

            title = check_id
            description = ""
            remediation_text: str | None = None
            remediation_code: str | None = None
            framework_mapping: list[str] = []

            if metadata:
                title = str(getattr(metadata, "CheckTitle", check_id))
                description = str(getattr(metadata, "Description", ""))
                remediation = getattr(metadata, "Remediation", None)
                if remediation:
                    rec = getattr(remediation, "Recommendation", None)
                    if rec:
                        remediation_text = str(getattr(rec, "Text", "")) or None
                    code = getattr(remediation, "Code", None)
                    if code:
                        remediation_code = str(getattr(code, "CLI", "")) or None

                compliance = getattr(metadata, "Compliance", []) or []
                for fw in compliance:
                    fw_name = str(getattr(fw, "Framework", ""))
                    fw_version = str(getattr(fw, "Version", ""))
                    for req in getattr(fw, "Requirements", []) or []:
                        req_id = str(getattr(req, "Id", ""))
                        if fw_name and req_id:
                            framework_mapping.append(f"{fw_name}-{fw_version}/{req_id}")

            return Finding(
                finding_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                check_id=check_id,
                title=title,
                description=description,
                resource_id=resource_id,
                resource_arn=resource_arn,
                resource_type=str(getattr(result, "resource_type", "unknown")),
                severity=severity,
                status=status,
                provider="aws",
                region=region,
                account_id=account_id,
                framework_mapping=framework_mapping,
                remediation=remediation_text,
                remediation_code=remediation_code,
                source=FindingSource.CSPM,
                scan_job_id=scan_job_id,
                raw_output={"status_extended": str(getattr(result, "status_extended", ""))},
            )
        except Exception:
            logger.exception("Failed to normalize Prowler result — skipping")
            return None
