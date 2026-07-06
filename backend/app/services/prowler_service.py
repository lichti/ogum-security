"""
Prowler v5 scan service.

Wraps the prowler-core programmatic API. In tests, ProwlerService is mocked
entirely — Prowler never runs against real cloud APIs in CI.

Prowler v5 API summary:
  - AwsProvider(**kwargs) — flat keyword args, no audit_config dict
  - Scan(provider, compliances=[...]) — high-level scanner
  - scan() — generator yielding (progress_float, [OutputFinding])
  - OutputFinding fields: status, status_extended, region, resource_uid,
    resource_name, resource_metadata, compliance, metadata, uid, raw, ...
  - Framework names use filesystem slugs: cis_2.0_aws, pci_4.0_aws, soc2_aws
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from app.models.finding import Finding, FindingSource, FindingStatus, SeverityLevel

logger = logging.getLogger(__name__)

# Map our public framework IDs to prowler's compliance file slugs
_FRAMEWORK_MAP: dict[str, str] = {
    "CIS-AWS-2.0": "cis_2.0_aws",
    "CIS-AWS-3.0": "cis_3.0_aws",
    "PCI_DSS_v4": "pci_4.0_aws",
    "PCI_DSS_3.2.1": "pci_3.2.1_aws",
    "SOC2": "soc2_aws",
    "HIPAA": "hipaa_aws",
    "NIST-800-53": "nist_800_53_revision_5_aws",
    "ISO27001": "iso27001_2022_aws",
    "GDPR": "gdpr_aws",
}

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
            from prowler.lib.scan.scan import Scan  # noqa: PLC0415
            from prowler.providers.aws.aws_provider import AwsProvider  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("prowler-core is not installed") from exc

        # Resolve framework slugs — skip any not in our map (with a warning)
        compliance_slugs: list[str] = []
        for fw in frameworks:
            slug = _FRAMEWORK_MAP.get(fw)
            if slug:
                compliance_slugs.append(slug)
            else:
                logger.warning("Framework %s not mapped to a prowler compliance slug — skipping", fw)

        if not compliance_slugs:
            logger.warning("No recognized frameworks for %s — aborting scan", frameworks)
            return []

        # Build AwsProvider with flat kwargs (prowler v5 removed audit_config dict)
        provider_kwargs: dict[str, Any] = {
            "session_duration": 3600,
            "scan_unused_services": False,
        }
        if role_arn:
            provider_kwargs["role_arn"] = role_arn
        if external_id:
            provider_kwargs["external_id"] = external_id
        if regions:
            provider_kwargs["regions"] = set(regions)
        if aws_access_key_id:
            provider_kwargs["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key:
            provider_kwargs["aws_secret_access_key"] = aws_secret_access_key

        provider = AwsProvider(**provider_kwargs)
        scan = Scan(provider, compliances=compliance_slugs)

        findings: list[Finding] = []
        for _progress, batch in scan.scan():
            for result in batch:
                finding = self._normalize(
                    result=result,
                    tenant_id=tenant_id,
                    account_id=account_id,
                    scan_job_id=scan_job_id,
                )
                if finding is not None:
                    findings.append(finding)

        return findings

    def _normalize(
        self,
        result: Any,
        tenant_id: str,
        account_id: str,
        scan_job_id: str,
    ) -> Finding | None:
        """Convert a Prowler v5 OutputFinding to our Finding model."""
        try:
            # Status
            status_str = str(getattr(result, "status", "FAIL")).upper()
            status = _STATUS_MAP.get(status_str, FindingStatus.FAIL)

            # result.metadata IS CheckMetadata directly (prowler v5 OutputFinding)
            check_metadata = getattr(result, "metadata", None)
            severity_str = "medium"
            if check_metadata:
                severity_str = str(getattr(check_metadata, "Severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

            check_id = str(getattr(check_metadata, "CheckID", "unknown")) if check_metadata else "unknown"
            title = str(getattr(check_metadata, "CheckTitle", check_id)) if check_metadata else check_id
            description = str(getattr(check_metadata, "Description", "")) if check_metadata else ""

            # Resource
            resource_uid = str(getattr(result, "resource_uid", "") or "")
            resource_name = str(getattr(result, "resource_name", "") or "")
            resource_id = resource_name or resource_uid or "unknown"
            resource_arn = resource_uid if resource_uid.startswith("arn:") else None
            region = str(getattr(result, "region", "") or "") or None
            resource_type = str(getattr(check_metadata, "ResourceType", "unknown")) if check_metadata else "unknown"

            # Remediation
            remediation_text: str | None = None
            remediation_code: str | None = None
            if check_metadata:
                remediation = getattr(check_metadata, "Remediation", None)
                if remediation:
                    rec = getattr(remediation, "Recommendation", None)
                    if rec:
                        remediation_text = str(getattr(rec, "Text", "") or "") or None
                    code = getattr(remediation, "Code", None)
                    if code:
                        remediation_code = str(getattr(code, "CLI", "") or "") or None

            # Framework mapping — compliance dict maps framework → [controls]
            compliance_raw = getattr(result, "compliance", {}) or {}
            framework_mapping: list[str] = []
            if isinstance(compliance_raw, dict):
                for fw_name, controls in compliance_raw.items():
                    if isinstance(controls, list):
                        for ctrl in controls:
                            framework_mapping.append(f"{fw_name}/{ctrl}")
                    else:
                        framework_mapping.append(str(fw_name))

            status_extended = str(getattr(result, "status_extended", ""))

            return Finding(
                finding_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                check_id=check_id,
                title=title,
                description=description,
                resource_id=resource_id,
                resource_arn=resource_arn,
                resource_type=resource_type,
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
                raw_output={"status_extended": status_extended},
            )
        except Exception:
            logger.exception("Failed to normalize Prowler v5 result — skipping")
            return None
