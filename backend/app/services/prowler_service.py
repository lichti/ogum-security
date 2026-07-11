"""
Prowler v5 scan service.

Wraps the prowler-core programmatic API. In tests, ProwlerService is mocked
entirely — Prowler never runs against real cloud APIs in CI.

Prowler v5 API summary:
  - AwsProvider(**kwargs) — flat keyword args, no audit_config dict
  - AzureProvider(**kwargs), GcpProvider(**kwargs), KubernetesProvider(**kwargs)
  - Scan(provider, compliances=[...]) — high-level scanner
  - scan() — generator yielding (progress_float, [OutputFinding])
  - OutputFinding fields: status, status_extended, region, resource_uid,
    resource_name, resource_metadata, compliance, metadata, account_uid, raw
  - Framework names use filesystem slugs: cis_2.0_aws, pci_4.0_aws, soc2_aws
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

from app.models.finding import Finding, FindingSource, FindingStatus, SeverityLevel

logger = logging.getLogger(__name__)

# ─── Framework ID → prowler compliance file slug ─────────────────────────────

_FRAMEWORK_MAP: dict[str, str] = {
    # AWS
    "CIS-AWS-2.0": "cis_2.0_aws",
    "CIS-AWS-3.0": "cis_3.0_aws",
    "PCI_DSS_v4": "pci_4.0_aws",
    "PCI_DSS_3.2.1": "pci_3.2.1_aws",
    "SOC2": "soc2_aws",
    "HIPAA": "hipaa_aws",
    "NIST-800-53": "nist_800_53_revision_5_aws",
    "ISO27001": "iso27001_2022_aws",
    "GDPR": "gdpr_aws",
    # Azure
    "CIS-AZURE-2.0": "cis_2.0_azure",
    "CIS-AZURE-3.0": "cis_3.0_azure",
    "CIS-AZURE-4.0": "cis_4.0_azure",
    # GCP
    "CIS-GCP-2.0": "cis_2.0_gcp",
    "CIS-GCP-3.0": "cis_3.0_gcp",
    "CIS-GCP-4.0": "cis_4.0_gcp",
    # Kubernetes
    "CIS-K8S-1.10": "cis_1.10_kubernetes",
    "CIS-K8S-1.12": "cis_1.12_kubernetes",
    "CIS-K8S-2.0": "cis_2.0.1_kubernetes",
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


@dataclass
class ScanResult:
    """Findings + raw OutputFinding objects for post-scan inventory extraction."""

    findings: list[Finding]
    raw_outputs: list[Any]  # list[OutputFinding]


class ProwlerService:  # pragma: no cover
    """Run Prowler v5 checks and return normalized Finding objects."""

    # ─── Public scan methods ───────────────────────────────────────────────

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
        frameworks: list[str] | None = None,
        scan_job_id: str,
    ) -> ScanResult:
        """Execute Prowler v5 checks against an AWS account.

        frameworks=None (the default) runs prowler's full check catalog for the
        provider — every check still tags its result with every compliance
        framework it belongs to, so this is a superset of any explicit framework
        list, not a narrower scan. Pass explicit frameworks only to scope a
        one-off scan to a specific compliance requirement.
        """
        try:
            from prowler.providers.aws.aws_provider import AwsProvider  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("prowler-core is not installed") from exc

        compliance_slugs = self._resolve_frameworks(frameworks, provider="aws") if frameworks else None
        if frameworks and not compliance_slugs:
            return ScanResult(findings=[], raw_outputs=[])

        kwargs: dict[str, Any] = {
            "session_duration": 3600,
            "scan_unused_services": False,
        }
        if role_arn:
            kwargs["role_arn"] = role_arn
        if external_id:
            kwargs["external_id"] = external_id
        if regions:
            kwargs["regions"] = set(regions)
        if aws_access_key_id:
            kwargs["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key:
            kwargs["aws_secret_access_key"] = aws_secret_access_key

        provider = AwsProvider(**kwargs)
        scan_result = self._run_scan(
            provider=provider,
            compliance_slugs=compliance_slugs,
            cloud_provider="aws",
            tenant_id=tenant_id,
            account_id=account_id,
            scan_job_id=scan_job_id,
        )
        self._enrich_lambda_execution_roles(provider, scan_result.raw_outputs)
        return scan_result

    def run_azure_scan(
        self,
        *,
        tenant_id: str,
        account_id: str,
        subscription_ids: list[str] | None = None,
        azure_tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        frameworks: list[str] | None = None,
        scan_job_id: str,
    ) -> ScanResult:
        """Execute Prowler v5 checks against an Azure subscription. See run_aws_scan
        for the frameworks=None (full catalog) semantics."""
        try:
            from prowler.providers.azure.azure_provider import AzureProvider  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("prowler-core is not installed") from exc

        compliance_slugs = self._resolve_frameworks(frameworks, provider="azure") if frameworks else None
        if frameworks and not compliance_slugs:
            return ScanResult(findings=[], raw_outputs=[])

        kwargs: dict[str, Any] = {}
        if azure_tenant_id:
            kwargs["tenant_id"] = azure_tenant_id
        if subscription_ids:
            kwargs["subscription_ids"] = subscription_ids
        if client_id:
            kwargs["client_id"] = client_id
        if client_secret:
            kwargs["client_secret"] = client_secret
        if client_id and client_secret:
            kwargs["sp_env_auth"] = False  # explicit SP credentials provided

        provider = AzureProvider(**kwargs)
        return self._run_scan(
            provider=provider,
            compliance_slugs=compliance_slugs,
            cloud_provider="azure",
            tenant_id=tenant_id,
            account_id=account_id,
            scan_job_id=scan_job_id,
        )

    def run_gcp_scan(
        self,
        *,
        tenant_id: str,
        account_id: str,
        project_ids: list[str] | None = None,
        service_account_key: dict[str, Any] | None = None,
        frameworks: list[str] | None = None,
        scan_job_id: str,
    ) -> ScanResult:
        """Execute Prowler v5 checks against a GCP project. See run_aws_scan for
        the frameworks=None (full catalog) semantics."""
        try:
            from prowler.providers.gcp.gcp_provider import GcpProvider  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("prowler-core is not installed") from exc

        compliance_slugs = self._resolve_frameworks(frameworks, provider="gcp") if frameworks else None
        if frameworks and not compliance_slugs:
            return ScanResult(findings=[], raw_outputs=[])

        kwargs: dict[str, Any] = {}
        if project_ids:
            kwargs["project_ids"] = project_ids
        if service_account_key:
            kwargs["service_account_key"] = service_account_key

        provider = GcpProvider(**kwargs)
        return self._run_scan(
            provider=provider,
            compliance_slugs=compliance_slugs,
            cloud_provider="gcp",
            tenant_id=tenant_id,
            account_id=account_id,
            scan_job_id=scan_job_id,
        )

    def run_kubernetes_scan(
        self,
        *,
        tenant_id: str,
        account_id: str,
        cluster_name: str | None = None,
        kubeconfig_content: dict[str, Any] | None = None,
        context: str | None = None,
        frameworks: list[str] | None = None,
        scan_job_id: str,
    ) -> ScanResult:
        """Execute Prowler v5 checks against a Kubernetes cluster. See run_aws_scan
        for the frameworks=None (full catalog) semantics."""
        try:
            from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("prowler-core is not installed") from exc

        compliance_slugs = self._resolve_frameworks(frameworks, provider="k8s") if frameworks else None
        if frameworks and not compliance_slugs:
            return ScanResult(findings=[], raw_outputs=[])

        kwargs: dict[str, Any] = {}
        if cluster_name:
            kwargs["cluster_name"] = cluster_name
        if kubeconfig_content:
            kwargs["kubeconfig_content"] = kubeconfig_content
        if context:
            kwargs["context"] = context

        provider = KubernetesProvider(**kwargs)
        return self._run_scan(
            provider=provider,
            compliance_slugs=compliance_slugs,
            cloud_provider="kubernetes",
            tenant_id=tenant_id,
            account_id=account_id,
            scan_job_id=scan_job_id,
        )

    # ─── Internal helpers ──────────────────────────────────────────────────

    def _resolve_frameworks(self, frameworks: list[str], provider: str) -> list[str]:
        slugs: list[str] = []
        for fw in frameworks:
            slug = _FRAMEWORK_MAP.get(fw)
            if slug:
                slugs.append(slug)
            else:
                logger.warning(
                    "Framework %s not mapped to a prowler compliance slug (provider=%s) — skipping",
                    fw,
                    provider,
                )
        if not slugs:
            logger.warning("No recognized frameworks for provider=%s in %s — aborting scan", provider, frameworks)
        return slugs

    def _run_scan(
        self,
        *,
        provider: Any,
        compliance_slugs: list[str] | None,
        cloud_provider: str,
        tenant_id: str,
        account_id: str,
        scan_job_id: str,
    ) -> ScanResult:
        from prowler.lib.scan.scan import Scan  # noqa: PLC0415

        # compliance_slugs=None runs prowler's full default check catalog for the
        # provider (see checks_loader.load_checks_to_execute: no checks/services/
        # compliances/categories filter -> "get all checks"). Passing an empty
        # list instead would ask Scan() to match zero compliance frameworks.
        scan = Scan(provider, compliances=compliance_slugs) if compliance_slugs else Scan(provider)
        findings: list[Finding] = []
        raw_outputs: list[Any] = []

        for _progress, batch in scan.scan():
            for result in batch:
                raw_outputs.append(result)
                finding = self._normalize(
                    result=result,
                    cloud_provider=cloud_provider,
                    tenant_id=tenant_id,
                    account_id=account_id,
                    scan_job_id=scan_job_id,
                )
                if finding is not None:
                    findings.append(finding)

        return ScanResult(findings=findings, raw_outputs=raw_outputs)

    def _enrich_lambda_execution_roles(self, provider: Any, raw_outputs: list[Any]) -> None:
        """Fill in the Lambda execution role ARN on scanned Function results.

        prowler.providers.aws.services.awslambda.awslambda_service.Function has no
        execution-role field at all (verified against the model source) — every
        other relationship we need (EC2 security groups/subnet/instance profile,
        IAM trust policy/attached policies) is already present in resource_metadata,
        but this one genuinely isn't. lambda:ListFunctions already returns Role per
        function, so one paginated call per region (reusing the session/credentials
        prowler already resolved) closes the gap without a broader rediscovery pass.
        Mutates resource_metadata in place on the matching raw results.
        """
        lambda_results = [
            r
            for r in raw_outputs
            if str(getattr(getattr(r, "metadata", None), "ResourceType", "")) == "AwsLambdaFunction"
        ]
        if not lambda_results:
            return

        try:
            clients = provider.generate_regional_clients("lambda")
        except Exception:
            logger.warning("Could not create Lambda clients for execution-role enrichment", exc_info=True)
            return

        role_by_arn: dict[str, str] = {}
        for client in clients.values():
            try:
                for page in client.get_paginator("list_functions").paginate():
                    for fn in page.get("Functions", []):
                        arn = fn.get("FunctionArn")
                        role = fn.get("Role")
                        if arn and role:
                            role_by_arn[arn] = role
            except Exception:
                logger.warning("lambda:ListFunctions failed during execution-role enrichment", exc_info=True)

        if not role_by_arn:
            return

        for result in lambda_results:
            uid = str(getattr(result, "resource_uid", "") or "")
            role = role_by_arn.get(uid)
            metadata = getattr(result, "resource_metadata", None)
            if role and isinstance(metadata, dict):
                metadata["execution_role_arn"] = role

    def _normalize(
        self,
        result: Any,
        cloud_provider: str,
        tenant_id: str,
        account_id: str,
        scan_job_id: str,
    ) -> Finding | None:
        """Convert a Prowler v5 OutputFinding to our Finding model."""
        try:
            # prowler.lib.outputs.common.Status subclasses (str, Enum) but does not
            # override __str__, so str(Status.PASS) == "Status.PASS", not "PASS" —
            # that string never matches _STATUS_MAP and silently fell through to the
            # FAIL default, misclassifying every PASS/MANUAL result as FAIL. .value
            # (or the plain string Prowler sometimes returns) gives the real code.
            status_obj = getattr(result, "status", None)
            status_str = str(getattr(status_obj, "value", status_obj) or "FAIL").upper()
            status = _STATUS_MAP.get(status_str, FindingStatus.FAIL)

            # prowler.lib.check.models.Severity is the same (str, Enum) shape as
            # Status above, with the same missing __str__ override — str(Severity.high)
            # == "Severity.high", not "high". That never matches _SEVERITY_MAP, so
            # every finding silently fell through to the SeverityLevel.MEDIUM default,
            # regardless of the check's real severity (including "informational").
            check_meta = getattr(result, "metadata", None)
            severity_str = "medium"
            if check_meta:
                severity_obj = getattr(check_meta, "Severity", None)
                severity_str = str(getattr(severity_obj, "value", severity_obj) or "medium").lower()
            severity = _SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)

            check_id = str(getattr(check_meta, "CheckID", "unknown")) if check_meta else "unknown"
            title = str(getattr(check_meta, "CheckTitle", check_id)) if check_meta else check_id
            description = str(getattr(check_meta, "Description", "")) if check_meta else ""
            resource_type = str(getattr(check_meta, "ResourceType", "unknown")) if check_meta else "unknown"

            resource_uid = str(getattr(result, "resource_uid", "") or "")
            resource_name = str(getattr(result, "resource_name", "") or "")
            resource_id = resource_name or resource_uid or "unknown"
            resource_arn = resource_uid if resource_uid.startswith("arn:") else None
            region = str(getattr(result, "region", "") or "") or None

            # For non-AWS providers account_uid is subscription/project/cluster ID
            result_account = str(getattr(result, "account_uid", "") or "").strip()
            effective_account = result_account or account_id

            remediation_text: str | None = None
            remediation_code: str | None = None
            if check_meta:
                remediation = getattr(check_meta, "Remediation", None)
                if remediation:
                    rec = getattr(remediation, "Recommendation", None)
                    if rec:
                        remediation_text = str(getattr(rec, "Text", "") or "") or None
                    code = getattr(remediation, "Code", None)
                    if code:
                        remediation_code = str(getattr(code, "CLI", "") or "") or None

            compliance_raw = getattr(result, "compliance", {}) or {}
            framework_mapping: list[str] = []
            if isinstance(compliance_raw, dict):
                for fw_name, controls in compliance_raw.items():
                    if isinstance(controls, list):
                        for ctrl in controls:
                            framework_mapping.append(f"{fw_name}/{ctrl}")
                    else:
                        framework_mapping.append(str(fw_name))

            provider_str = "k8s" if cloud_provider == "kubernetes" else cloud_provider

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
                provider=provider_str,
                region=region,
                account_id=effective_account,
                framework_mapping=framework_mapping,
                remediation=remediation_text,
                remediation_code=remediation_code,
                source=FindingSource.CSPM,
                scan_job_id=scan_job_id,
                raw_output={"status_extended": str(getattr(result, "status_extended", ""))},
            )
        except Exception:
            logger.exception("Failed to normalize Prowler v5 result — skipping")
            return None
