"""
CSPM scan task — runs Prowler v5 checks and persists findings to ArangoDB.

ProwlerService is mocked entirely in tests — Prowler never runs in CI.
ArangoDB upserts are idempotent (same check+resource+tenant produces the same key).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from app.db.init import init_tenant_schema
from app.models.finding import Finding, ScanJob, ScanJobStatus
from app.services.prowler_service import ProwlerService
from app.workers.celery_app import celery_app
from app.workers.tasks.discovery import _get_tenant_db, _upsert

logger = logging.getLogger(__name__)


def _update_job(db: Any, job_id: str, **fields: Any) -> None:
    try:
        db.collection("scan_jobs").update({"_key": job_id, **fields})
    except Exception:
        logger.exception("Failed to update scan_job %s", job_id)


def _upsert_finding(db: Any, finding: Finding) -> None:
    """Upsert finding and create HAS_FINDING edge from resource → finding."""
    _upsert(db, "findings", finding.to_arango_doc(), finding.to_arango_update())

    finding_key = finding.arango_key()
    edge_key = f"{finding.resource_id}__{finding_key}".replace("/", "_").replace(":", "_")
    edge_doc = {
        "_key": edge_key[:240],
        "_from": f"resources/{finding.resource_id}",
        "_to": f"findings/{finding_key}",
        "tenant_id": finding.tenant_id,
    }
    try:
        if not db.collection("HAS_FINDING").has(edge_doc["_key"]):
            db.collection("HAS_FINDING").insert(edge_doc)
    except Exception:
        pass  # edge already exists or resource doesn't exist — both acceptable


@celery_app.task(bind=True, max_retries=2, default_retry_delay=120)
def run_cspm_scan(
    self: Any,
    tenant_id: str,
    provider_id: str,
    provider: str,
    frameworks: list[str],
    credentials: dict[str, Any],
    account_id: str,
    regions: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run a CSPM scan via Prowler v5 and persist findings to ArangoDB.

    Args:
        tenant_id: Ogum tenant identifier.
        provider_id: ArangoDB key of the provider config.
        provider: Cloud provider ("aws", "azure", "gcp").
        frameworks: List of compliance framework IDs to scan.
        credentials: Ephemeral credentials dict (never stored beyond this call).
        account_id: Cloud account/subscription/project ID.
        regions: Optional list of regions to scan (None = all).
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    job_id = str(uuid.uuid4())
    job = ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        provider_id=provider_id,
        provider=provider,
        frameworks=frameworks,
        regions=regions or [],
        status=ScanJobStatus.RUNNING,
        started_at=datetime.now(UTC),
    )
    db.collection("scan_jobs").insert(job.to_arango_doc())

    try:
        prowler = ProwlerService()
        findings: list[Finding] = []

        if provider == "aws":
            findings = prowler.run_aws_scan(
                tenant_id=tenant_id,
                account_id=account_id,
                role_arn=credentials.get("role_arn"),
                external_id=credentials.get("external_id"),
                aws_access_key_id=credentials.get("aws_access_key_id"),
                aws_secret_access_key=credentials.get("aws_secret_access_key"),
                regions=regions,
                frameworks=frameworks,
                scan_job_id=job_id,
            )
        else:
            logger.warning("CSPM scan not yet supported for provider=%s", provider)

        for finding in findings:
            _upsert_finding(db, finding)

        fail_count = sum(1 for f in findings if f.status == "FAIL")
        _update_job(
            db,
            job_id,
            status=ScanJobStatus.COMPLETED,
            checks_total=len(findings),
            checks_completed=len(findings),
            findings_found=len(findings),
            findings_fail=fail_count,
            completed_at=datetime.now(UTC).isoformat(),
        )

        logger.info(
            "CSPM scan complete [tenant=%s provider=%s]: findings=%d fail=%d",
            tenant_id,
            provider,
            len(findings),
            fail_count,
        )

        # Enqueue post-scan graph enrichment (fire-and-forget)
        try:
            from app.workers.tasks.attack_paths import (  # noqa: PLC0415
                detect_attack_paths,
                recalculate_risk_scores,
            )

            recalculate_risk_scores.delay(tenant_id)
            detect_attack_paths.delay(tenant_id)
        except Exception:
            logger.warning("Failed to enqueue post-scan graph tasks for tenant=%s", tenant_id)

        return {
            "job_id": job_id,
            "tenant_id": tenant_id,
            "provider": provider,
            "findings_found": len(findings),
            "findings_fail": fail_count,
        }

    except Exception as exc:
        logger.exception("CSPM scan failed [tenant=%s job=%s]: %s", tenant_id, job_id, exc)
        _update_job(
            db,
            job_id,
            status=ScanJobStatus.FAILED,
            error_message=str(exc),
            completed_at=datetime.now(UTC).isoformat(),
        )
        raise self.retry(exc=exc)
