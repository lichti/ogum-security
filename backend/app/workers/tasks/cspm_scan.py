"""
CSPM scan task — runs Prowler v5 checks and persists findings + inventory to ArangoDB.

ProwlerService is mocked entirely in tests — Prowler never runs in CI.
ArangoDB upserts are idempotent (same check+resource+tenant produces the same key).

After every scan the resource inventory is refreshed from the scan output so
a separate discovery run is not required for CSPM-covered resources.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from app.db.init import init_tenant_schema
from app.models.finding import Finding, ScanJob, ScanJobStatus
from app.services.graph.data_access_edges import build_data_access_edges
from app.services.graph.exposure import compute_exposed_internet
from app.services.graph.iam_edges import build_iam_edges
from app.services.graph.resource_edges import build_resource_edges
from app.services.prowler_inventory import extract_inventory_from_findings
from app.services.prowler_service import ProwlerService, ScanResult
from app.services.side_scanning.trigger import (
    SCANNABLE_RESOURCE_TYPES,
    enqueue_side_scan,
    has_prior_side_scan,
)
from app.workers.celery_app import celery_app
from app.workers.tasks.cloud_utils import _get_tenant_db, _upsert, upsert_finding
from app.workers.tasks.job_logging import JobLogHandler

logger = logging.getLogger(__name__)


def _update_job(db: Any, job_id: str, **fields: Any) -> None:
    try:
        db.collection("scan_jobs").update({"_key": job_id, **fields})
    except Exception:
        logger.exception("Failed to update scan_job %s", job_id)


def _upsert_finding(db: Any, finding: Finding) -> None:
    """Upsert finding and create HAS_FINDING edge from resource → finding."""
    upsert_finding(db, finding)

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


def _upsert_inventory(db: Any, inventory: dict[str, list[dict[str, Any]]]) -> int:
    """Upsert resources, identities, and data_assets from post-scan extraction."""
    _immutable = {"_key", "tenant_id", "provider", "resource_id", "arn"}
    count = 0
    for collection, docs in inventory.items():
        for doc in docs:
            update_fields = {k: v for k, v in doc.items() if k not in _immutable}
            _upsert(db, collection, doc, update_fields)
            count += 1
    return count


def _soft_delete_stale(
    db: Any,
    tenant_id: str,
    provider: str,
    inventory: dict[str, list[dict[str, Any]]],
) -> int:
    """Mark resources/identities/data_assets absent from this scan as deleted.

    Scoped to (tenant_id, provider) — a single Prowler run covers every
    resource type for the provider in one pass, so no per-type/per-region
    scoping is needed (unlike the old typed discovery.py soft-delete, which
    had to avoid deleting resources outside the specific type/region scope of
    a partial discovery run).
    """
    now = datetime.now(UTC).isoformat()
    normalized_provider = "k8s" if provider == "kubernetes" else provider
    total = 0
    for collection, docs in inventory.items():
        discovered_keys = [doc["_key"] for doc in docs]
        cursor = db.aql.execute(
            """
            FOR doc IN @@collection
              FILTER doc.tenant_id == @tenant_id
              FILTER doc.provider == @provider
              FILTER doc.status != "deleted"
              FILTER doc._key NOT IN @discovered_keys
              UPDATE doc WITH { status: "deleted", deleted_at: @now, updated_at: @now } IN @@collection
              RETURN 1
            """,
            bind_vars={
                "@collection": collection,
                "tenant_id": tenant_id,
                "provider": normalized_provider,
                "discovered_keys": discovered_keys,
                "now": now,
            },
        )
        total += len(list(cursor))
    return total


def _auto_trigger_side_scans(
    db: Any,
    tenant_id: str,
    provider_id: str,
    credentials: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
) -> int:
    """
    Enqueue a side-scan for each EC2/Lambda resource in this scan's inventory that
    has never had one before (first-seen only — no periodic auto re-scan, to keep
    EBS snapshot cost and Celery/trivy-server load bounded). Re-scanning later is
    either manual ("Scan Now" in Inventory) or via the daily rescan_sboms task,
    which re-checks stored SBOMs against new CVEs at zero AWS cost.

    Best-effort: a failure enqueuing one resource is logged and skipped, never
    fails the CSPM scan job itself.
    """
    triggered = 0
    for resource in inventory.get("resources", []):
        if resource.get("resource_type") not in SCANNABLE_RESOURCE_TYPES:
            continue
        resource_key = resource.get("_key")
        if not resource_key or has_prior_side_scan(db, tenant_id, resource_key):
            continue
        try:
            job_id = enqueue_side_scan(db, tenant_id, resource, provider_id, credentials)
        except Exception:
            logger.exception("Failed to auto-trigger side-scan [tenant=%s resource=%s]", tenant_id, resource_key)
            continue
        if job_id:
            triggered += 1
    return triggered


def _dispatch_scan(
    prowler: ProwlerService,
    provider: str,
    tenant_id: str,
    account_id: str,
    frameworks: list[str] | None,
    credentials: dict[str, Any],
    regions: list[str] | None,
    scan_job_id: str,
) -> ScanResult:
    """Route to the correct ProwlerService method by provider."""
    if provider == "aws":
        return prowler.run_aws_scan(
            tenant_id=tenant_id,
            account_id=account_id,
            role_arn=credentials.get("role_arn"),
            external_id=credentials.get("external_id"),
            aws_access_key_id=credentials.get("aws_access_key_id"),
            aws_secret_access_key=credentials.get("aws_secret_access_key"),
            regions=regions,
            frameworks=frameworks,
            scan_job_id=scan_job_id,
        )

    if provider == "azure":
        return prowler.run_azure_scan(
            tenant_id=tenant_id,
            account_id=account_id,
            subscription_ids=[account_id] if account_id else None,
            azure_tenant_id=credentials.get("azure_tenant_id"),
            client_id=credentials.get("azure_client_id"),
            client_secret=credentials.get("azure_client_secret"),
            frameworks=frameworks,
            scan_job_id=scan_job_id,
        )

    if provider == "gcp":
        return prowler.run_gcp_scan(
            tenant_id=tenant_id,
            account_id=account_id,
            project_ids=[account_id] if account_id else None,
            service_account_key=credentials.get("gcp_service_account_json"),
            frameworks=frameworks,
            scan_job_id=scan_job_id,
        )

    if provider in ("k8s", "kubernetes"):
        return prowler.run_kubernetes_scan(
            tenant_id=tenant_id,
            account_id=account_id,
            cluster_name=credentials.get("cluster_name") or account_id or None,
            kubeconfig_content=credentials.get("kubeconfig"),
            frameworks=frameworks,
            scan_job_id=scan_job_id,
        )

    logger.warning("CSPM scan not supported for provider=%s", provider)
    return ScanResult(findings=[], raw_outputs=[])


@celery_app.task(bind=True, max_retries=2, default_retry_delay=120)
def run_cspm_scan(
    self: Any,
    tenant_id: str,
    provider_id: str,
    provider: str,
    frameworks: list[str] | None,
    credentials: dict[str, Any],
    account_id: str,
    regions: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run a CSPM scan via Prowler v5, persist findings, and refresh inventory.

    This is also the only inventory-building path — a scan is a full
    discovery pass: resources/identities/data_assets and their graph edges
    are (re)built from this scan's output every time it runs.

    Args:
        tenant_id: Ogum tenant identifier.
        provider_id: ArangoDB key of the provider config.
        provider: Cloud provider ("aws", "azure", "gcp", "k8s").
        frameworks: Compliance framework IDs to scan, or None/empty to run
            Prowler's full check catalog (recommended — every check still
            tags its result with every framework it belongs to, so this is a
            superset of any explicit list, not a narrower scan).
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
        task_name=f"cspm_scan/{provider}",
        frameworks=frameworks or [],
        regions=regions or [],
        status=ScanJobStatus.RUNNING,
        started_at=datetime.now(UTC),
    )
    db.collection("scan_jobs").insert(job.to_arango_doc())

    # Captures this task's own logging plus anything that propagates through
    # it (Prowler, boto3 at WARNING+) into the job doc's `logs` field, so the
    # Admin Jobs UI can show what happened — see job_logging.py for why this
    # is attach/detach rather than a `with` block (avoids reindenting the
    # whole try/except below).
    log_handler = JobLogHandler(db, job_id)
    logging.getLogger().addHandler(log_handler)

    try:
        prowler = ProwlerService()
        scan_result = _dispatch_scan(
            prowler=prowler,
            provider=provider,
            tenant_id=tenant_id,
            account_id=account_id,
            frameworks=frameworks,
            credentials=credentials,
            regions=regions,
            scan_job_id=job_id,
        )

        findings = scan_result.findings

        for finding in findings:
            _upsert_finding(db, finding)

        # Refresh inventory from scan output — covers all providers
        inventory = extract_inventory_from_findings(
            findings=scan_result.raw_outputs,
            tenant_id=tenant_id,
            provider=provider,
            account_id=account_id,
        )
        inventory_count = _upsert_inventory(db, inventory)
        deleted_count = _soft_delete_stale(db, tenant_id, provider, inventory)

        # Side-scanning is AWS-only (scan_ec2_instance_v2/scan_lambda_function) and
        # needs a live boto3 session, which credentials/provider_id here already
        # carry — no extra credential resolution.
        side_scans_triggered = (
            _auto_trigger_side_scans(db, tenant_id, provider_id, credentials, inventory) if provider == "aws" else 0
        )

        # Graph enrichment — derives edges from the raw_metadata just persisted
        # above, no additional cloud API calls (Lambda execution-role is the
        # sole exception, already resolved during the scan itself).
        iam_edge_counts = build_iam_edges(db, tenant_id)
        resource_edge_counts = build_resource_edges(db, tenant_id)
        data_access_edges = build_data_access_edges(db, tenant_id)
        exposure_counts = compute_exposed_internet(db, tenant_id)

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
            "CSPM scan complete [tenant=%s provider=%s]: findings=%d fail=%d inventory=%d deleted=%d "
            "iam_edges=%s resource_edges=%s data_access_edges=%d exposure=%s side_scans_triggered=%d",
            tenant_id,
            provider,
            len(findings),
            fail_count,
            inventory_count,
            deleted_count,
            iam_edge_counts,
            resource_edge_counts,
            data_access_edges,
            exposure_counts,
            side_scans_triggered,
        )

        # Enqueue post-scan risk scoring / attack path detection (fire-and-forget)
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
            "inventory_upserted": inventory_count,
            "inventory_deleted": deleted_count,
            "iam_edges": iam_edge_counts,
            "resource_edges": resource_edge_counts,
            "data_access_edges": data_access_edges,
            "exposure_updated": exposure_counts,
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
    finally:
        log_handler.flush_to_db()
        logging.getLogger().removeHandler(log_handler)
