"""
Side-scanning Celery tasks (Epic 03 Sprint 1).

scan_ec2_instance — agentless EC2 scan via ephemeral EBS snapshot:
  1. Create EBS snapshot of root volume (tagged ogum:scan=true)
  2. Wait for snapshot to complete (max 15 min)
  3. Create gp3 volume from snapshot
  4. Prepare scan path (mount in production; configurable in tests)
  5. Run Trivy, YARA, TruffleHog in parallel
  6. Cleanup (always runs in finally — snapshot and volume destroyed)
  7. Normalise findings → persist to ArangoDB with HAS_FINDING edges

cleanup_orphan_snapshots — Celery Beat hourly task:
  Lists all ogum:scan=true snapshots and deletes any past their ogum:expires_at tag.

Security invariants:
  - Snapshots always carry ogum:expires_at so orphan cleanup can recover from worker crashes.
  - Secret values found on disk are NEVER logged.
  - Volume is mounted read-only — no writes to customer disk content.
"""

from __future__ import annotations

import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

from app.db.init import init_tenant_schema
from app.models.finding import Finding, FindingSource, FindingStatus, SeverityLevel
from app.services.side_scanning import cvss_to_severity
from app.services.side_scanning.analyzers.secret_analyzer import run_trufflehog
from app.services.side_scanning.analyzers.trivy_analyzer import run_trivy_fs
from app.services.side_scanning.analyzers.yara_analyzer import run_yara
from app.services.side_scanning.snapshot_manager import (
    create_scan_snapshot,
    create_volume_from_snapshot,
    delete_snapshot_safe,
    delete_volume_safe,
    list_ogum_snapshots,
    mount_volume_ro,
    umount_volume,
    wait_for_snapshot,
)
from app.workers.celery_app import celery_app
from app.workers.tasks._job_tracking import (
    complete_discovery_job,
    start_discovery_job,
)
from app.workers.tasks.discovery import _get_aws_session, _get_tenant_db, _upsert

logger = logging.getLogger(__name__)

# Mount path inside the scanner container; override via env for testing
_SCAN_MOUNT_PATH = os.environ.get("OGUM_SCAN_MOUNT_PATH", "/mnt/target")

# Device name used when attaching the scan volume to the scanner EC2 instance
_SCAN_DEVICE = os.environ.get("OGUM_SCAN_DEVICE", "/dev/xvdf")

# Scanner EC2 instance ID — required for volume attachment in production
_SCANNER_INSTANCE_ID = os.environ.get("OGUM_SCANNER_INSTANCE_ID", "")

# Analysis timeout per tool (seconds) — total task hard-limit is 30 min via Celery
_ANALYZER_TIMEOUT = 1200


# ─── Finding persistence ──────────────────────────────────────────────────────


def _upsert_finding(db: Any, finding: Finding) -> None:
    """Upsert a side-scanning finding and create HAS_FINDING edge from resource."""
    _upsert(db, "findings", finding.to_arango_doc(), finding.to_arango_update())
    finding_key = finding.arango_key()
    raw_edge_key = f"{finding.resource_id}__{finding_key}"
    edge_key = raw_edge_key.replace("/", "_").replace(":", "_")[:240]
    edge_doc = {
        "_key": edge_key,
        "_from": f"resources/{finding.resource_id}",
        "_to": f"findings/{finding_key}",
        "tenant_id": finding.tenant_id,
    }
    try:
        if not db.collection("HAS_FINDING").has(edge_doc["_key"]):
            db.collection("HAS_FINDING").insert(edge_doc)
    except Exception:
        pass  # edge already exists — acceptable


# ─── Finding normalisation ────────────────────────────────────────────────────


def _normalise_cve(
    vuln: dict[str, Any],
    *,
    tenant_id: str,
    resource_id: str,
    resource_arn: str | None,
    provider: str,
    region: str,
    account_id: str,
    scan_job_id: str,
) -> Finding:
    cve_id = vuln.get("cve_id") or "NOID"
    package = vuln.get("package", "unknown")
    check_id = f"side_scanning/cve/{cve_id}"
    severity = cvss_to_severity(vuln.get("cvss_score", 0.0))
    title = vuln.get("title") or f"{cve_id} in {package}"
    desc = vuln.get("description") or title
    return Finding(
        finding_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        check_id=check_id,
        title=title[:200],
        description=desc[:500],
        resource_id=resource_id,
        resource_arn=resource_arn,
        resource_type="ec2_instance",
        severity=severity,
        status=FindingStatus.FAIL,
        provider=provider,
        region=region,
        account_id=account_id,
        source=FindingSource.SIDE_SCANNING,
        scan_job_id=scan_job_id,
        raw_output={
            "package": package,
            "installed_version": vuln.get("installed_version", ""),
            "fixed_version": vuln.get("fixed_version", ""),
            "cvss_score": vuln.get("cvss_score", 0.0),
        },
    )


def _normalise_secret(
    secret: dict[str, Any],
    *,
    tenant_id: str,
    resource_id: str,
    resource_arn: str | None,
    provider: str,
    region: str,
    account_id: str,
    scan_job_id: str,
) -> Finding:
    rule = secret.get("rule", "unknown")
    path = secret.get("path", "")
    check_id = f"side_scanning/secret/{rule}"
    return Finding(
        finding_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        check_id=check_id,
        title=f"Exposed secret detected: {rule}",
        description=f"Secret matching rule '{rule}' found at path '{path}' on the instance disk.",
        resource_id=resource_id,
        resource_arn=resource_arn,
        resource_type="ec2_instance",
        severity=SeverityLevel.CRITICAL,
        status=FindingStatus.FAIL,
        provider=provider,
        region=region,
        account_id=account_id,
        source=FindingSource.SIDE_SCANNING,
        scan_job_id=scan_job_id,
        # path metadata only — never include the actual secret value
        raw_output={"rule": rule, "path": path, "line": secret.get("line", 0)},
    )


def _normalise_malware(
    match: dict[str, str],
    *,
    tenant_id: str,
    resource_id: str,
    resource_arn: str | None,
    provider: str,
    region: str,
    account_id: str,
    scan_job_id: str,
) -> Finding:
    rule = match.get("rule", "unknown")
    path = match.get("path", "")
    check_id = f"side_scanning/malware/{rule}"
    return Finding(
        finding_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        check_id=check_id,
        title=f"Malware detected: {rule}",
        description=f"YARA rule '{rule}' matched at path '{path}' on the instance disk.",
        resource_id=resource_id,
        resource_arn=resource_arn,
        resource_type="ec2_instance",
        severity=SeverityLevel.CRITICAL,
        status=FindingStatus.FAIL,
        provider=provider,
        region=region,
        account_id=account_id,
        source=FindingSource.SIDE_SCANNING,
        scan_job_id=scan_job_id,
        raw_output={"rule": rule, "path": path},
    )


# ─── Main task ────────────────────────────────────────────────────────────────


@celery_app.task(bind=True, max_retries=1, default_retry_delay=300, time_limit=1800)
def scan_ec2_instance(  # noqa: PLR0913
    self: Any,
    *,
    tenant_id: str,
    resource_key: str,
    provider_key: str,
    region: str,
    account_id: str,
    instance_id: str,
    volume_id: str,
    availability_zone: str,
    resource_arn: str | None = None,
    role_arn: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> dict[str, Any]:
    """Agentless EC2 scan via ephemeral EBS snapshot."""
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)
    job_id = start_discovery_job(db, tenant_id, "aws", provider_key)
    logger.info(
        "side_scanning start [tenant=%s instance=%s volume=%s job=%s]",
        tenant_id,
        instance_id,
        volume_id,
        job_id,
    )

    session = _get_aws_session(
        role_arn=role_arn,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    ec2 = session.client("ec2", region_name=region)

    snapshot_id: str | None = None
    scan_volume_id: str | None = None
    mounted = False

    try:
        # 1. Create and wait for snapshot
        snapshot_id = create_scan_snapshot(ec2, volume_id, tenant_id)
        wait_for_snapshot(ec2, snapshot_id)

        # 2. Create volume from snapshot
        scan_volume_id = create_volume_from_snapshot(ec2, snapshot_id, availability_zone)

        # 3. Mount (skipped when scanner is not on EC2 — OGUM_SCANNER_INSTANCE_ID not set)
        scan_path = _SCAN_MOUNT_PATH
        if _SCANNER_INSTANCE_ID:
            ec2.attach_volume(
                VolumeId=scan_volume_id,
                InstanceId=_SCANNER_INSTANCE_ID,
                Device=_SCAN_DEVICE,
            )
            mount_volume_ro(_SCAN_DEVICE, scan_path)
            mounted = True

        # 4. Run analysers in parallel
        vulns: list[dict[str, Any]] = []
        yara_matches: list[dict[str, str]] = []
        secrets: list[dict[str, Any]] = []

        def _run_trivy() -> list[dict[str, Any]]:
            return run_trivy_fs(scan_path, timeout=_ANALYZER_TIMEOUT)

        def _run_yara() -> list[dict[str, str]]:
            return run_yara(scan_path, timeout=_ANALYZER_TIMEOUT)

        def _run_secrets() -> list[dict[str, Any]]:
            return run_trufflehog(scan_path, timeout=_ANALYZER_TIMEOUT)

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(_run_trivy): "trivy",
                pool.submit(_run_yara): "yara",
                pool.submit(_run_secrets): "secrets",
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    if name == "trivy":
                        vulns = result
                    elif name == "yara":
                        yara_matches = result
                    else:
                        secrets = result
                except Exception:
                    logger.exception("Analyser %s failed for instance=%s", name, instance_id)

    finally:
        # 5. Cleanup — always runs, even on exception
        if mounted:
            umount_volume(scan_path)
        if scan_volume_id:
            try:
                if _SCANNER_INSTANCE_ID and mounted:
                    ec2.detach_volume(VolumeId=scan_volume_id, Force=True)
                delete_volume_safe(ec2, scan_volume_id)
            except Exception:
                logger.exception("Volume cleanup failed for %s — job=%s", scan_volume_id, job_id)
        if snapshot_id:
            try:
                delete_snapshot_safe(ec2, snapshot_id)
            except Exception:
                logger.exception("Snapshot cleanup failed for %s — job=%s", snapshot_id, job_id)

    # 6. Normalise and persist findings
    common = dict(
        tenant_id=tenant_id,
        resource_id=resource_key,
        resource_arn=resource_arn,
        provider="aws",
        region=region,
        account_id=account_id,
        scan_job_id=job_id,
    )
    findings: list[Finding] = []
    for v in vulns:
        findings.append(_normalise_cve(v, **common))
    for s in secrets:
        findings.append(_normalise_secret(s, **common))
    for m in yara_matches:
        findings.append(_normalise_malware(m, **common))

    for f in findings:
        try:
            _upsert_finding(db, f)
        except Exception:
            logger.exception("Failed to persist finding %s", f.check_id)

    complete_discovery_job(db, job_id, len(findings))
    logger.info(
        "side_scanning complete [tenant=%s instance=%s findings=%d job=%s]",
        tenant_id,
        instance_id,
        len(findings),
        job_id,
    )
    return {
        "job_id": job_id,
        "instance_id": instance_id,
        "findings_count": len(findings),
        "cve_count": len(vulns),
        "secret_count": len(secrets),
        "malware_count": len(yara_matches),
    }


# ─── Orphan cleanup task ──────────────────────────────────────────────────────


@celery_app.task(bind=True, max_retries=0)
def cleanup_orphan_snapshots(
    self: Any,
    *,
    tenant_id: str,
    region: str = "us-east-1",
    role_arn: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> dict[str, Any]:
    """Hourly Celery Beat task: delete expired ogum:scan snapshots."""
    session = _get_aws_session(
        role_arn=role_arn,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    ec2 = session.client("ec2", region_name=region)

    snapshots = list_ogum_snapshots(ec2)
    now = datetime.now(UTC)
    deleted = 0

    for snap in snapshots:
        expires_at_str: str | None = None
        for tag in snap.get("Tags") or []:
            if tag["Key"] == "ogum:expires_at":
                expires_at_str = tag["Value"]
                break

        if not expires_at_str:
            continue

        try:
            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
        except ValueError:
            logger.warning("Could not parse ogum:expires_at=%s on snapshot=%s", expires_at_str, snap["SnapshotId"])
            continue

        if now >= expires_at:
            try:
                delete_snapshot_safe(ec2, snap["SnapshotId"])
                deleted += 1
                logger.info(
                    "Orphan cleanup: deleted expired snapshot %s (expired %s)",
                    snap["SnapshotId"],
                    expires_at_str,
                )
            except Exception:
                logger.exception("Orphan cleanup: failed to delete snapshot %s", snap["SnapshotId"])

    logger.info("Orphan snapshot cleanup complete: %d deleted of %d found (region=%s)", deleted, len(snapshots), region)
    return {"deleted": deleted, "scanned": len(snapshots)}
