"""
Side-scanning Celery tasks (Epic 03 Sprints 1 & 2).

scan_ec2_instance (Sprint 1) — agentless EC2 scan via ephemeral EBS snapshot + volume mount.
scan_ec2_instance_v2 (Sprint 2) — agentless EC2 scan via EBS Direct API (no volume, no mount).
scan_lambda_function (Sprint 2) — agentless Lambda scan via ZIP download to /dev/shm.
rescan_sboms (Sprint 2) — daily re-scan of stored CycloneDX SBOMs for new CVEs.
cleanup_orphan_snapshots — Celery Beat hourly task.

Security invariants:
  - Snapshots always carry ogum:expires_at so orphan cleanup can recover from crashes.
  - Secret values found on disk are NEVER logged or stored (Trivy redacts Match as ****).
  - Lambda code is downloaded to RAM disk (/dev/shm) and always deleted in finally.
  - EBS snapshots are always deleted in finally (delete_snapshot_safe does not raise).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from typing import Any

import httpx

from app.db.init import init_tenant_schema
from app.models.finding import Finding, FindingSource, FindingStatus, SeverityLevel
from app.services.side_scanning import cvss_to_severity
from app.services.side_scanning.analyzers.trivy_analyzer import (
    run_trivy_ebs,
    run_trivy_fs,
    run_trivy_image,
    run_trivy_rootfs,
)
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
    update_job_to_running,
)
from app.workers.tasks.cloud_utils import _get_aws_session, _get_tenant_db, _upsert

logger = logging.getLogger(__name__)

# Mount path inside the scanner container; override via env for testing
_SCAN_MOUNT_PATH = os.environ.get("OGUM_SCAN_MOUNT_PATH", "/mnt/target")

# Device name used when attaching the scan volume to the scanner EC2 instance (Sprint 1)
_SCAN_DEVICE = os.environ.get("OGUM_SCAN_DEVICE", "/dev/xvdf")

# Scanner EC2 instance ID — required for volume attachment in Sprint 1 production mode
_SCANNER_INSTANCE_ID = os.environ.get("OGUM_SCANNER_INSTANCE_ID", "")

# Trivy sidecar server URL for EBS Direct API (Sprint 2)
_TRIVY_SERVER_URL = os.environ.get("TRIVY_SERVER_URL", "http://trivy-server:4954")

# Analysis timeout per tool (seconds) — total task hard-limit is 30 min via Celery
_ANALYZER_TIMEOUT = 1200

# Trivy severity string → SeverityLevel mapping (Sprint 2)
_TRIVY_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "INFORMATIONAL": SeverityLevel.INFORMATIONAL,
}


def _trivy_severity(trivy_sev: str, cvss_score: float) -> SeverityLevel:
    """Map Trivy Severity string to SeverityLevel. Falls back to CVSS when UNKNOWN."""
    mapped = _TRIVY_SEVERITY_MAP.get((trivy_sev or "UNKNOWN").upper())
    if mapped is not None:
        return mapped
    return cvss_to_severity(cvss_score)


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


def _normalise_cve_v2(
    vuln: dict[str, Any],
    *,
    tenant_id: str,
    resource_id: str,
    resource_arn: str | None,
    provider: str,
    region: str,
    account_id: str,
    scan_job_id: str,
    detection_method: str = "ebs_direct",
) -> Finding:
    """Normalise a Trivy vulnerability dict (Sprint 2). Trivy Severity field is primary."""
    cve_id = vuln.get("cve_id") or "NOID"
    package = vuln.get("package", "unknown")
    check_id = f"side_scanning/cve/{cve_id}"
    severity = _trivy_severity(vuln.get("severity", "UNKNOWN"), vuln.get("cvss_score", 0.0))
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
            "detection_method": detection_method,
        },
    )


def _normalise_trivy_secret(
    secret: dict[str, Any],
    *,
    tenant_id: str,
    resource_id: str,
    resource_arn: str | None,
    provider: str,
    region: str,
    account_id: str,
    scan_job_id: str,
    resource_type: str = "ec2_instance",
    detection_method: str = "trivy_secret",
) -> Finding:
    """Normalise a Trivy secret dict (Sprint 2). Never includes the matched secret value."""
    rule_id = secret.get("rule_id", "unknown")
    category = secret.get("category", "")
    title = secret.get("title") or f"Secret detected: {rule_id}"
    target = secret.get("target", "")
    check_id = f"side_scanning/secret/{rule_id}"
    severity = _trivy_severity(secret.get("severity", "HIGH"), 0.0)
    return Finding(
        finding_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        check_id=check_id,
        title=title[:200],
        description=f"Secret '{rule_id}' (category: {category}) found in '{target}'.",
        resource_id=resource_id,
        resource_arn=resource_arn,
        resource_type=resource_type,
        severity=severity,
        status=FindingStatus.FAIL,
        provider=provider,
        region=region,
        account_id=account_id,
        source=FindingSource.SIDE_SCANNING,
        scan_job_id=scan_job_id,
        # target path metadata only — Trivy already redacts Match as ****
        raw_output={"rule_id": rule_id, "category": category, "target": target, "detection_method": detection_method},
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
    job_id = start_discovery_job(db, tenant_id, "aws", provider_key, job_type="ec2")
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

        # 4. Run analysers in parallel (secrets via Trivy --scanners secret in v2)
        vulns: list[dict[str, Any]] = []
        yara_matches: list[dict[str, str]] = []
        secrets: list[dict[str, Any]] = []

        def _run_trivy() -> list[dict[str, Any]]:
            return run_trivy_fs(scan_path, timeout=_ANALYZER_TIMEOUT)

        def _run_yara() -> list[dict[str, str]]:
            return run_yara(scan_path, timeout=_ANALYZER_TIMEOUT)

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                pool.submit(_run_trivy): "trivy",
                pool.submit(_run_yara): "yara",
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    if name == "trivy":
                        vulns = result
                    else:
                        yara_matches = result
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


# ─── Sprint 2 helpers ─────────────────────────────────────────────────────────


def _generate_sbom(snapshot_id: str, trivy_server_url: str, job_id: str) -> dict[str, Any]:
    """Generate CycloneDX SBOM via trivy client. Returns empty dict on failure."""
    result = subprocess.run(
        [
            "trivy",
            "client",
            "--server",
            trivy_server_url,
            "vm",
            f"ebs:{snapshot_id}",
            "--format",
            "cyclonedx",
            "--quiet",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode not in (0, 1) or not result.stdout.strip():
        logger.warning("SBOM generation returned %d for snapshot=%s job=%s", result.returncode, snapshot_id, job_id)
        return {}
    try:
        return json.loads(result.stdout)  # type: ignore[no-any-return]
    except Exception:
        logger.exception("Failed to parse SBOM JSON for snapshot=%s", snapshot_id)
        return {}


def _persist_sbom(
    db: Any,
    sbom_json: dict[str, Any],
    tenant_id: str,
    resource_id: str,
    job_id: str,
) -> None:
    """Upsert a CycloneDX SBOM document and create HAS_SBOM edge from the resource."""
    if not sbom_json:
        return
    resource_key = resource_id.replace("/", "_").replace(":", "_")
    key = f"{tenant_id}_{resource_key}"[:240]
    doc = {
        "_key": key,
        "tenant_id": tenant_id,
        "resource_id": resource_id,
        "format": "cyclonedx",
        "content": sbom_json,
        "generated_at": datetime.now(UTC).isoformat(),
        "trivy_db_version": sbom_json.get("metadata", {}).get("component", {}).get("version", ""),
        "job_id": job_id,
        "component_count": len(sbom_json.get("components", [])),
    }
    _upsert(db, "sboms", doc, {"generated_at": doc["generated_at"], "component_count": doc["component_count"]})

    edge_key = f"sbom__{key}"
    edge_doc = {
        "_key": edge_key,
        "_from": f"resources/{resource_key}",
        "_to": f"sboms/{key}",
        "tenant_id": tenant_id,
    }
    try:
        if not db.collection("HAS_SBOM").has(edge_doc["_key"]):
            db.collection("HAS_SBOM").insert(edge_doc)
    except Exception:
        pass  # edge already exists


# ─── Sprint 2 tasks ───────────────────────────────────────────────────────────


@celery_app.task(bind=True, max_retries=1, default_retry_delay=300, time_limit=1800)
def scan_ec2_instance_v2(  # noqa: PLR0913
    self: Any,
    tenant_id: str,
    instance_id: str,
    volume_id: str,
    provider_id: str,
    job_id: str,
    trivy_server_url: str = _TRIVY_SERVER_URL,
    severity_threshold: str = "HIGH,CRITICAL",
    region: str = "us-east-1",
    account_id: str = "",
    resource_key: str = "",
    resource_arn: str | None = None,
    role_arn: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> dict[str, Any]:
    """
    EBS Direct API scan pipeline (Sprint 2):
      1. CreateSnapshot
      2. trivy client vm ebs:{snapshot_id} (no volume, no mount)
      3. Generate SBOM CycloneDX
      4. DeleteSnapshot (always in finally)
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)
    scan_job_id = start_discovery_job(db, tenant_id, "aws", provider_id, job_type="ec2")
    logger.info(
        "scan_ec2_instance_v2 start [tenant=%s instance=%s volume=%s job=%s]",
        tenant_id,
        instance_id,
        volume_id,
        scan_job_id,
    )

    session = _get_aws_session(
        role_arn=role_arn,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    ec2 = session.client("ec2", region_name=region)

    snapshot_id: str | None = None
    vulns: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    sbom_json: dict[str, Any] = {}

    try:
        # 1. Create and wait for snapshot
        snapshot_id = create_scan_snapshot(ec2, volume_id, tenant_id)
        wait_for_snapshot(ec2, snapshot_id)

        # 2. EBS Direct API scan — no volume creation, no mount
        vulns, secrets = run_trivy_ebs(snapshot_id, trivy_server_url=trivy_server_url)

        # 3. SBOM generation
        sbom_json = _generate_sbom(snapshot_id, trivy_server_url, scan_job_id)

    finally:
        # 4. Always delete snapshot (delete_snapshot_safe does not raise)
        if snapshot_id:
            delete_snapshot_safe(ec2, snapshot_id)
        complete_discovery_job(db, scan_job_id, len(vulns) + len(secrets))

    # 5. Normalise and persist findings
    rkey = resource_key or instance_id
    common = dict(
        tenant_id=tenant_id,
        resource_id=rkey,
        resource_arn=resource_arn,
        provider="aws",
        region=region,
        account_id=account_id,
        scan_job_id=scan_job_id,
    )
    findings: list[Finding] = []
    for v in vulns:
        findings.append(_normalise_cve_v2(v, **common, detection_method="ebs_direct"))
    for s in secrets:
        findings.append(_normalise_trivy_secret(s, **common, detection_method="trivy_secret"))

    for f in findings:
        try:
            _upsert_finding(db, f)
        except Exception:
            logger.exception("Failed to persist finding %s", f.check_id)

    # 6. Persist SBOM
    try:
        _persist_sbom(db, sbom_json, tenant_id, rkey, scan_job_id)
    except Exception:
        logger.exception("Failed to persist SBOM for instance=%s", instance_id)

    logger.info(
        "scan_ec2_instance_v2 complete [tenant=%s instance=%s findings=%d job=%s]",
        tenant_id,
        instance_id,
        len(findings),
        scan_job_id,
    )
    return {
        "job_id": scan_job_id,
        "instance_id": instance_id,
        "findings_count": len(findings),
        "cve_count": len(vulns),
        "secret_count": len(secrets),
        "sbom_components": len(sbom_json.get("components", [])),
    }


@celery_app.task(bind=True, max_retries=1, default_retry_delay=120, time_limit=900)
def scan_lambda_function(  # noqa: PLR0913
    self: Any,
    tenant_id: str,
    function_name: str,
    function_arn: str,
    provider_id: str,
    job_id: str,
    trivy_server_url: str = _TRIVY_SERVER_URL,
    region: str = "us-east-1",
    account_id: str = "",
    role_arn: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> dict[str, Any]:
    """
    Agentless Lambda scan via RAM disk:
      1. GetFunction → pre-signed URL
      2. Download ZIP to /dev/shm/ogum-{job_id}/
      3. trivy fs --scanners vuln,secret /dev/shm/ogum-{job_id}/code/
      4. Normalize findings → ArangoDB
      5. Cleanup RAM disk (always in finally)

    # TODO: image-based Lambda support (Sprint 3)
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)
    scan_job_id = start_discovery_job(db, tenant_id, "aws", provider_id, job_type="lambda")
    logger.info(
        "scan_lambda_function start [tenant=%s function=%s job=%s]",
        tenant_id,
        function_name,
        scan_job_id,
    )

    session = _get_aws_session(
        role_arn=role_arn,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )
    lambda_client = session.client("lambda", region_name=region)

    ram_dir = f"/dev/shm/ogum-{scan_job_id}"
    vulns: list[dict[str, Any]] = []

    try:
        # 1. Get pre-signed download URL
        func_info = lambda_client.get_function(FunctionName=function_arn)
        code_url: str = func_info["Code"]["Location"]

        # 2. Download ZIP to RAM disk
        os.makedirs(f"{ram_dir}/code", exist_ok=True)
        zip_path = f"{ram_dir}/function.zip"

        response = httpx.get(code_url, follow_redirects=True, timeout=120.0)
        response.raise_for_status()
        with open(zip_path, "wb") as fh:
            fh.write(response.content)

        # 3. Extract ZIP
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(f"{ram_dir}/code")

        # 4. Scan with trivy fs (Lambda uses local trivy, not EBS Direct)
        vulns = run_trivy_fs(f"{ram_dir}/code", timeout=600)

    finally:
        # 5. Always wipe RAM disk
        shutil.rmtree(ram_dir, ignore_errors=True)
        complete_discovery_job(db, scan_job_id, len(vulns))

    # 6. Normalise and persist
    resource_key = function_arn.replace("/", "_").replace(":", "_")
    findings: list[Finding] = []
    for v in vulns:
        f = Finding(
            finding_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            check_id=f"side_scanning/cve/{v.get('cve_id', 'NOID')}",
            title=(v.get("title") or f"{v.get('cve_id', 'NOID')} in {v.get('package', 'unknown')}")[:200],
            description=(v.get("description") or v.get("title") or "")[:500],
            resource_id=resource_key,
            resource_arn=function_arn,
            resource_type="lambda_function",
            severity=_trivy_severity(v.get("severity", "UNKNOWN"), v.get("cvss_score", 0.0)),
            status=FindingStatus.FAIL,
            provider="aws",
            region=region,
            account_id=account_id,
            source=FindingSource.SIDE_SCANNING,
            scan_job_id=scan_job_id,
            raw_output={
                "package": v.get("package", ""),
                "installed_version": v.get("installed_version", ""),
                "fixed_version": v.get("fixed_version", ""),
                "detection_method": "lambda_zip",
            },
        )
        findings.append(f)

    for f in findings:
        try:
            _upsert_finding(db, f)
        except Exception:
            logger.exception("Failed to persist Lambda finding %s", f.check_id)

    logger.info(
        "scan_lambda_function complete [tenant=%s function=%s findings=%d job=%s]",
        tenant_id,
        function_name,
        len(findings),
        scan_job_id,
    )
    return {
        "job_id": scan_job_id,
        "function_name": function_name,
        "findings_count": len(findings),
    }


@celery_app.task(bind=True, max_retries=1, default_retry_delay=60, time_limit=3600)
def rescan_sboms(
    self: Any,
    tenant_id: str,
    trivy_server_url: str = _TRIVY_SERVER_URL,
) -> dict[str, Any]:
    """
    Daily SBOM rescan: run trivy sbom against stored SBOMs to find new CVEs
    without creating new EBS snapshots.
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    try:
        cursor = db.aql.execute(
            "FOR s IN sboms FILTER s.tenant_id == @tid RETURN s",
            bind_vars={"tid": tenant_id},
        )
        sbom_docs: list[dict[str, Any]] = list(cursor)
    except Exception:
        logger.exception("Failed to query sboms for tenant=%s", tenant_id)
        return {"tenant_id": tenant_id, "sboms_scanned": 0, "new_findings": 0}

    sboms_scanned = 0
    new_findings = 0

    for sbom_doc in sbom_docs:
        sbom_key = sbom_doc.get("_key", "unknown")
        resource_id = sbom_doc.get("resource_id", sbom_key)
        content = sbom_doc.get("content")
        if not content:
            continue

        tmp_path = f"/tmp/sbom-{sbom_key}.cdx.json"  # noqa: S108
        try:
            with open(tmp_path, "w") as fh:
                json.dump(content, fh)

            result = subprocess.run(
                [
                    "trivy",
                    "client",
                    "--server",
                    trivy_server_url,
                    "sbom",
                    tmp_path,
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "--quiet",
                    "--no-progress",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode not in (0, 1) or not result.stdout.strip():
                logger.warning("trivy sbom returned %d for key=%s", result.returncode, sbom_key)
                continue

            data = json.loads(result.stdout)
            scan_job_id = f"rescan_{sbom_key}"

            for item in data.get("Results", []):
                for v in item.get("Vulnerabilities") or []:
                    cve_id = v.get("VulnerabilityID", "NOID")
                    finding = Finding(
                        finding_id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        check_id=f"side_scanning/cve/{cve_id}",
                        title=(v.get("Title") or f"{cve_id} in {v.get('PkgName', 'unknown')}")[:200],
                        description=(v.get("Description") or "")[:500],
                        resource_id=resource_id,
                        resource_type="sbom_component",
                        severity=_trivy_severity(v.get("Severity", "UNKNOWN"), 0.0),
                        status=FindingStatus.FAIL,
                        provider="aws",
                        region="",
                        account_id="",
                        source=FindingSource.SIDE_SCANNING,
                        scan_job_id=scan_job_id,
                        raw_output={
                            "package": v.get("PkgName", ""),
                            "installed_version": v.get("InstalledVersion", ""),
                            "fixed_version": v.get("FixedVersion", ""),
                            "detection_method": "sbom_rescan",
                        },
                    )
                    try:
                        _upsert_finding(db, finding)
                        new_findings += 1
                    except Exception:
                        logger.exception("Failed to persist rescan finding %s", cve_id)

            sboms_scanned += 1

        except Exception:
            logger.exception("SBOM rescan failed for key=%s", sbom_key)
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass

    logger.info(
        "rescan_sboms complete [tenant=%s sboms=%d new_findings=%d]",
        tenant_id,
        sboms_scanned,
        new_findings,
    )
    return {"tenant_id": tenant_id, "sboms_scanned": sboms_scanned, "new_findings": new_findings}


# ─── Sprint 3 helpers ─────────────────────────────────────────────────────────


def _generate_sbom_rootfs(rootfs_path: str, trivy_server_url: str, job_id: str) -> dict[str, Any]:
    """Generate CycloneDX SBOM for a container rootfs via trivy client. Returns empty dict on failure."""
    result = subprocess.run(
        [
            "trivy",
            "client",
            "--server",
            trivy_server_url,
            "rootfs",
            rootfs_path,
            "--format",
            "cyclonedx",
            "--quiet",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode not in (0, 1) or not result.stdout.strip():
        logger.warning("Rootfs SBOM generation returned %d for path=%s job=%s", result.returncode, rootfs_path, job_id)
        return {}
    try:
        return json.loads(result.stdout)  # type: ignore[no-any-return]
    except Exception:
        logger.exception("Failed to parse rootfs SBOM JSON for path=%s", rootfs_path)
        return {}


# ─── Sprint 3 task ────────────────────────────────────────────────────────────


@celery_app.task(bind=True, max_retries=1, default_retry_delay=120, time_limit=900)
def scan_k8s_container(  # noqa: PLR0913
    self: Any,
    tenant_id: str,
    pod_name: str,
    pod_namespace: str,
    container_name: str,
    pid: int,
    node_name: str,
    resource_id: str,
    provider_id: str,
    job_id: str,
    trivy_server_url: str = _TRIVY_SERVER_URL,
    host_proc_root: str = "/host/proc",
) -> dict[str, Any]:
    """
    Scan a running container's filesystem via /proc/<PID>/root (no pod restart).
    Runs inside the ogum-scanner DaemonSet pod on the same node as the target container.
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)
    # job_id is pre-created by the K8s webhook with type="k8s_container"; just flip to running
    scan_job_id = job_id
    update_job_to_running(db, scan_job_id)
    logger.info(
        "scan_k8s_container start [tenant=%s pod=%s/%s container=%s pid=%d job=%s]",
        tenant_id,
        pod_namespace,
        pod_name,
        container_name,
        pid,
        scan_job_id,
    )

    scan_path = f"{host_proc_root}/{pid}/root"
    vulns: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    sbom_json: dict[str, Any] = {}

    try:
        if not os.path.exists(scan_path):
            raise FileNotFoundError(f"Container proc root not found: {scan_path}")

        # 1. Scan rootfs via trivy client + sidecar
        vulns, secrets = run_trivy_rootfs(scan_path, trivy_server_url=trivy_server_url)

        # 2. SBOM generation
        sbom_json = _generate_sbom_rootfs(scan_path, trivy_server_url, scan_job_id)

    finally:
        complete_discovery_job(db, scan_job_id, len(vulns) + len(secrets))

    # 3. Normalise findings — resource_id is the ArangoDB _id of the Pod vertex
    resource_key = resource_id.replace("/", "_").replace(":", "_")
    findings: list[Finding] = []

    for v in vulns:
        findings.append(
            _normalise_cve_v2(
                v,
                tenant_id=tenant_id,
                resource_id=resource_key,
                resource_arn=None,
                provider="k8s",
                region=node_name,
                account_id="",
                scan_job_id=scan_job_id,
                detection_method="k8s_proc_root",
            )
        )

    for s in secrets:
        findings.append(
            _normalise_trivy_secret(
                s,
                tenant_id=tenant_id,
                resource_id=resource_key,
                resource_arn=None,
                provider="k8s",
                region=node_name,
                account_id="",
                scan_job_id=scan_job_id,
                resource_type="k8s_container",
                detection_method="trivy_secret_k8s",
            )
        )

    for f in findings:
        try:
            _upsert_finding(db, f)
        except Exception:
            logger.exception("Failed to persist K8s finding %s", f.check_id)

    # 4. Persist SBOM
    try:
        _persist_sbom(db, sbom_json, tenant_id, resource_key, scan_job_id)
    except Exception:
        logger.exception("Failed to persist SBOM for pod=%s/%s", pod_namespace, pod_name)

    logger.info(
        "scan_k8s_container complete [tenant=%s pod=%s/%s findings=%d job=%s]",
        tenant_id,
        pod_namespace,
        pod_name,
        len(findings),
        scan_job_id,
    )
    return {
        "job_id": scan_job_id,
        "pod": f"{pod_namespace}/{pod_name}",
        "container": container_name,
        "findings_count": len(findings),
        "cve_count": len(vulns),
        "secret_count": len(secrets),
        "sbom_components": len(sbom_json.get("components", [])),
    }


# ─── Sprint 4 helpers ─────────────────────────────────────────────────────────


def _generate_sarif(image_uri: str, image_digest: str, trivy_server_url: str) -> dict[str, Any]:
    """Generate SARIF report for CI/CD integration via trivy image --format sarif."""
    result = subprocess.run(
        [
            "trivy",
            "client",
            "--server",
            trivy_server_url,
            "image",
            f"{image_uri}@{image_digest}",
            "--format",
            "sarif",
            "--quiet",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode not in (0, 1) or not result.stdout.strip():
        logger.warning("SARIF generation returned %d for %s@%s", result.returncode, image_uri, image_digest[:16])
        return {}
    try:
        parsed: dict[str, Any] = json.loads(result.stdout)
        return parsed
    except Exception:
        logger.exception("Failed to parse SARIF JSON for %s", image_uri)
        return {}


def _persist_sarif(
    db: Any,
    sarif_json: dict[str, Any],
    tenant_id: str,
    image_uri: str,
    image_digest: str,
    job_id: str,
) -> None:
    """Upsert a SARIF report document in the sarif_reports collection."""
    if not sarif_json:
        return
    digest_key = image_digest.replace(":", "_").replace("/", "_")[:40]
    key = f"{tenant_id}_{digest_key}"[:240]
    doc = {
        "_key": key,
        "tenant_id": tenant_id,
        "image_uri": image_uri,
        "image_digest": image_digest,
        "format": "sarif",
        "content": sarif_json,
        "generated_at": datetime.now(UTC).isoformat(),
        "job_id": job_id,
    }
    _upsert(db, "sarif_reports", doc, {"generated_at": doc["generated_at"]})


def _normalise_misconfig(
    misconfig: dict[str, Any],
    *,
    tenant_id: str,
    resource_id: str,
    provider: str,
    region: str,
    account_id: str,
    scan_job_id: str,
    detection_method: str = "trivy_misconfig",
) -> Finding:
    """Normalise a Trivy misconfiguration dict into a Finding."""
    misconfig_id = misconfig.get("id", "UNKNOWN")
    check_id = f"misconfig/{misconfig_id}"
    severity = _trivy_severity(misconfig.get("severity", "UNKNOWN"), 0.0)
    title = misconfig.get("title") or f"Misconfiguration {misconfig_id}"
    description = misconfig.get("description") or title
    return Finding(
        finding_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        check_id=check_id,
        title=title[:200],
        description=description[:500],
        resource_id=resource_id,
        resource_type="container_image",
        severity=severity,
        status=FindingStatus.FAIL,
        provider=provider,
        region=region,
        account_id=account_id,
        source=FindingSource.SIDE_SCANNING,
        scan_job_id=scan_job_id,
        raw_output={
            "id": misconfig_id,
            "resolution": misconfig.get("resolution", ""),
            "references": misconfig.get("references", []),
            "target": misconfig.get("target", ""),
            "detection_method": detection_method,
        },
    )


# ─── Sprint 4 task ────────────────────────────────────────────────────────────


@celery_app.task(bind=True, max_retries=1, default_retry_delay=120, time_limit=1800)
def scan_container_image(  # noqa: PLR0913
    self: Any,
    tenant_id: str,
    image_uri: str,
    image_digest: str,
    provider_id: str,
    job_id: str,
    trivy_server_url: str = _TRIVY_SERVER_URL,
    scanners: str = "vuln,secret,misconfig",
    region: str = "",
    account_id: str = "",
) -> dict[str, Any]:
    """
    Scan a container image in ECR/registry via trivy image (no docker run).
    Generates findings and a SARIF report for CI/CD integration.
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)
    # job_id is pre-created by the ECR webhook with type="ecr"; just flip to running
    scan_job_id = job_id
    update_job_to_running(db, scan_job_id)
    logger.info(
        "scan_container_image start [tenant=%s image=%s digest=%s job=%s]",
        tenant_id,
        image_uri,
        image_digest[:16],
        scan_job_id,
    )

    vulns: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    misconfigs: list[dict[str, Any]] = []
    sarif_json: dict[str, Any] = {}

    try:
        # 1. Scan image — vuln + secret + misconfig
        vulns, secrets, misconfigs = run_trivy_image(
            image_uri,
            image_digest,
            trivy_server_url=trivy_server_url,
            scanners=scanners,
        )

        # 2. SARIF report for CI/CD
        sarif_json = _generate_sarif(image_uri, image_digest, trivy_server_url)

    finally:
        complete_discovery_job(db, scan_job_id, len(vulns) + len(secrets) + len(misconfigs))

    # 3. Normalise findings — resource_id is the image digest (stable across tags)
    resource_id = image_digest.replace(":", "_").replace("/", "_")[:120]
    findings: list[Finding] = []
    common = dict(
        tenant_id=tenant_id,
        resource_id=resource_id,
        resource_arn=f"{image_uri}@{image_digest}",
        provider=provider_id or "aws",
        region=region,
        account_id=account_id,
        scan_job_id=scan_job_id,
    )

    for v in vulns:
        findings.append(_normalise_cve_v2(v, **common, detection_method="registry_scan"))

    for s in secrets:
        findings.append(_normalise_trivy_secret(s, **common, detection_method="trivy_secret_registry"))

    for m in misconfigs:
        findings.append(
            _normalise_misconfig(
                m,
                tenant_id=tenant_id,
                resource_id=resource_id,
                provider=provider_id or "aws",
                region=region,
                account_id=account_id,
                scan_job_id=scan_job_id,
                detection_method="trivy_misconfig",
            )
        )

    for f in findings:
        try:
            _upsert_finding(db, f)
        except Exception:
            logger.exception("Failed to persist registry finding %s", f.check_id)

    # 4. Persist SARIF
    try:
        _persist_sarif(db, sarif_json, tenant_id, image_uri, image_digest, scan_job_id)
    except Exception:
        logger.exception("Failed to persist SARIF for %s", image_uri)

    logger.info(
        "scan_container_image complete [tenant=%s image=%s findings=%d job=%s]",
        tenant_id,
        image_uri,
        len(findings),
        scan_job_id,
    )
    return {
        "job_id": scan_job_id,
        "image_uri": image_uri,
        "digest": image_digest,
        "findings": len(findings),
        "cve_count": len(vulns),
        "secret_count": len(secrets),
        "misconfig_count": len(misconfigs),
    }
