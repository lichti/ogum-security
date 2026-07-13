"""
Enqueue side-scanning tasks for EC2/Lambda resources.

Shared by the manual "Scan Now" trigger (app/api/v1/side_scans.py), its retry
path, and the automatic first-seen hook in run_cspm_scan
(app/workers/tasks/cspm_scan.py) — a single place decides how a resources/
document turns into a scan_jobs record + enqueued Celery task, so all three
callers stay consistent.
"""

from __future__ import annotations

import time
from typing import Any

from arango.database import StandardDatabase

from app.services.side_scanning.ec2_metadata import resolve_ec2_scan_metadata
from app.workers.tasks.cloud_utils import _get_aws_session
from app.workers.tasks.side_scanning import scan_ec2_instance_v2, scan_lambda_function

SCANNABLE_RESOURCE_TYPES = frozenset({"ec2_instance", "lambda_function"})


def _extract_instance_id(resource_doc: dict[str, Any]) -> str | None:
    """EC2 ARNs are arn:aws:ec2:{region}:{account}:instance/{id} — "instance/" is
    preceded by a colon (the account-id field separator), not a slash. Prowler
    also reports account-level check results tagged as ec2_instance
    (resource_type misclassification, out of scope here) — those ARNs have no
    ":instance/" segment and must be rejected, not passed to describe_instances."""
    arn = resource_doc.get("arn") or ""
    if ":instance/" not in arn:
        return None
    return arn.rsplit("/", 1)[-1]


def _extract_function_name(resource_doc: dict[str, Any]) -> str | None:
    arn = resource_doc.get("arn") or ""
    if ":function:" not in arn:
        return None
    return arn.rsplit(":", 1)[-1]


def _insert_job_doc(db: StandardDatabase, job_doc: dict[str, Any]) -> None:
    try:
        if not db.collection("scan_jobs").has(job_doc["_key"]):
            db.collection("scan_jobs").insert(job_doc)
    except Exception:
        pass  # key collision acceptable


def has_prior_side_scan(db: StandardDatabase, tenant_id: str, resource_key: str) -> bool:
    """True if this resource has ever had an ec2/lambda scan_jobs entry, any status."""
    try:
        cursor = db.aql.execute(
            "FOR j IN scan_jobs FILTER j.tenant_id == @tid AND j.resource_id == @rid "
            'AND j.type IN ["ec2", "lambda"] LIMIT 1 RETURN 1',
            bind_vars={"tid": tenant_id, "rid": resource_key},
        )
        return len(list(cursor)) > 0
    except Exception:
        # Fail closed on the side of not re-triggering — an auto-trigger storm
        # from a transient query error is worse than a missed first-seen scan.
        return True


def enqueue_side_scan(
    db: StandardDatabase,
    tenant_id: str,
    resource_doc: dict[str, Any],
    provider_id: str,
    credentials: dict[str, Any],
) -> str | None:
    """
    Create a scan_jobs record and enqueue the matching side-scanning task for an
    EC2 instance or Lambda function resource. Returns the new job_id, or None if
    the resource isn't a scannable/currently-scannable EC2 or Lambda resource
    (wrong resource_type, malformed ARN, or the EC2 instance no longer exists /
    has no attached volume per a live describe_instances lookup).
    """
    resource_type = resource_doc.get("resource_type")
    resource_key = resource_doc["_key"]
    region = resource_doc.get("region") or "us-east-1"
    account_id = resource_doc.get("account_id") or ""
    arn = resource_doc.get("arn")
    role_arn = credentials.get("role_arn")
    external_id = credentials.get("external_id")
    aws_access_key_id = credentials.get("aws_access_key_id")
    aws_secret_access_key = credentials.get("aws_secret_access_key")

    job_id = f"{resource_type}-{resource_key}-{int(time.time())}"

    if resource_type == "ec2_instance":
        instance_id = _extract_instance_id(resource_doc)
        if not instance_id:
            return None

        session = _get_aws_session(
            role_arn=role_arn,
            external_id=external_id,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        ec2_client = session.client("ec2", region_name=region)
        instance_meta = resolve_ec2_scan_metadata(ec2_client, [instance_id]).get(instance_id)
        if not instance_meta:
            return None

        _insert_job_doc(
            db,
            {
                "_key": job_id,
                "job_id": job_id,
                "tenant_id": tenant_id,
                "type": "ec2",
                "task_name": "side_scan/ec2",
                "provider": "aws",
                "status": "queued",
                "resource_id": resource_key,
                "provider_id": provider_id,
                "created_at": str(int(time.time())),
            },
        )
        scan_ec2_instance_v2.delay(
            tenant_id=tenant_id,
            instance_id=instance_id,
            volume_id=instance_meta["volume_id"],
            provider_id=provider_id,
            job_id=job_id,
            region=region,
            account_id=account_id,
            resource_key=resource_key,
            availability_zone=instance_meta["availability_zone"],
            resource_arn=arn,
            role_arn=role_arn,
            external_id=external_id,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        return job_id

    if resource_type == "lambda_function":
        function_name = _extract_function_name(resource_doc)
        if not function_name:
            return None

        _insert_job_doc(
            db,
            {
                "_key": job_id,
                "job_id": job_id,
                "tenant_id": tenant_id,
                "type": "lambda",
                "task_name": "side_scan/lambda",
                "provider": "aws",
                "status": "queued",
                "resource_id": resource_key,
                "provider_id": provider_id,
                "created_at": str(int(time.time())),
            },
        )
        scan_lambda_function.delay(
            tenant_id=tenant_id,
            function_name=function_name,
            function_arn=arn or "",
            provider_id=provider_id,
            job_id=job_id,
            region=region,
            account_id=account_id,
            role_arn=role_arn,
            external_id=external_id,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        return job_id

    return None
