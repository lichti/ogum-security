"""
Shared cloud/ArangoDB helpers used across scan and discovery tasks.

Split out of the former discovery.py (AWS-specific resource discovery, now
retired — inventory is built entirely from CSPM scan output, see
workers/tasks/cspm_scan.py) since these helpers are genuinely cross-cutting:
_get_aws_session is used by AWS credential validation and side-scanning,
_get_tenant_db/_upsert/_mark_stale_deleted/_set_provider_status are used by
every provider's discovery/scan task (AWS, Azure, GCP, K8s).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import boto3
from arango import ArangoClient

from app.core.config import settings
from app.models.inventory import ResourceStatus


def _get_aws_session(
    role_arn: str | None = None,
    external_id: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> boto3.Session:
    """Return a boto3 Session.

    Priority:
    1. STS AssumeRole when role_arn is provided (preferred — cross-account). The
       AssumeRole call itself is signed with aws_access_key_id/aws_secret_access_key
       when both are given — a base identity assuming into a target role, the same
       chain a static-key tenant_config with role_arn set represents. When neither
       key is given, the call falls back to ambient credentials (the production
       path: an EC2/ECS instance profile or IRSA identity assumes into the
       customer's role — nothing to chain from, since there's no static base
       identity to sign with).
    2. Static keys directly when aws_access_key_id + aws_secret_access_key are
       provided and no role_arn (dev only).
    3. Ambient credentials from the worker environment (instance profile / env vars).
    """
    if role_arn:
        sts_kwargs: dict[str, Any] = {"region_name": "us-east-1"}
        if aws_access_key_id and aws_secret_access_key:
            sts_kwargs["aws_access_key_id"] = aws_access_key_id
            sts_kwargs["aws_secret_access_key"] = aws_secret_access_key
        sts = boto3.client("sts", **sts_kwargs)
        assume_kwargs: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": "ogum-discovery",
            "DurationSeconds": 3600,
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id
        resp = sts.assume_role(**assume_kwargs)
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

    if aws_access_key_id and aws_secret_access_key:
        return boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )

    return boto3.Session()


def _set_provider_status(db: Any, provider_key: str | None, status: str) -> None:
    """Update provider discovery status in tenant_config (best-effort)."""
    if not provider_key:
        return
    try:
        if db.has_collection("tenant_config"):
            db.collection("tenant_config").update({"_key": provider_key, "status": status})
    except Exception:
        pass


def _get_tenant_db(tenant_id: str):  # type: ignore[no-untyped-def]
    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    return client.db(
        f"ogum_{tenant_id}",
        username=settings.ARANGO_USER,
        password=settings.ARANGO_PASSWORD,
    )


def _upsert(db: Any, collection: str, doc: dict[str, Any], update: dict[str, Any]) -> None:
    arn = doc.get("arn")
    if arn:
        # Search by ARN when present — handles key-format migrations gracefully and
        # avoids unique-constraint violations when legacy documents exist with the
        # same ARN but a different _key format.
        db.aql.execute(
            """
            UPSERT { arn: @arn }
            INSERT @doc
            UPDATE @update
            IN @@collection
            """,
            bind_vars={
                "@collection": collection,
                "arn": arn,
                "doc": doc,
                "update": update,
            },
        )
    else:
        db.aql.execute(
            """
            UPSERT { _key: @key }
            INSERT @doc
            UPDATE @update
            IN @@collection
            """,
            bind_vars={
                "@collection": collection,
                "key": doc["_key"],
                "doc": doc,
                "update": update,
            },
        )


def upsert_finding(db: Any, finding: Any) -> None:
    """Upsert a finding, tracking first/last-seen scan id and a re-scan counter.

    `first_seen_scan_id` is only ever written by the INSERT branch (never overwritten
    by the UPDATE branch), so it stays "when this finding was first detected" across
    every re-scan — the basis for the Timeline panel (Epic 14 US-14.10). `scan_count`
    guards against pre-migration documents that predate this field with `OLD.scan_count
    || 0` — undercounts by one on the first re-scan after upgrade, which is an accepted,
    self-correcting drift rather than a blocking backfill migration.
    """
    doc = finding.to_arango_doc()
    doc["first_seen_scan_id"] = finding.scan_job_id
    doc["last_seen_scan_id"] = finding.scan_job_id
    doc["scan_count"] = 1
    update = finding.to_arango_update()
    db.aql.execute(
        """
        UPSERT { _key: @key }
        INSERT @doc
        UPDATE {
            status: @update.status,
            severity: @update.severity,
            updated_at: @update.updated_at,
            framework_mapping: @update.framework_mapping,
            remediation: @update.remediation,
            remediation_code: @update.remediation_code,
            raw_output: @update.raw_output,
            last_seen_scan_id: @doc.last_seen_scan_id,
            scan_count: (OLD.scan_count || 0) + 1
        }
        IN findings
        """,
        bind_vars={"key": doc["_key"], "doc": doc, "update": update},
    )


def _mark_stale_deleted(
    db: Any,
    *,
    collection: str,
    tenant_id: str,
    provider: str,
    type_field: str,
    type_values: list[str],
    regions: list[str] | None,
    discovered_keys: set[str],
) -> int:
    """
    Soft-delete resources not seen in the current discovery run.

    Only affects the (provider, type_values, regions) scope that was scanned,
    so a partial discovery of us-east-1 does not delete resources in us-west-2.
    """
    now = datetime.now(UTC).isoformat()
    region_clause = "FILTER doc.region IN @regions" if regions is not None else ""
    bind_vars: dict[str, Any] = {
        "@collection": collection,
        "tenant_id": tenant_id,
        "provider": provider,
        "type_values": type_values,
        "deleted": ResourceStatus.DELETED.value,
        "discovered_keys": list(discovered_keys),
        "now": now,
    }
    if regions is not None:
        bind_vars["regions"] = regions

    # type_field is controlled by application code — not user input
    aql = f"""
    FOR doc IN @@collection
      FILTER doc.tenant_id == @tenant_id
      FILTER doc.provider == @provider
      FILTER doc.{type_field} IN @type_values
      {region_clause}
      FILTER doc.status != @deleted
      FILTER doc._key NOT IN @discovered_keys
      UPDATE doc WITH {{ status: @deleted, deleted_at: @now, updated_at: @now }}
      IN @@collection
      RETURN 1
    """
    cursor = db.aql.execute(aql, bind_vars=bind_vars)
    return sum(1 for _ in cursor)
