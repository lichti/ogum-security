"""
AWS discovery task — EC2 instances, IAM roles/users, S3 buckets.

boto3 calls are wrapped with exponential backoff to handle provider throttling.
ArangoDB upserts are idempotent: re-running discovery never duplicates resources.
Resources absent from the current scan are soft-deleted (status: "deleted").
"""
from __future__ import annotations

import functools
import logging
import random
import time
from datetime import datetime, timezone
from typing import Any

import boto3
from arango import ArangoClient
from botocore.exceptions import ClientError

from app.core.config import settings
from app.db.init import init_tenant_schema
from app.models.inventory import (
    AWSResource,
    DataAsset,
    Identity,
    IdentityType,
    Provider,
    ResourceStatus,
)
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

_RETRYABLE_CODES = frozenset({
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "ServiceUnavailable",
})


# ─── Retry decorator ──────────────────────────────────────────────────────────

def retry_with_backoff(
    max_retries: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
):
    """Decorator: exponential backoff with jitter on AWS throttling errors."""
    def decorator(func):  # type: ignore[no-untyped-def]
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code not in _RETRYABLE_CODES or attempt == max_retries - 1:
                        raise
                    delay = min(
                        base_delay * (2 ** attempt) + random.uniform(0, 1),
                        max_delay,
                    )
                    logger.warning(
                        "AWS throttle (%s) on %s, retry %d/%d in %.1fs",
                        code, func.__name__, attempt + 1, max_retries, delay,
                    )
                    time.sleep(delay)
            return None  # unreachable — satisfies mypy
        return wrapper
    return decorator


# ─── ArangoDB helpers ─────────────────────────────────────────────────────────

def _get_tenant_db(tenant_id: str):  # type: ignore[no-untyped-def]
    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    return client.db(
        f"ogum_{tenant_id}",
        username=settings.ARANGO_USER,
        password=settings.ARANGO_PASSWORD,
    )


def _upsert(db: Any, collection: str, doc: dict[str, Any], update: dict[str, Any]) -> None:
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
    now = datetime.now(timezone.utc).isoformat()
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


# ─── AWS discovery helpers ─────────────────────────────────────────────────────

@retry_with_backoff()
def _list_ec2_instances(ec2_client: Any, tenant_id: str, region: str) -> list[AWSResource]:
    instances: list[AWSResource] = []
    paginator = ec2_client.get_paginator("describe_instances")

    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            owner_id: str = reservation.get("OwnerId", "")
            for inst in reservation.get("Instances", []):
                instance_id: str = inst["InstanceId"]
                arn = f"arn:aws:ec2:{region}:{owner_id}:instance/{instance_id}"
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                instances.append(
                    AWSResource(
                        tenant_id=tenant_id,
                        resource_type="ec2_instance",
                        resource_id=instance_id,
                        name=tags.get("Name", instance_id),
                        arn=arn,
                        region=region,
                        account_id=owner_id or None,
                        tags=tags,
                        is_public=bool(inst.get("PublicIpAddress")),
                        raw_metadata={
                            "instance_type": inst.get("InstanceType"),
                            "state": inst.get("State", {}).get("Name"),
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "private_ip": inst.get("PrivateIpAddress"),
                            "public_ip": inst.get("PublicIpAddress"),
                            "security_groups": [
                                sg["GroupId"] for sg in inst.get("SecurityGroups", [])
                            ],
                            "iam_instance_profile": (
                                inst.get("IamInstanceProfile", {}) or {}
                            ).get("Arn"),
                        },
                    )
                )
    return instances


@retry_with_backoff()
def _list_iam_roles(iam_client: Any, tenant_id: str) -> list[Identity]:
    identities: list[Identity] = []
    paginator = iam_client.get_paginator("list_roles")

    for page in paginator.paginate():
        for role in page.get("Roles", []):
            identities.append(
                Identity(
                    tenant_id=tenant_id,
                    provider=Provider.AWS,
                    identity_type=IdentityType.IAM_ROLE,
                    name=role["RoleName"],
                    arn=role["Arn"],
                    raw_metadata={
                        "role_id": role.get("RoleId"),
                        "path": role.get("Path"),
                        "max_session_duration": role.get("MaxSessionDuration"),
                        "create_date": str(role.get("CreateDate", "")),
                    },
                )
            )
    return identities


@retry_with_backoff()
def _list_iam_users(iam_client: Any, tenant_id: str) -> list[Identity]:
    identities: list[Identity] = []
    paginator = iam_client.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page.get("Users", []):
            identities.append(
                Identity(
                    tenant_id=tenant_id,
                    provider=Provider.AWS,
                    identity_type=IdentityType.IAM_USER,
                    name=user["UserName"],
                    arn=user["Arn"],
                    raw_metadata={
                        "user_id": user.get("UserId"),
                        "path": user.get("Path"),
                        "create_date": str(user.get("CreateDate", "")),
                    },
                )
            )
    return identities


@retry_with_backoff()
def _list_s3_buckets(s3_client: Any, tenant_id: str) -> list[DataAsset]:
    assets: list[DataAsset] = []
    response = s3_client.list_buckets()

    for bucket in response.get("Buckets", []):
        name: str = bucket["Name"]
        try:
            loc = s3_client.get_bucket_location(Bucket=name)
            region = loc.get("LocationConstraint") or "us-east-1"
        except ClientError:
            region = "us-east-1"

        assets.append(
            DataAsset(
                tenant_id=tenant_id,
                provider=Provider.AWS,
                asset_type="s3_bucket",
                name=name,
                arn=f"arn:aws:s3:::{name}",
                raw_metadata={
                    "creation_date": str(bucket.get("CreationDate", "")),
                    "region": region,
                },
            )
        )
    return assets


# ─── Celery task ───────────────────────────────────────────────────────────────

@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def discover_aws_basic(
    self: Any,
    tenant_id: str,
    regions: list[str],
    account_id: str | None = None,
) -> dict[str, int | str]:
    """
    Discover EC2 instances, IAM roles/users, and S3 buckets for an AWS account.

    Args:
        tenant_id: Tenant identifier — selects the ArangoDB database.
        regions: AWS regions to scan for regional resources (e.g. EC2).
        account_id: Optional AWS account ID for logging; extracted from ARNs otherwise.
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    resource_keys: set[str] = set()
    identity_keys: set[str] = set()
    data_asset_keys: set[str] = set()

    # ── EC2 (per region) ─────────────────────────────────────────────────────
    for region in regions:
        ec2_client = boto3.client("ec2", region_name=region)
        instances = _list_ec2_instances(ec2_client, tenant_id, region)
        for resource in instances:
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())
        logger.info("EC2: %d instances discovered in %s [tenant=%s]", len(instances), region, tenant_id)

    # ── IAM (global) ─────────────────────────────────────────────────────────
    iam_client = boto3.client("iam", region_name="us-east-1")
    roles = _list_iam_roles(iam_client, tenant_id)
    users = _list_iam_users(iam_client, tenant_id)

    for identity in roles + users:
        _upsert(db, "identities", identity.to_arango_doc(), identity.to_arango_update())
        identity_keys.add(identity.arango_key())
    logger.info("IAM: %d identities discovered [tenant=%s]", len(roles) + len(users), tenant_id)

    # ── S3 (global) ──────────────────────────────────────────────────────────
    s3_client = boto3.client("s3", region_name="us-east-1")
    buckets = _list_s3_buckets(s3_client, tenant_id)

    for asset in buckets:
        _upsert(db, "data_assets", asset.to_arango_doc(), asset.to_arango_update())
        data_asset_keys.add(asset.arango_key())
    logger.info("S3: %d buckets discovered [tenant=%s]", len(buckets), tenant_id)

    # ── Soft-delete stale resources ───────────────────────────────────────────
    deleted_resources = _mark_stale_deleted(
        db,
        collection="resources",
        tenant_id=tenant_id,
        provider="aws",
        type_field="resource_type",
        type_values=["ec2_instance"],
        regions=regions,
        discovered_keys=resource_keys,
    )
    deleted_identities = _mark_stale_deleted(
        db,
        collection="identities",
        tenant_id=tenant_id,
        provider="aws",
        type_field="identity_type",
        type_values=["iam_role", "iam_user"],
        regions=None,
        discovered_keys=identity_keys,
    )
    deleted_assets = _mark_stale_deleted(
        db,
        collection="data_assets",
        tenant_id=tenant_id,
        provider="aws",
        type_field="asset_type",
        type_values=["s3_bucket"],
        regions=None,
        discovered_keys=data_asset_keys,
    )

    total_discovered = len(resource_keys) + len(identity_keys) + len(data_asset_keys)
    total_deleted = deleted_resources + deleted_identities + deleted_assets

    logger.info(
        "Discovery complete [tenant=%s]: discovered=%d deleted=%d",
        tenant_id, total_discovered, total_deleted,
    )

    return {
        "tenant_id": tenant_id,
        "discovered": total_discovered,
        "deleted": total_deleted,
        "ec2_count": len(resource_keys),
        "iam_count": len(identity_keys),
        "s3_count": len(data_asset_keys),
    }
