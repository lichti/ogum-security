"""
AWS discovery tasks — full service coverage with relationship edges.

boto3 calls are wrapped with exponential backoff to handle provider throttling.
ArangoDB upserts are idempotent: re-running discovery never duplicates resources.
Resources absent from the current scan are soft-deleted (status: "deleted").
"""

from __future__ import annotations

import functools
import logging
import random
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from arango import ArangoClient
from botocore.exceptions import ClientError, NoCredentialsError

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
from app.workers.tasks._job_tracking import complete_discovery_job, fail_discovery_job, start_discovery_job

logger = logging.getLogger(__name__)

_RETRYABLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "ServiceUnavailable",
    }
)


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
                        base_delay * (2**attempt) + random.uniform(0, 1),
                        max_delay,
                    )
                    logger.warning(
                        "AWS throttle (%s) on %s, retry %d/%d in %.1fs",
                        code,
                        func.__name__,
                        attempt + 1,
                        max_retries,
                        delay,
                    )
                    time.sleep(delay)
            return None  # unreachable — satisfies mypy

        return wrapper

    return decorator


# ─── AWS session / credential helpers ────────────────────────────────────────


def _get_aws_session(
    role_arn: str | None = None,
    external_id: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> boto3.Session:
    """Return a boto3 Session.

    Priority:
    1. STS AssumeRole when role_arn is provided (preferred — cross-account)
    2. Static keys when aws_access_key_id + aws_secret_access_key are provided (dev only)
    3. Ambient credentials from the worker environment (instance profile / env vars)
    """
    if role_arn:
        sts = boto3.client("sts", region_name="us-east-1")
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


def _resolve_aws_regions(session: boto3.Session) -> list[str]:
    """Return all enabled regions for the given session/account."""
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
    return sorted(r["RegionName"] for r in resp["Regions"])


def _set_provider_status(db: Any, provider_key: str | None, status: str) -> None:
    """Update provider discovery status in tenant_config (best-effort)."""
    if not provider_key:
        return
    try:
        if db.has_collection("tenant_config"):
            db.collection("tenant_config").update({"_key": provider_key, "status": status})
    except Exception:
        pass


# ─── ArangoDB helpers ─────────────────────────────────────────────────────────


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


def _upsert_edge(
    db: Any,
    collection: str,
    from_id: str,
    to_id: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Idempotent edge upsert keyed on (_from, _to)."""
    now = datetime.now(UTC).isoformat()
    doc = {
        "_from": from_id,
        "_to": to_id,
        "created_at": now,
        "updated_at": now,
        **(extra or {}),
    }
    db.aql.execute(
        """
        UPSERT { _from: @from_id, _to: @to_id }
        INSERT @doc
        UPDATE { updated_at: @now }
        IN @@collection
        """,
        bind_vars={
            "@collection": collection,
            "from_id": from_id,
            "to_id": to_id,
            "doc": doc,
            "now": now,
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


# ─── Sprint 1: EC2, IAM, S3 discovery ────────────────────────────────────────


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
                            "security_groups": [sg["GroupId"] for sg in inst.get("SecurityGroups", [])],
                            "iam_instance_profile": (inst.get("IamInstanceProfile", {}) or {}).get("Arn"),
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


# ─── Sprint 2: expanded EC2/network/RDS/Lambda/EKS/ECR/KMS/SM/CT/IAM ────────


@retry_with_backoff()
def _list_vpcs(ec2_client: Any, tenant_id: str, account_id: str, region: str) -> list[AWSResource]:
    vpcs: list[AWSResource] = []
    paginator = ec2_client.get_paginator("describe_vpcs")

    for page in paginator.paginate():
        for vpc in page.get("Vpcs", []):
            vpc_id: str = vpc["VpcId"]
            tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            vpcs.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="vpc",
                    resource_id=vpc_id,
                    name=tags.get("Name", vpc_id),
                    arn=f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
                    region=region,
                    account_id=account_id or None,
                    tags=tags,
                    raw_metadata={
                        "cidr_block": vpc.get("CidrBlock"),
                        "is_default": vpc.get("IsDefault", False),
                        "state": vpc.get("State"),
                    },
                )
            )
    return vpcs


@retry_with_backoff()
def _list_subnets(ec2_client: Any, tenant_id: str, account_id: str, region: str) -> list[AWSResource]:
    subnets: list[AWSResource] = []
    paginator = ec2_client.get_paginator("describe_subnets")

    for page in paginator.paginate():
        for subnet in page.get("Subnets", []):
            subnet_id: str = subnet["SubnetId"]
            tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
            subnets.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="subnet",
                    resource_id=subnet_id,
                    name=tags.get("Name", subnet_id),
                    arn=f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}",
                    region=region,
                    account_id=account_id or None,
                    tags=tags,
                    raw_metadata={
                        "vpc_id": subnet.get("VpcId"),
                        "cidr_block": subnet.get("CidrBlock"),
                        "availability_zone": subnet.get("AvailabilityZone"),
                        "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
                    },
                )
            )
    return subnets


@retry_with_backoff()
def _list_internet_gateways(ec2_client: Any, tenant_id: str, account_id: str, region: str) -> list[AWSResource]:
    igws: list[AWSResource] = []
    paginator = ec2_client.get_paginator("describe_internet_gateways")

    for page in paginator.paginate():
        for igw in page.get("InternetGateways", []):
            igw_id: str = igw["InternetGatewayId"]
            tags = {t["Key"]: t["Value"] for t in igw.get("Tags", [])}
            attached_vpc_ids = [a["VpcId"] for a in igw.get("Attachments", []) if a.get("State") == "available"]
            igws.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="internet_gateway",
                    resource_id=igw_id,
                    name=tags.get("Name", igw_id),
                    arn=f"arn:aws:ec2:{region}:{account_id}:internet-gateway/{igw_id}",
                    region=region,
                    account_id=account_id or None,
                    tags=tags,
                    is_public=True,
                    raw_metadata={"attached_vpc_ids": attached_vpc_ids},
                )
            )
    return igws


@retry_with_backoff()
def _list_elastic_ips(ec2_client: Any, tenant_id: str, account_id: str, region: str) -> list[AWSResource]:
    eips: list[AWSResource] = []
    response = ec2_client.describe_addresses()

    for addr in response.get("Addresses", []):
        allocation_id = addr.get("AllocationId")
        if not allocation_id:
            continue  # classic EIP — skip
        eips.append(
            AWSResource(
                tenant_id=tenant_id,
                resource_type="elastic_ip",
                resource_id=allocation_id,
                name=addr.get("PublicIp", allocation_id),
                arn=f"arn:aws:ec2:{region}:{account_id}:elastic-ip/{allocation_id}",
                region=region,
                account_id=account_id or None,
                is_public=True,
                raw_metadata={
                    "public_ip": addr.get("PublicIp"),
                    "private_ip": addr.get("PrivateIpAddress"),
                    "instance_id": addr.get("InstanceId"),
                    "domain": addr.get("Domain"),
                },
            )
        )
    return eips


@retry_with_backoff()
def _list_security_groups(ec2_client: Any, tenant_id: str, account_id: str, region: str) -> list[AWSResource]:
    sgs: list[AWSResource] = []
    paginator = ec2_client.get_paginator("describe_security_groups")

    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            sg_id: str = sg["GroupId"]
            tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}

            ingress_rules = sg.get("IpPermissions", [])
            is_public = any(
                r.get("IpProtocol") == "-1"
                or any(
                    ip.get("CidrIp") == "0.0.0.0/0" or ip.get("CidrIpv6") == "::/0"
                    for ip in (r.get("IpRanges", []) + r.get("Ipv6Ranges", []))
                )
                for r in ingress_rules
            )

            sgs.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="security_group",
                    resource_id=sg_id,
                    name=sg.get("GroupName", sg_id),
                    arn=f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}",
                    region=region,
                    account_id=account_id or None,
                    tags=tags,
                    is_public=is_public,
                    raw_metadata={
                        "vpc_id": sg.get("VpcId"),
                        "description": sg.get("Description"),
                        "group_name": sg.get("GroupName"),
                        "ingress_rule_count": len(ingress_rules),
                        "egress_rule_count": len(sg.get("IpPermissionsEgress", [])),
                    },
                )
            )
    return sgs


@retry_with_backoff()
def _list_rds_instances(rds_client: Any, tenant_id: str, region: str) -> list[AWSResource]:
    instances: list[AWSResource] = []
    paginator = rds_client.get_paginator("describe_db_instances")

    for page in paginator.paginate():
        for db in page.get("DBInstances", []):
            arn: str = db["DBInstanceArn"]
            endpoint = db.get("Endpoint") or {}
            instances.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="rds_instance",
                    resource_id=db["DBInstanceIdentifier"],
                    name=db["DBInstanceIdentifier"],
                    arn=arn,
                    region=region,
                    is_public=bool(db.get("PubliclyAccessible")),
                    raw_metadata={
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "instance_class": db.get("DBInstanceClass"),
                        "multi_az": db.get("MultiAZ", False),
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "vpc_id": (db.get("DBSubnetGroup") or {}).get("VpcId"),
                        "endpoint": endpoint.get("Address"),
                        "status": db.get("DBInstanceStatus"),
                    },
                )
            )
    return instances


@retry_with_backoff()
def _list_lambda_functions(lambda_client: Any, tenant_id: str, region: str) -> list[AWSResource]:
    functions: list[AWSResource] = []
    paginator = lambda_client.get_paginator("list_functions")

    for page in paginator.paginate():
        for func in page.get("Functions", []):
            arn: str = func["FunctionArn"]
            vpc_config = func.get("VpcConfig") or {}
            functions.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="lambda_function",
                    resource_id=func["FunctionName"],
                    name=func["FunctionName"],
                    arn=arn,
                    region=region,
                    raw_metadata={
                        "execution_role_arn": func.get("Role"),
                        "runtime": func.get("Runtime"),
                        "memory_size": func.get("MemorySize"),
                        "timeout": func.get("Timeout"),
                        "handler": func.get("Handler"),
                        "vpc_id": vpc_config.get("VpcId"),
                        "vpc_security_group_ids": vpc_config.get("SecurityGroupIds", []),
                    },
                )
            )
    return functions


@retry_with_backoff()
def _list_eks_clusters(eks_client: Any, tenant_id: str, region: str) -> list[AWSResource]:
    clusters: list[AWSResource] = []
    paginator = eks_client.get_paginator("list_clusters")

    cluster_names: list[str] = []
    for page in paginator.paginate():
        cluster_names.extend(page.get("clusters", []))

    for name in cluster_names:
        try:
            detail = eks_client.describe_cluster(name=name)["cluster"]
        except ClientError:
            continue
        vpc_config = detail.get("resourcesVpcConfig") or {}
        clusters.append(
            AWSResource(
                tenant_id=tenant_id,
                resource_type="eks_cluster",
                resource_id=name,
                name=name,
                arn=detail.get("arn", f"arn:aws:eks:{region}::cluster/{name}"),
                region=region,
                is_public=bool(vpc_config.get("endpointPublicAccess", True)),
                raw_metadata={
                    "kubernetes_version": detail.get("version"),
                    "status": detail.get("status"),
                    "vpc_id": vpc_config.get("vpcId"),
                },
            )
        )
    return clusters


@retry_with_backoff()
def _list_ecr_repositories(ecr_client: Any, tenant_id: str, region: str) -> list[AWSResource]:
    repos: list[AWSResource] = []
    paginator = ecr_client.get_paginator("describe_repositories")

    for page in paginator.paginate():
        for repo in page.get("repositories", []):
            arn: str = repo["repositoryArn"]
            scan_config = repo.get("imageScanningConfiguration") or {}
            encrypt_config = repo.get("encryptionConfiguration") or {}
            repos.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="ecr_repository",
                    resource_id=repo["repositoryName"],
                    name=repo["repositoryName"],
                    arn=arn,
                    region=region,
                    raw_metadata={
                        "uri": repo.get("repositoryUri"),
                        "image_tag_mutability": repo.get("imageTagMutability"),
                        "scan_on_push": scan_config.get("scanOnPush", False),
                        "encryption_type": encrypt_config.get("encryptionType"),
                    },
                )
            )
    return repos


@retry_with_backoff()
def _list_kms_keys(kms_client: Any, tenant_id: str, region: str) -> list[AWSResource]:
    keys: list[AWSResource] = []
    paginator = kms_client.get_paginator("list_keys")

    for page in paginator.paginate():
        for key_ref in page.get("Keys", []):
            key_id: str = key_ref["KeyId"]
            try:
                meta = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in ("AccessDeniedException", "KMSInvalidStateException"):
                    continue
                raise
            if meta.get("KeyManager") == "AWS":
                continue  # skip AWS-managed keys
            keys.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="kms_key",
                    resource_id=key_id,
                    name=meta.get("Description") or key_id,
                    arn=meta["Arn"],
                    region=region,
                    raw_metadata={
                        "key_usage": meta.get("KeyUsage"),
                        "key_state": meta.get("KeyState"),
                        "key_manager": meta.get("KeyManager"),
                        "enabled": meta.get("Enabled", False),
                        "multi_region": meta.get("MultiRegion", False),
                    },
                )
            )
    return keys


@retry_with_backoff()
def _list_secrets_manager(sm_client: Any, tenant_id: str, region: str) -> list[AWSResource]:
    secrets: list[AWSResource] = []
    paginator = sm_client.get_paginator("list_secrets")

    for page in paginator.paginate():
        for secret in page.get("SecretList", []):
            arn: str = secret["ARN"]
            secrets.append(
                AWSResource(
                    tenant_id=tenant_id,
                    resource_type="secrets_manager_secret",
                    resource_id=secret["Name"],
                    name=secret["Name"],
                    arn=arn,
                    region=region,
                    raw_metadata={
                        "description": secret.get("Description"),
                        "rotation_enabled": secret.get("RotationEnabled", False),
                        "last_rotated": str(secret.get("LastRotatedDate", "")),
                        "last_accessed": str(secret.get("LastAccessedDate", "")),
                    },
                )
            )
    return secrets


@retry_with_backoff()
def _list_cloudtrail_trails(ct_client: Any, tenant_id: str, account_id: str, region: str) -> list[AWSResource]:
    trails: list[AWSResource] = []
    response = ct_client.describe_trails(includeShadowTrails=False)

    for trail in response.get("trailList", []):
        if trail.get("HomeRegion") != region:
            continue
        trail_arn: str = trail["TrailARN"]
        trails.append(
            AWSResource(
                tenant_id=tenant_id,
                resource_type="cloudtrail_trail",
                resource_id=trail["Name"],
                name=trail["Name"],
                arn=trail_arn,
                region=region,
                raw_metadata={
                    "is_multi_region": trail.get("IsMultiRegionTrail", False),
                    "log_bucket": trail.get("S3BucketName"),
                    "include_global_service_events": trail.get("IncludeGlobalServiceEvents", False),
                },
            )
        )
    return trails


@retry_with_backoff()
def _list_iam_groups(iam_client: Any, tenant_id: str) -> list[Identity]:
    groups: list[Identity] = []
    paginator = iam_client.get_paginator("list_groups")

    for page in paginator.paginate():
        for group in page.get("Groups", []):
            group_name: str = group["GroupName"]
            member_arns: list[str] = []

            # Paginate through get_group to collect all members
            marker: str | None = None
            while True:
                kwargs: dict[str, Any] = {"GroupName": group_name}
                if marker:
                    kwargs["Marker"] = marker
                detail = iam_client.get_group(**kwargs)
                member_arns.extend(u["Arn"] for u in detail.get("Users", []))
                if not detail.get("IsTruncated"):
                    break
                marker = detail.get("Marker")

            groups.append(
                Identity(
                    tenant_id=tenant_id,
                    provider=Provider.AWS,
                    identity_type=IdentityType.IAM_GROUP,
                    name=group_name,
                    arn=group["Arn"],
                    raw_metadata={
                        "group_id": group.get("GroupId"),
                        "path": group.get("Path"),
                        "member_arns": member_arns,
                    },
                )
            )
    return groups


# ─── Relationship edge creation ───────────────────────────────────────────────


def _create_resource_edges(
    db: Any,
    *,
    tenant_id: str,
    ec2_resources: list[AWSResource],
    igw_resources: list[AWSResource],
    lambda_resources: list[AWSResource],
    vpc_key_map: dict[str, str],
    sg_key_map: dict[str, str],
    role_key_map: dict[str, str],
    iam_groups: list[Identity],
    user_arn_to_key: dict[str, str],
) -> int:
    """Create all relationship edges discovered during this scan run."""
    count = 0
    extra = {"tenant_id": tenant_id}

    for ec2 in ec2_resources:
        ec2_handle = f"resources/{ec2.arango_key()}"

        # BELONGS_TO: EC2 → VPC
        vpc_id = ec2.raw_metadata.get("vpc_id")
        if vpc_id and vpc_id in vpc_key_map:
            _upsert_edge(db, "BELONGS_TO", ec2_handle, f"resources/{vpc_key_map[vpc_id]}", extra)
            count += 1

        # ATTACHED_TO: SG → EC2
        for sg_id in ec2.raw_metadata.get("security_groups", []):
            if sg_id in sg_key_map:
                _upsert_edge(db, "ATTACHED_TO", f"resources/{sg_key_map[sg_id]}", ec2_handle, extra)
                count += 1

        # ASSUMES_ROLE: EC2 → IAM Role (via instance profile, same-name heuristic)
        profile_arn = ec2.raw_metadata.get("iam_instance_profile")
        if profile_arn:
            profile_name = profile_arn.rstrip("/").split("/")[-1]
            if profile_name in role_key_map:
                _upsert_edge(
                    db,
                    "ASSUMES_ROLE",
                    ec2_handle,
                    f"identities/{role_key_map[profile_name]}",
                    extra,
                )
                count += 1

    # ROUTES_TRAFFIC: IGW → VPC
    for igw in igw_resources:
        igw_handle = f"resources/{igw.arango_key()}"
        for vpc_id in igw.raw_metadata.get("attached_vpc_ids", []):
            if vpc_id in vpc_key_map:
                _upsert_edge(
                    db,
                    "ROUTES_TRAFFIC",
                    igw_handle,
                    f"resources/{vpc_key_map[vpc_id]}",
                    extra,
                )
                count += 1

    # ASSUMES_ROLE: Lambda → IAM Role (execution role)
    for lam in lambda_resources:
        lam_handle = f"resources/{lam.arango_key()}"
        role_arn = lam.raw_metadata.get("execution_role_arn")
        if role_arn:
            role_name = role_arn.rstrip("/").split("/")[-1]
            if role_name in role_key_map:
                _upsert_edge(
                    db,
                    "ASSUMES_ROLE",
                    lam_handle,
                    f"identities/{role_key_map[role_name]}",
                    extra,
                )
                count += 1

    # MEMBER_OF: IAM User → IAM Group
    for group in iam_groups:
        group_handle = f"identities/{group.arango_key()}"
        for user_arn in group.raw_metadata.get("member_arns", []):
            if user_arn in user_arn_to_key:
                _upsert_edge(
                    db,
                    "MEMBER_OF",
                    f"identities/{user_arn_to_key[user_arn]}",
                    group_handle,
                    extra,
                )
                count += 1

    return count


# ─── Celery tasks ──────────────────────────────────────────────────────────────


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

    if not regions:
        regions = _resolve_aws_regions(boto3.Session())
        logger.info("discover_aws_basic: no regions specified — scanning all %d enabled regions", len(regions))

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
        tenant_id,
        total_discovered,
        total_deleted,
    )

    return {
        "tenant_id": tenant_id,
        "discovered": total_discovered,
        "deleted": total_deleted,
        "ec2_count": len(resource_keys),
        "iam_count": len(identity_keys),
        "s3_count": len(data_asset_keys),
    }


_ALL_RESOURCE_TYPES = [
    "ec2_instance",
    "vpc",
    "subnet",
    "internet_gateway",
    "elastic_ip",
    "security_group",
    "rds_instance",
    "lambda_function",
    "eks_cluster",
    "ecr_repository",
    "kms_key",
    "secrets_manager_secret",
    "cloudtrail_trail",
]


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def discover_aws(
    self: Any,
    tenant_id: str,
    regions: list[str],
    account_id: str | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
    provider_key: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> dict[str, int | str]:
    """
    Full AWS discovery: all services + relationship edges.

    Supersedes discover_aws_basic with complete coverage of EC2 networking,
    RDS, Lambda, EKS, ECR, KMS, Secrets Manager, CloudTrail, and IAM groups.
    Creates BELONGS_TO, ATTACHED_TO, ROUTES_TRAFFIC, ASSUMES_ROLE, and MEMBER_OF edges.

    Args:
        tenant_id: Tenant identifier — selects the ArangoDB database.
        regions: AWS regions to scan for regional resources.
        account_id: AWS account ID; resolved via STS if not provided.
        role_arn: Cross-account IAM Role ARN to assume (preferred credential model).
        external_id: External ID for the AssumeRole call (confused deputy protection).
        provider_key: ArangoDB key of the provider config for status updates.
        aws_access_key_id: Static access key (dev only — never stored in ArangoDB).
        aws_secret_access_key: Static secret key (dev only — never stored in ArangoDB).
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    _job_id = start_discovery_job(db, tenant_id, "aws", provider_key, regions)

    logger.info(
        "discover_aws start [tenant=%s regions=%s account_id=%s has_role_arn=%s has_static_keys=%s]",
        tenant_id,
        regions,
        account_id,
        bool(role_arn),
        bool(aws_access_key_id and aws_secret_access_key),
    )

    try:
        session = _get_aws_session(
            role_arn,
            external_id,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        sts = session.client("sts", region_name="us-east-1")
        # Always call STS to validate credentials — even when account_id is already known.
        # This ensures NoCredentialsError is caught here, not mid-discovery inside _list_vpcs.
        resolved = sts.get_caller_identity().get("Account", "")
        if not account_id:
            account_id = resolved
    except NoCredentialsError:
        logger.error(
            "AWS discovery failed [tenant=%s]: no credentials. "
            "role_arn=%s static_keys=%s ambient=False. "
            "Options: (1) provide role_arn when registering the provider, "
            "(2) provide aws_access_key_id + aws_secret_access_key in the wizard, "
            "(3) set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in the worker environment.",
            tenant_id,
            bool(role_arn),
            bool(aws_access_key_id and aws_secret_access_key),
        )
        _set_provider_status(db, provider_key, "error")
        fail_discovery_job(db, _job_id, "no_credentials")
        return {"status": "failed", "reason": "no_credentials", "resources": 0}
    except ClientError as exc:
        if "AccessDenied" in str(exc) or "InvalidClientTokenId" in str(exc):
            logger.error("AWS discovery failed for tenant %s: %s", tenant_id, exc)
            _set_provider_status(db, provider_key, "error")
            fail_discovery_job(db, _job_id, str(exc))
            return {"status": "failed", "reason": str(exc), "resources": 0}
        account_id = account_id or ""

    if not regions:
        regions = _resolve_aws_regions(session)
        logger.info("discover_aws: no regions specified — scanning all %d enabled regions", len(regions))

    resource_keys: set[str] = set()
    identity_keys: set[str] = set()
    data_asset_keys: set[str] = set()

    # Lookup maps for edge creation (built during vertex discovery)
    vpc_key_map: dict[str, str] = {}
    sg_key_map: dict[str, str] = {}
    role_key_map: dict[str, str] = {}
    user_arn_to_key: dict[str, str] = {}

    # Cross-region resource lists needed for edge creation
    all_ec2: list[AWSResource] = []
    all_igw: list[AWSResource] = []
    all_lambda: list[AWSResource] = []

    for region in regions:
        ec2_client = session.client("ec2", region_name=region)
        rds_client = session.client("rds", region_name=region)
        lambda_client = session.client("lambda", region_name=region)
        eks_client = session.client("eks", region_name=region)
        ecr_client = session.client("ecr", region_name=region)
        kms_client = session.client("kms", region_name=region)
        sm_client = session.client("secretsmanager", region_name=region)
        ct_client = session.client("cloudtrail", region_name=region)

        for resource in _list_vpcs(ec2_client, tenant_id, account_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())
            vpc_key_map[resource.resource_id] = resource.arango_key()

        for resource in _list_subnets(ec2_client, tenant_id, account_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        igws = _list_internet_gateways(ec2_client, tenant_id, account_id, region)
        for resource in igws:
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())
        all_igw.extend(igws)

        for resource in _list_elastic_ips(ec2_client, tenant_id, account_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        sgs = _list_security_groups(ec2_client, tenant_id, account_id, region)
        for resource in sgs:
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())
            sg_key_map[resource.resource_id] = resource.arango_key()

        instances = _list_ec2_instances(ec2_client, tenant_id, region)
        for resource in instances:
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())
        all_ec2.extend(instances)

        for resource in _list_rds_instances(rds_client, tenant_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        lambdas = _list_lambda_functions(lambda_client, tenant_id, region)
        for resource in lambdas:
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())
        all_lambda.extend(lambdas)

        for resource in _list_eks_clusters(eks_client, tenant_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_ecr_repositories(ecr_client, tenant_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_kms_keys(kms_client, tenant_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_secrets_manager(sm_client, tenant_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_cloudtrail_trails(ct_client, tenant_id, account_id, region):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        logger.info(
            "Region %s complete: %d resources [tenant=%s]",
            region,
            len(resource_keys),
            tenant_id,
        )

    # ── IAM (global) ─────────────────────────────────────────────────────────
    iam_client = session.client("iam", region_name="us-east-1")

    roles = _list_iam_roles(iam_client, tenant_id)
    for identity in roles:
        _upsert(db, "identities", identity.to_arango_doc(), identity.to_arango_update())
        identity_keys.add(identity.arango_key())
        role_key_map[identity.name] = identity.arango_key()

    users = _list_iam_users(iam_client, tenant_id)
    for identity in users:
        _upsert(db, "identities", identity.to_arango_doc(), identity.to_arango_update())
        identity_keys.add(identity.arango_key())
        user_arn_to_key[identity.arn] = identity.arango_key()

    iam_groups = _list_iam_groups(iam_client, tenant_id)
    for identity in iam_groups:
        _upsert(db, "identities", identity.to_arango_doc(), identity.to_arango_update())
        identity_keys.add(identity.arango_key())

    logger.info(
        "IAM: %d roles, %d users, %d groups [tenant=%s]",
        len(roles),
        len(users),
        len(iam_groups),
        tenant_id,
    )

    # ── S3 (global) ──────────────────────────────────────────────────────────
    s3_client = session.client("s3", region_name="us-east-1")
    buckets = _list_s3_buckets(s3_client, tenant_id)
    for asset in buckets:
        _upsert(db, "data_assets", asset.to_arango_doc(), asset.to_arango_update())
        data_asset_keys.add(asset.arango_key())

    # ── Relationship edges ────────────────────────────────────────────────────
    total_edges = _create_resource_edges(
        db,
        tenant_id=tenant_id,
        ec2_resources=all_ec2,
        igw_resources=all_igw,
        lambda_resources=all_lambda,
        vpc_key_map=vpc_key_map,
        sg_key_map=sg_key_map,
        role_key_map=role_key_map,
        iam_groups=iam_groups,
        user_arn_to_key=user_arn_to_key,
    )

    # ── Soft-delete stale resources ───────────────────────────────────────────
    deleted_resources = _mark_stale_deleted(
        db,
        collection="resources",
        tenant_id=tenant_id,
        provider="aws",
        type_field="resource_type",
        type_values=_ALL_RESOURCE_TYPES,
        regions=regions,
        discovered_keys=resource_keys,
    )
    deleted_identities = _mark_stale_deleted(
        db,
        collection="identities",
        tenant_id=tenant_id,
        provider="aws",
        type_field="identity_type",
        type_values=["iam_role", "iam_user", "iam_group"],
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
        "Full discovery complete [tenant=%s]: discovered=%d deleted=%d edges=%d",
        tenant_id,
        total_discovered,
        total_deleted,
        total_edges,
    )

    _set_provider_status(db, provider_key, "active")
    complete_discovery_job(db, _job_id, total_discovered)

    return {
        "tenant_id": tenant_id,
        "discovered": total_discovered,
        "deleted": total_deleted,
        "edges": total_edges,
        "resource_count": len(resource_keys),
        "identity_count": len(identity_keys),
        "data_asset_count": len(data_asset_keys),
    }
