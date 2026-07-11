"""
Post-scan inventory extraction from Prowler v5 OutputFinding objects.

After a CSPM scan, every resource that had at least one check will appear
in the findings list (PASS or FAIL). This module deduplicates by resource_uid
and upserts into the appropriate ArangoDB inventory collection.

Collection routing:
  - identities   → IAM roles/users/groups, service accounts, Entra IDs
  - data_assets  → S3/Storage buckets, RDS/SQL databases, data stores
  - resources    → everything else (VMs, VPCs, K8s pods, EKS clusters, etc.)
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def _to_jsonable(obj: Any) -> Any:
    """Recursively convert Pydantic models and other non-serializable objects to plain Python types.

    Prowler v5 uses Pydantic v1 and stores service objects (e.g. Trail, Bucket)
    as values inside resource_metadata dicts. json.dumps raises TypeError for these.
    """
    if hasattr(obj, "model_dump"):  # Pydantic v2
        return _to_jsonable(obj.model_dump())
    if hasattr(obj, "__fields__") and hasattr(obj, "dict") and callable(obj.dict):  # Pydantic v1
        return _to_jsonable(obj.dict())
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_to_jsonable(item) for item in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, str | int | float | bool) or obj is None:
        return obj
    return str(obj)


# ---------------------------------------------------------------------------
# Collection routing heuristics (applied to the raw prowler ResourceType)
# ---------------------------------------------------------------------------

_IDENTITY_RE = re.compile(
    r"iam|identity|user|role|group|service.?account|principal|entra|"
    r"policy|access.?key|credential",
    re.IGNORECASE,
)

# For AWS specifically, the bare-word _IDENTITY_RE above false-positives on
# "Group"/"Role"/"Policy" as substrings of unrelated resource names — e.g.
# AwsEc2SecurityGroup, AwsAthenaWorkGroup, AwsAutoScalingAutoScalingGroup,
# AwsLogsLogGroup, AwsWafRuleGroup all contain "Group" but are not identities.
# AWS ResourceType strings always carry an explicit service prefix, so for
# "Aws*" types we route by service prefix instead of bare-word matching.
# Non-AWS providers don't consistently prefix by service in the same way, so
# they keep using the broader regex.
_AWS_IDENTITY_SERVICE_RE = re.compile(r"^Aws(Iam|RolesAnywhere)", re.IGNORECASE)

_DATA_ASSET_RE = re.compile(
    r"s3|bucket|storage|rds|db.?instance|database|sql|dynamo|cosmos|"
    r"blob|lake|warehouse|opensearch|elasticsearch|datastore|secrets.?manager|"
    r"kms|key.?vault|secret",
    re.IGNORECASE,
)


def _collection_for(raw_type: str) -> str:
    if raw_type.startswith("Aws"):
        if _AWS_IDENTITY_SERVICE_RE.search(raw_type):
            return "identities"
    elif _IDENTITY_RE.search(raw_type):
        return "identities"
    if _DATA_ASSET_RE.search(raw_type):
        return "data_assets"
    return "resources"


# ---------------------------------------------------------------------------
# ResourceType → snake_case name
# ---------------------------------------------------------------------------


def _camel_to_snake(name: str) -> str:
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower()


def _normalize_type_name(raw: str, provider: str) -> str:
    """Convert prowler ResourceType to a slug like ec2_instance, azure_vm, etc."""
    if not raw:
        return "unknown"

    if provider == "aws":
        # AwsEc2Instance → ec2_instance
        # AwsIamRole → iam_role
        s = re.sub(r"^Aws", "", raw)
        return _camel_to_snake(s).strip("_")

    if provider == "azure":
        # microsoft.compute/virtualmachines → azure_compute_virtualmachines
        s = raw.lower().replace("microsoft.", "").replace("/", "_").replace(".", "_")
        return f"azure_{s}"

    if provider == "gcp":
        # compute.googleapis.com/Instance → gcp_compute_instance
        m = re.match(r"([^.]+)\.googleapis\.com/(.+)", raw)
        if m:
            service = m.group(1).lower()
            kind = _camel_to_snake(m.group(2)).strip("_")
            return f"gcp_{service}_{kind}"
        return f"gcp_{_camel_to_snake(raw)}"

    if provider in ("kubernetes", "k8s"):
        # Pod, Deployment, DaemonSet → k8s_pod, k8s_deployment, k8s_daemon_set
        return f"k8s_{_camel_to_snake(raw)}"

    return raw.lower()


# ---------------------------------------------------------------------------
# Tag extraction
# ---------------------------------------------------------------------------


def _extract_tags(metadata: dict[str, Any]) -> dict[str, str]:
    raw = metadata.get("tags") or metadata.get("Tags") or metadata.get("labels") or []
    if isinstance(raw, list):
        tags = {}
        for tag in raw:
            if isinstance(tag, dict):
                k = tag.get("Key") or tag.get("key") or ""
                v = tag.get("Value") or tag.get("value") or ""
                if k:
                    tags[str(k)] = str(v)
        return tags
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {}


def _is_public(metadata: dict[str, Any]) -> bool:
    return bool(
        metadata.get("public_ip")
        or metadata.get("PublicIpAddress")
        or metadata.get("public_access")
        or metadata.get("is_public")
        or metadata.get("enable_internet_access")
        # prowler's VpcSubnet.public — already derived from route-table analysis
        # (0.0.0.0/0 route to an IGW), a more accurate signal than the
        # map_public_ip_on_launch flag native discovery used to rely on.
        or metadata.get("public")
    )


# ---------------------------------------------------------------------------
# identities: identity_type classification + relationship field extraction
#
# These fields mirror what app/models/inventory.py::Identity expects
# (identity_type, trust_policy, policies) so app/services/graph/iam_edges.py
# — which already reads those three fields straight off ArangoDB documents,
# with zero AWS API calls — works unmodified regardless of whether the
# identity was persisted by native discovery or by this extraction path.
# ---------------------------------------------------------------------------

_SERVICE_ACCOUNT_RE = re.compile(r"service.?account", re.IGNORECASE)
_GROUP_RE = re.compile(r"group", re.IGNORECASE)
_USER_RE = re.compile(r"user", re.IGNORECASE)


def _identity_type_for(raw_type: str) -> str:
    """Best-effort IdentityType classification from the raw prowler ResourceType.

    Order matters: service-account and group markers are checked before the
    more generic "role" fallback, which also catches types routed to
    `identities` by _IDENTITY_RE that aren't literally roles/users/groups
    (e.g. policies, access keys) — IAM_ROLE is the closest fit for those.
    """
    if _SERVICE_ACCOUNT_RE.search(raw_type):
        return "service_account"
    if _GROUP_RE.search(raw_type):
        return "iam_group"
    if _USER_RE.search(raw_type):
        return "iam_user"
    return "iam_role"


def _policy_arns(policies: Any) -> list[str]:
    """Flatten prowler's attached_policies ([{"PolicyArn": ...}, ...]) plus
    inline_policies (list[str] of names) into the flat list[str] Identity.policies
    and build_iam_edges expect."""
    arns: list[str] = []
    if isinstance(policies, list):
        for p in policies:
            if isinstance(p, dict):
                arn = p.get("PolicyArn") or p.get("Arn") or p.get("policy_arn")
                if arn:
                    arns.append(str(arn))
            elif isinstance(p, str):
                arns.append(p)
    return arns


def _member_arns(users: Any) -> list[str]:
    """Flatten prowler Group.users ([{"arn": ...}, ...] once serialized via .dict())
    into the flat list[str] graph/resource_edges.py expects for MEMBER_OF edges."""
    arns: list[str] = []
    if isinstance(users, list):
        for u in users:
            if isinstance(u, dict) and u.get("arn"):
                arns.append(str(u["arn"]))
    return arns


_ADMIN_POLICY_NAME_SUFFIXES = ("/AdministratorAccess", "/PowerUserAccess")


def _has_admin_policy(policy_arns: list[str]) -> bool:
    """Managed-policy admin heuristic ported from discovery.py's
    _classify_iam_role — matches by ARN suffix so it works for both AWS-managed
    and customer-managed policies.

    discovery.py additionally inspected inline policy *documents* for wildcard
    actions (iam:GetRolePolicy per inline policy) to catch admin access granted
    via inline policy rather than an attached managed policy. Prowler's Role
    model only carries inline_policies as a list[str] of names, not the policy
    document content, so that inline-policy wildcard detection has no
    equivalent here — accepted gap, same class as the other Prowler-metadata
    limitations in this module (see _extract_resource_relationships).
    """
    return any(arn.endswith(suffix) for arn in policy_arns for suffix in _ADMIN_POLICY_NAME_SUFFIXES)


def _extract_identity_fields(metadata: dict[str, Any]) -> dict[str, Any]:
    """trust_policy + policies + has_admin_policy for IAM roles/users/groups
    (prowler Role/User/Group models — see iam_service.py). Absent on types that
    don't carry these (e.g. an IAM access key resource routed here by
    _IDENTITY_RE) — fields simply omitted."""
    fields: dict[str, Any] = {}

    trust_policy = metadata.get("assume_role_policy")
    if isinstance(trust_policy, dict):
        fields["trust_policy"] = trust_policy

    policies = _policy_arns(metadata.get("attached_policies")) + [
        p for p in metadata.get("inline_policies") or [] if isinstance(p, str)
    ]
    if policies:
        fields["policies"] = policies
        fields["has_admin_policy"] = _has_admin_policy(policies)

    return fields


# ---------------------------------------------------------------------------
# resources: relationship field extraction for graph edge building
#
# app/services/graph/resource_edges.py reads these from resource.raw_metadata
# using the same field names discovery.py used to write — so switching the
# data source doesn't require changing the edge-building logic itself.
# ---------------------------------------------------------------------------


def _extract_resource_relationships(type_name: str, metadata: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}

    if type_name == "ec2_instance":
        if metadata.get("security_groups"):
            fields["security_groups"] = metadata["security_groups"]
        if metadata.get("subnet_id"):
            fields["subnet_id"] = metadata["subnet_id"]
        profile = metadata.get("instance_profile")
        if isinstance(profile, dict) and profile.get("Arn"):
            fields["iam_instance_profile"] = profile["Arn"]

    # Note: prowler has no InternetGateway resource model at all (verified against
    # prowler-core's vpc_service.py) — ROUTES_TRAFFIC (IGW -> VPC) edges can't be
    # derived from scan data the way native discovery's _list_internet_gateways
    # used to. Internet exposure is still captured via VpcSubnet.public (see
    # _is_public above), which is arguably a more accurate signal anyway.

    elif type_name == "lambda_function":
        # execution_role_arn isn't present on prowler's Function model at all —
        # ProwlerService._enrich_lambda_execution_roles fills it into
        # resource_metadata via a small targeted lambda:list_functions call
        # before extraction runs, so it's read here like any other field.
        if metadata.get("execution_role_arn"):
            fields["execution_role_arn"] = metadata["execution_role_arn"]
        if metadata.get("vpc_id"):
            fields["vpc_id"] = metadata["vpc_id"]
        if metadata.get("security_groups"):
            fields["security_groups"] = metadata["security_groups"]

    return fields


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resource_arango_key(resource_uid: str, tenant_id: str) -> str:
    return hashlib.sha256(f"{resource_uid}|{tenant_id}".encode()).hexdigest()


def extract_inventory_from_findings(
    findings: list[Any],
    tenant_id: str,
    provider: str,
    account_id: str,
) -> dict[str, list[dict[str, Any]]]:
    """
    Deduplicate and normalize resources from Prowler OutputFinding objects.

    Each unique resource_uid produces exactly one inventory document.
    Returns {"resources": [...], "identities": [...], "data_assets": [...]}.
    """
    now = datetime.now(UTC).isoformat()

    # uid → (collection, doc) — last finding wins for metadata (same resource)
    seen: dict[str, tuple[str, dict[str, Any]]] = {}

    for finding in findings:
        resource_uid = str(getattr(finding, "resource_uid", "") or "").strip()
        resource_name = str(getattr(finding, "resource_name", "") or "").strip()

        uid = resource_uid or resource_name
        if not uid or uid in seen:
            continue

        check_meta = getattr(finding, "metadata", None)
        raw_type = str(getattr(check_meta, "ResourceType", "") or "").strip() if check_meta else ""
        region = str(getattr(finding, "region", "") or "").strip() or None

        # For non-AWS providers, account_uid carries subscription/project ID
        result_account = str(getattr(finding, "account_uid", "") or "").strip()
        effective_account = result_account or account_id

        resource_metadata = getattr(finding, "resource_metadata", {})
        metadata_dict = _to_jsonable(resource_metadata) if resource_metadata else {}

        type_name = _normalize_type_name(raw_type, provider)
        collection = _collection_for(raw_type or type_name)

        arn = resource_uid if resource_uid.startswith("arn:") else None

        doc: dict[str, Any] = {
            "_key": resource_arango_key(uid, tenant_id),
            "tenant_id": tenant_id,
            "provider": "k8s" if provider == "kubernetes" else provider,
            "resource_id": uid,
            "name": resource_name or resource_uid,
            "arn": arn,
            "region": region,
            "account_id": effective_account,
            "status": "active",
            "is_public": _is_public(metadata_dict),
            "tags": _extract_tags(metadata_dict),
            "last_scanned_at": now,
            "updated_at": now,
        }

        if collection == "identities":
            # Identity model fields: identity_type, trust_policy, policies (all
            # top-level, not nested under raw_metadata) — matches what
            # graph/iam_edges.py::build_iam_edges reads.
            doc["identity_type"] = _identity_type_for(raw_type)
            doc.update(_extract_identity_fields(metadata_dict))
            # member_arns lives under raw_metadata (not a top-level Identity model
            # field) — graph/resource_edges.py reads it the same way discovery.py
            # used to for MEMBER_OF edges.
            member_arns = _member_arns(metadata_dict.get("users"))
            doc["raw_metadata"] = {**metadata_dict, "member_arns": member_arns} if member_arns else metadata_dict
        elif collection == "data_assets":
            # DataAsset model field is asset_type, not resource_type.
            doc["asset_type"] = type_name
            doc["raw_metadata"] = metadata_dict
        else:
            doc["resource_type"] = type_name
            doc["raw_metadata"] = {**metadata_dict, **_extract_resource_relationships(type_name, metadata_dict)}

        seen[uid] = (collection, doc)

    output: dict[str, list[dict[str, Any]]] = {
        "resources": [],
        "identities": [],
        "data_assets": [],
    }
    for _uid, (col, doc) in seen.items():
        bucket = output.get(col)
        if bucket is not None:
            bucket.append(doc)
        else:
            output["resources"].append(doc)

    logger.info(
        "Inventory extracted [provider=%s tenant=%s]: resources=%d identities=%d data_assets=%d",
        provider,
        tenant_id,
        len(output["resources"]),
        len(output["identities"]),
        len(output["data_assets"]),
    )
    return output
