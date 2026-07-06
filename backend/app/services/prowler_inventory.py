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


# ---------------------------------------------------------------------------
# Collection routing heuristics (applied to the raw prowler ResourceType)
# ---------------------------------------------------------------------------

_IDENTITY_RE = re.compile(
    r"iam|identity|user|role|group|service.?account|principal|entra|"
    r"policy|access.?key|credential",
    re.IGNORECASE,
)

_DATA_ASSET_RE = re.compile(
    r"s3|bucket|storage|rds|db.?instance|database|sql|dynamo|cosmos|"
    r"blob|lake|warehouse|opensearch|elasticsearch|datastore|secrets.?manager|"
    r"kms|key.?vault|secret",
    re.IGNORECASE,
)


def _collection_for(raw_type: str) -> str:
    if _IDENTITY_RE.search(raw_type):
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
    raw = (
        metadata.get("tags")
        or metadata.get("Tags")
        or metadata.get("labels")
        or []
    )
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
    )


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

    for result in findings:
        resource_uid = str(getattr(result, "resource_uid", "") or "").strip()
        resource_name = str(getattr(result, "resource_name", "") or "").strip()

        uid = resource_uid or resource_name
        if not uid or uid in seen:
            continue

        check_meta = getattr(result, "metadata", None)
        raw_type = str(getattr(check_meta, "ResourceType", "") or "").strip() if check_meta else ""
        region = str(getattr(result, "region", "") or "").strip() or None

        # For non-AWS providers, account_uid carries subscription/project ID
        result_account = str(getattr(result, "account_uid", "") or "").strip()
        effective_account = result_account or account_id

        resource_metadata = getattr(result, "resource_metadata", {})
        metadata_dict = resource_metadata if isinstance(resource_metadata, dict) else {}

        type_name = _normalize_type_name(raw_type, provider)
        collection = _collection_for(raw_type or type_name)

        arn = resource_uid if resource_uid.startswith("arn:") else None

        seen[uid] = (
            collection,
            {
                "_key": resource_arango_key(uid, tenant_id),
                "tenant_id": tenant_id,
                "provider": "k8s" if provider == "kubernetes" else provider,
                "resource_type": type_name,
                "resource_id": uid,
                "name": resource_name or resource_uid,
                "arn": arn,
                "region": region,
                "account_id": effective_account,
                "status": "active",
                "is_public": _is_public(metadata_dict),
                "tags": _extract_tags(metadata_dict),
                "raw_metadata": metadata_dict,
                "last_scanned_at": now,
                "updated_at": now,
            },
        )

    result: dict[str, list[dict[str, Any]]] = {
        "resources": [],
        "identities": [],
        "data_assets": [],
    }
    for uid, (col, doc) in seen.items():
        result.get(col, result["resources"]).append(doc)

    logger.info(
        "Inventory extracted [provider=%s tenant=%s]: resources=%d identities=%d data_assets=%d",
        provider,
        tenant_id,
        len(result["resources"]),
        len(result["identities"]),
        len(result["data_assets"]),
    )
    return result
