"""
Resource Graph Edges — build BELONGS_TO, ATTACHED_TO, ASSUMES_ROLE (EC2 and
Lambda), and MEMBER_OF edges from metadata already persisted in the
`resources`/`identities` collections.

No new AWS API calls are made — everything is derived from `raw_metadata`
fields written by prowler_inventory.py during CSPM inventory extraction.
Mirrors the DB-driven pattern in graph/iam_edges.py.

Known limitations (accepted — see the Prowler-as-source-of-truth plan):
  - ROUTES_TRAFFIC (Internet Gateway -> VPC) cannot be derived: prowler-core
    has no InternetGateway resource model. VpcSubnet.public is used as an
    exposure signal elsewhere instead.
  - EC2 instance-profile -> role resolution is name-based only (profile name
    == role name). The old discovery.py resolved mismatched names via a live
    iam:ListInstanceProfiles call; that live lookup is not reintroduced here.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _edge_key(from_id: str, to_id: str, edge_type: str) -> str:
    raw = f"{edge_type}|{from_id}|{to_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _raw_aws_id(arn: str | None) -> str | None:
    """Extract the trailing AWS resource id (e.g. 'vpc-0123') from an ARN of
    the form arn:aws:ec2:region:account:vpc/vpc-0123."""
    if not arn or "/" not in arn:
        return None
    return arn.rsplit("/", 1)[-1]


def _role_name(arn: str) -> str:
    return arn.rstrip("/").split("/")[-1]


def _upsert_edge(
    collection: Any,
    edge_type: str,
    from_id: str,
    to_id: str,
    tenant_id: str,
) -> bool:
    ekey = _edge_key(from_id, to_id, edge_type)
    edge = {"_key": ekey, "_from": from_id, "_to": to_id, "tenant_id": tenant_id}
    try:
        collection.insert(edge, overwrite=True)
        return True
    except Exception:
        logger.debug("%s edge already exists: %s", edge_type, ekey)
        return False


def build_resource_edges(db: Any, tenant_id: str) -> dict[str, int]:
    """
    Traverse resources/identities already persisted for this tenant and
    materialize BELONGS_TO, ATTACHED_TO, ASSUMES_ROLE, and MEMBER_OF edges.

    Returns dict with counts per edge type.
    """
    counts = {"BELONGS_TO": 0, "ATTACHED_TO": 0, "ASSUMES_ROLE": 0, "MEMBER_OF": 0}

    try:
        resources: list[dict[str, Any]] = list(
            db.aql.execute(
                "FOR r IN resources FILTER r.tenant_id == @tid AND r.status != 'deleted' RETURN r",
                bind_vars={"tid": tenant_id},
            )
        )
        identities: list[dict[str, Any]] = list(
            db.aql.execute(
                "FOR i IN identities FILTER i.tenant_id == @tid AND i.status != 'deleted' RETURN i",
                bind_vars={"tid": tenant_id},
            )
        )
    except Exception:
        logger.exception("Failed to load resources/identities for tenant=%s", tenant_id)
        return counts

    # ── Lookup indexes ─────────────────────────────────────────────────────
    vpc_key_by_raw_id: dict[str, str] = {}
    sg_key_by_raw_id: dict[str, str] = {}
    subnet_to_vpc_raw_id: dict[str, str] = {}

    for r in resources:
        resource_type = r.get("resource_type")
        raw_id = _raw_aws_id(r.get("arn"))
        if not raw_id:
            continue
        if resource_type == "ec2_vpc":
            vpc_key_by_raw_id[raw_id] = r["_id"]
        elif resource_type == "ec2_security_group":
            sg_key_by_raw_id[raw_id] = r["_id"]
        elif resource_type == "ec2_subnet":
            vpc_raw_id = (r.get("raw_metadata") or {}).get("vpc_id")
            if vpc_raw_id:
                subnet_to_vpc_raw_id[raw_id] = vpc_raw_id

    arn_to_identity_id: dict[str, str] = {}
    role_name_to_identity_id: dict[str, str] = {}
    for ident in identities:
        arn = ident.get("arn")
        if not arn:
            continue
        arn_to_identity_id[arn] = ident["_id"]
        if ident.get("identity_type") == "iam_role":
            role_name_to_identity_id[_role_name(arn)] = ident["_id"]

    edge_cols = {name: db.collection(name) for name in counts}

    # ── EC2: BELONGS_TO (VPC), ATTACHED_TO (SG), ASSUMES_ROLE (instance profile) ──
    for r in resources:
        if r.get("resource_type") != "ec2_instance":
            continue
        ec2_id = r["_id"]
        metadata = r.get("raw_metadata") or {}

        subnet_id = metadata.get("subnet_id")
        vpc_raw_id = subnet_to_vpc_raw_id.get(subnet_id) if subnet_id else None
        vpc_key = vpc_key_by_raw_id.get(vpc_raw_id) if vpc_raw_id else None
        if vpc_key and _upsert_edge(edge_cols["BELONGS_TO"], "BELONGS_TO", ec2_id, vpc_key, tenant_id):
            counts["BELONGS_TO"] += 1

        for sg_raw_id in metadata.get("security_groups") or []:
            sg_key = sg_key_by_raw_id.get(sg_raw_id)
            if sg_key and _upsert_edge(edge_cols["ATTACHED_TO"], "ATTACHED_TO", sg_key, ec2_id, tenant_id):
                counts["ATTACHED_TO"] += 1

        profile_arn = metadata.get("iam_instance_profile")
        if profile_arn:
            role_id = role_name_to_identity_id.get(_role_name(profile_arn))
            if role_id and _upsert_edge(edge_cols["ASSUMES_ROLE"], "ASSUMES_ROLE", ec2_id, role_id, tenant_id):
                counts["ASSUMES_ROLE"] += 1

    # ── Lambda: ASSUMES_ROLE (execution role) ──────────────────────────────
    for r in resources:
        if r.get("resource_type") != "lambda_function":
            continue
        lam_id = r["_id"]
        role_arn = (r.get("raw_metadata") or {}).get("execution_role_arn")
        if not role_arn:
            continue
        role_id = arn_to_identity_id.get(role_arn) or role_name_to_identity_id.get(_role_name(role_arn))
        if role_id and _upsert_edge(edge_cols["ASSUMES_ROLE"], "ASSUMES_ROLE", lam_id, role_id, tenant_id):
            counts["ASSUMES_ROLE"] += 1

    # ── IAM Group: MEMBER_OF ───────────────────────────────────────────────
    for ident in identities:
        if ident.get("identity_type") != "iam_group":
            continue
        group_id = ident["_id"]
        member_arns = (ident.get("raw_metadata") or {}).get("member_arns") or []
        for user_arn in member_arns:
            user_id = arn_to_identity_id.get(user_arn)
            if user_id and _upsert_edge(edge_cols["MEMBER_OF"], "MEMBER_OF", user_id, group_id, tenant_id):
                counts["MEMBER_OF"] += 1

    return counts
