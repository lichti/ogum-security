"""
IAM Deep Model — build STS_ASSUMEROLE_ALLOW, ASSUMES, and ATTACHED_POLICY edges
from metadata already stored in the `identities` collection.

No new AWS API calls are made — all information is derived from fields persisted
during discovery:
  - identity.trust_policy         → STS_ASSUMEROLE_ALLOW edges
  - identity.assumed_role_arn     → ASSUMES edges
  - identity.policies             → ATTACHED_POLICY edges
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

_ASSUME_ACTIONS = frozenset(
    [
        "sts:assumerole",
        "sts:assumerolwithwebidentity",
        "sts:assumerolwithsaml",
        "sts:assumerolewithwebidentity",  # normalize common typo
        "*",
    ]
)


def _edge_key(from_id: str, to_id: str, edge_type: str) -> str:
    raw = f"{edge_type}|{from_id}|{to_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _extract_principal_arns(trust_policy: Any) -> list[str]:
    """Return ARNs/identifiers listed as principals in a trust policy document."""
    if not isinstance(trust_policy, dict):
        return []
    arns: list[str] = []
    for stmt in trust_policy.get("Statement", []):
        if str(stmt.get("Effect", "")).upper() != "ALLOW":
            continue
        actions_raw = stmt.get("Action", [])
        actions: list[str] = [actions_raw] if isinstance(actions_raw, str) else actions_raw
        if not any(a.lower() in _ASSUME_ACTIONS for a in actions):
            continue
        principal = stmt.get("Principal", {})
        if isinstance(principal, str):
            arns.append(principal)
        elif isinstance(principal, dict):
            for v in principal.values():
                if isinstance(v, str):
                    arns.append(v)
                elif isinstance(v, list):
                    arns.extend(v)
        elif isinstance(principal, list):
            arns.extend(principal)
    return arns


def build_iam_edges(db: Any, tenant_id: str) -> dict[str, int]:
    """
    Traverse the identities collection and materialize IAM graph edges.

    Returns dict with counts per edge type.
    """
    sts_allow_count = 0
    assumes_count = 0
    attached_policy_count = 0

    # Index all identities by ARN and by _id for quick lookup
    all_identities: list[dict[str, Any]] = []
    try:
        cursor = db.aql.execute(
            "FOR i IN identities FILTER i.tenant_id == @tid RETURN i",
            bind_vars={"tid": tenant_id},
        )
        all_identities = list(cursor)
    except Exception:
        logger.exception("Failed to load identities for tenant=%s", tenant_id)
        return {"STS_ASSUMEROLE_ALLOW": 0, "ASSUMES": 0, "ATTACHED_POLICY": 0}

    arn_to_id: dict[str, str] = {}
    for identity in all_identities:
        arn = identity.get("arn")
        if arn:
            arn_to_id[arn] = identity["_id"]

    sts_col = db.collection("STS_ASSUMEROLE_ALLOW")
    assumes_col = db.collection("ASSUMES")
    policy_col = db.collection("ATTACHED_POLICY")

    for identity in all_identities:
        from_id = identity["_id"]

        # ── STS_ASSUMEROLE_ALLOW: build from trust_policy on role identities ──────
        trust_policy = identity.get("trust_policy")
        if trust_policy:
            principal_arns = _extract_principal_arns(trust_policy)
            for principal_arn in principal_arns:
                to_id = arn_to_id.get(principal_arn)
                if not to_id or to_id == from_id:
                    continue
                # Edge direction: principal_identity → role  (principal CAN assume role)
                ekey = _edge_key(to_id, from_id, "STS_ASSUMEROLE_ALLOW")
                edge = {
                    "_key": ekey,
                    "_from": to_id,
                    "_to": from_id,
                    "tenant_id": tenant_id,
                    "via_arn": principal_arn,
                }
                try:
                    sts_col.insert(edge, overwrite=True)
                    sts_allow_count += 1
                except Exception:
                    logger.debug("STS_ASSUMEROLE_ALLOW edge already exists: %s", ekey)

        # ── ASSUMES: active role assumptions from assumed_role_arn field ──────────
        assumed_arn = identity.get("assumed_role_arn")
        if assumed_arn:
            to_id = arn_to_id.get(assumed_arn)
            if to_id and to_id != from_id:
                ekey = _edge_key(from_id, to_id, "ASSUMES")
                edge = {
                    "_key": ekey,
                    "_from": from_id,
                    "_to": to_id,
                    "tenant_id": tenant_id,
                }
                try:
                    assumes_col.insert(edge, overwrite=True)
                    assumes_count += 1
                except Exception:
                    logger.debug("ASSUMES edge already exists: %s", ekey)

        # ── ATTACHED_POLICY: policies list stored on identity ─────────────────────
        policies = identity.get("policies") or []
        if isinstance(policies, str):
            policies = [policies]
        for policy_arn in policies:
            if not policy_arn:
                continue
            ekey = _edge_key(from_id, policy_arn, "ATTACHED_POLICY")
            edge = {
                "_key": ekey,
                "_from": from_id,
                "_to": from_id,  # self-reference until policies have their own collection
                "tenant_id": tenant_id,
                "policy_arn": policy_arn,
            }
            try:
                policy_col.insert(edge, overwrite=True)
                attached_policy_count += 1
            except Exception:
                logger.debug("ATTACHED_POLICY edge already exists: %s", ekey)

    return {
        "STS_ASSUMEROLE_ALLOW": sts_allow_count,
        "ASSUMES": assumes_count,
        "ATTACHED_POLICY": attached_policy_count,
    }
