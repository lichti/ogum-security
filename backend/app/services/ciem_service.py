"""
CIEM (Cloud Infrastructure Entitlement Management) — Static Analysis.

Epic 02 Sprint 4: static permission analysis without CloudTrail.
Detects dangerous permissions granted to IAM identities and AssumeRole
privilege escalation chains in the graph.

Privilege gap analysis (granted vs. used actions) is deferred to Epic 07
when CloudTrail ingestion is available via Ogum.Pulse.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Permissions that directly enable privilege escalation regardless of other context.
DANGEROUS_PERMISSIONS: list[dict[str, str]] = [
    {
        "action": "iam:CreatePolicyVersion",
        "risk": "Can replace any managed policy with a version granting AdministratorAccess.",
    },
    {
        "action": "iam:SetDefaultPolicyVersion",
        "risk": "Can activate any existing policy version, including one granting admin access.",
    },
    {
        "action": "iam:AttachUserPolicy",
        "risk": "Can attach any managed policy (including AdministratorAccess) to any IAM user.",
    },
    {
        "action": "iam:AttachGroupPolicy",
        "risk": "Can attach any managed policy to any IAM group, escalating all group members.",
    },
    {
        "action": "iam:AttachRolePolicy",
        "risk": "Can attach any managed policy to any role, enabling subsequent role assumption.",
    },
    {
        "action": "iam:PutUserPolicy",
        "risk": "Can inline any policy into any user, granting arbitrary permissions.",
    },
    {
        "action": "iam:PutGroupPolicy",
        "risk": "Can inline any policy into any group.",
    },
    {
        "action": "iam:PutRolePolicy",
        "risk": "Can inline any policy into any role.",
    },
    {
        "action": "iam:PassRole",
        "risk": "Can pass roles to services (Lambda, EC2, ECS), enabling privilege escalation via compute.",
    },
    {
        "action": "iam:CreateAccessKey",
        "risk": "Can create long-lived credentials for any IAM user.",
    },
    {
        "action": "iam:UpdateAssumeRolePolicy",
        "risk": "Can modify trust policy of any role, allowing any principal to assume it.",
    },
    {
        "action": "sts:AssumeRole",
        "risk": "Unrestricted AssumeRole allows lateral movement to any role in the account.",
    },
    {
        "action": "s3:*",
        "risk": "Wildcard S3 access allows reading, writing, and deleting all objects in all buckets.",
    },
    {
        "action": "ec2:*",
        "risk": "Wildcard EC2 access allows creating and destroying infrastructure, including IAM-attached instances.",
    },
    {
        "action": "iam:*",
        "risk": "Wildcard IAM access is effectively AdministratorAccess — can create/modify any identity or policy.",
    },
    {
        "action": "lambda:UpdateFunctionCode",
        "risk": "Can replace Lambda function code with malicious code running under the function's execution role.",
    },
    {
        "action": "lambda:AddPermission",
        "risk": "Can grant external principals permission to invoke Lambda functions.",
    },
    {
        "action": "cloudformation:CreateStack",
        "risk": "Can deploy arbitrary CloudFormation stacks with IAM role creation capabilities.",
    },
    {
        "action": "glue:CreateDevEndpoint",
        "risk": "Can create a Glue dev endpoint with any role attached, enabling privilege escalation.",
    },
]

_DANGEROUS_ACTIONS: set[str] = {p["action"] for p in DANGEROUS_PERMISSIONS}
_DANGEROUS_WILDCARDS: list[str] = [p["action"] for p in DANGEROUS_PERMISSIONS if p["action"].endswith(":*")]

_QUERY_MAX_RUNTIME_SEC = 10
_MAX_CHAINS_PER_QUERY = 50


def _matches_dangerous(action: str) -> str | None:
    """Return the matched dangerous action string, or None if safe.

    Exact matching only — wildcard entries like ec2:* only match when the
    granted action IS ec2:* (not when a specific ec2:Foo action is granted).
    Specific actions like ec2:RunInstances are not inherently dangerous without
    additional context; only the explicit wildcard grant is flagged.
    """
    if action in _DANGEROUS_ACTIONS:
        return action
    return None


def analyze_dangerous_permissions(
    identity_doc: dict[str, Any],
) -> list[dict[str, str]]:
    """
    Inspect an identity document's granted_actions and policies for dangerous permissions.

    Returns a list of {action, risk} dicts for each dangerous permission found.
    Does not query the database — operates on the already-loaded document.
    """
    granted: list[str] = identity_doc.get("granted_actions", []) or []
    policies: list[str] = identity_doc.get("policies", []) or []
    dangerous: list[dict[str, str]] = []
    seen: set[str] = set()

    # Check granted_actions (normalized list stored during discovery)
    for action in granted:
        matched = _matches_dangerous(action)
        if matched and matched not in seen:
            seen.add(matched)
            risk_entry = next((p for p in DANGEROUS_PERMISSIONS if p["action"] == matched), None)
            if risk_entry:
                dangerous.append(risk_entry.copy())

    # Check policy names — AdministratorAccess is an instant flag
    for policy in policies:
        if "AdministratorAccess" in policy or "PowerUserAccess" in policy:
            action = "iam:*"
            if action not in seen:
                seen.add(action)
                dangerous.append({"action": action, "risk": f"Policy '{policy}' grants unrestricted IAM access."})

    return dangerous


def find_assume_role_chains(
    db: Any,
    identity_id: str,
    tenant_id: str,
    max_depth: int = 4,
) -> list[dict[str, Any]]:
    """
    Traverse ASSUMES_ROLE edges from a given identity to find privilege escalation chains.

    Returns a list of chain dicts, each describing the path from the starting
    identity to a high-privilege target.
    """
    aql = """
    LET start = DOCUMENT(@identity_id)
    FOR v, e, p IN 1..@max_depth OUTBOUND start
        ASSUMES_ROLE
        PRUNE v.tenant_id != @tenant_id
        FILTER v.tenant_id == @tenant_id
        FILTER STARTS_WITH(v._id, "identities/")
        FILTER v.has_admin_policy == true
            OR (v.dangerous_permissions != null AND LENGTH(v.dangerous_permissions) > 0)
        LIMIT @max_chains
        RETURN {
            start_id: start._id,
            start_name: start.name,
            target_id: v._id,
            target_name: v.name,
            hops: LENGTH(p.edges),
            chain: p.vertices[*].name
        }
    """
    try:
        cursor = db.aql.execute(
            aql,
            bind_vars={
                "identity_id": identity_id,
                "tenant_id": tenant_id,
                "max_depth": max_depth,
                "max_chains": _MAX_CHAINS_PER_QUERY,
            },
            max_runtime=_QUERY_MAX_RUNTIME_SEC,
        )
        return list(cursor)
    except Exception:
        logger.exception("find_assume_role_chains failed for identity=%s", identity_id)
        return []


def get_identity_ciem_summary(
    db: Any,
    identity_key: str,
    tenant_id: str,
) -> dict[str, Any]:
    """
    Return a complete CIEM analysis for a single identity.

    Loads the identity document, analyses dangerous permissions, and
    counts reachable privilege escalation chains.
    """
    doc = db.collection("identities").get(identity_key)
    if not doc:
        return {}

    dangerous = analyze_dangerous_permissions(doc)
    identity_id = f"identities/{identity_key}"
    chains = find_assume_role_chains(db, identity_id, tenant_id)

    return {
        "identity_id": identity_id,
        "identity_key": identity_key,
        "name": doc.get("name", ""),
        "identity_type": doc.get("identity_type", ""),
        "provider": doc.get("provider", ""),
        "account_id": doc.get("account_id"),
        "policies": doc.get("policies", []),
        "granted_actions": doc.get("granted_actions", []),
        "dangerous_permissions": dangerous,
        "dangerous_permissions_count": len(dangerous),
        "escalation_chains": chains,
        "escalation_paths_count": len(chains),
        "has_admin_policy": doc.get("has_admin_policy", False),
        "privilege_gap_score": doc.get("privilege_gap_score", 0),
        "risk_score": doc.get("risk_score", 0),
        "status": doc.get("status", "active"),
    }


def list_identities_with_ciem(
    db: Any,
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
    provider: str | None = None,
    only_dangerous: bool = False,
) -> tuple[list[dict[str, Any]], int]:
    """
    List identities with pre-computed CIEM counters.

    Returns (items, total_count).
    """
    filters = ["FILTER i.tenant_id == @tenant_id"]
    bind: dict[str, Any] = {"tenant_id": tenant_id}

    if provider:
        filters.append("FILTER i.provider == @provider")
        bind["provider"] = provider

    if only_dangerous:
        filters.append(
            "FILTER (i.dangerous_permissions != null AND LENGTH(i.dangerous_permissions) > 0)"
            " OR i.has_admin_policy == true"
        )

    filter_str = "\n    ".join(filters)

    count_aql = f"""
    FOR i IN identities
        {filter_str}
        COLLECT WITH COUNT INTO n
        RETURN n
    """
    list_aql = f"""
    FOR i IN identities
        {filter_str}
        SORT i.risk_score DESC, i.name ASC
        LIMIT @offset, @limit
        RETURN {{
            key: i._key,
            name: i.name,
            identity_type: i.identity_type,
            provider: i.provider,
            account_id: i.account_id,
            arn: i.arn,
            status: i.status,
            risk_score: i.risk_score,
            has_admin_policy: i.has_admin_policy,
            dangerous_permissions_count: LENGTH(i.dangerous_permissions != null ? i.dangerous_permissions : []),
            escalation_paths_count: i.escalation_paths_count,
            privilege_gap_score: i.privilege_gap_score,
            policies: i.policies,
            last_scanned_at: i.last_scanned_at
        }}
    """
    bind["limit"] = limit
    bind["offset"] = offset

    try:
        count_bind = {k: v for k, v in bind.items() if k not in ("limit", "offset")}
        count_cursor = db.aql.execute(count_aql, bind_vars=count_bind)
        total = (list(count_cursor) or [0])[0]

        list_cursor = db.aql.execute(list_aql, bind_vars=bind)
        items = list(list_cursor)
        return items, int(total)
    except Exception:
        logger.exception("list_identities_with_ciem failed for tenant=%s", tenant_id)
        return [], 0
