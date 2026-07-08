"""
IAM Privilege Escalation Detection (10 patterns).

Traverses the IAM deep model edges (STS_ASSUMEROLE_ALLOW, ASSUMES, ATTACHED_POLICY)
to find identities that can escalate to admin without going through the intended
path. Patterns based on Rhino Security Labs IAM Privilege Escalation research.

All queries are bounded to 4 hops maximum and scoped to the tenant.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_MAX_RUNTIME_SEC = 10


# Each pattern returns list[dict] with: identity_id, target_id, pattern, description
ESCALATION_PATTERNS: list[dict[str, Any]] = [
    {
        "id": "PRIVESC-01",
        "name": "Direct role assumption to admin",
        "description": "Identity can assume a role that has AdministratorAccess or equivalent.",
    },
    {
        "id": "PRIVESC-02",
        "name": "Chain role assumption to admin",
        "description": "Identity can chain 2+ role assumptions to reach an admin role.",
    },
    {
        "id": "PRIVESC-03",
        "name": "iam:CreatePolicyVersion — new policy version with *",
        "description": (
            "Identity with iam:CreatePolicyVersion can create a new default version with wildcard permissions."
        ),
    },
    {
        "id": "PRIVESC-04",
        "name": "iam:SetDefaultPolicyVersion — revert to admin version",
        "description": "Identity with iam:SetDefaultPolicyVersion can promote an older admin policy version.",
    },
    {
        "id": "PRIVESC-05",
        "name": "iam:AttachRolePolicy — attach admin policy to assumable role",
        "description": "Identity with iam:AttachRolePolicy can attach AdministratorAccess to a role it can assume.",
    },
    {
        "id": "PRIVESC-06",
        "name": "iam:AttachUserPolicy — self-escalation via policy attachment",
        "description": "Identity with iam:AttachUserPolicy can attach admin policies to itself.",
    },
    {
        "id": "PRIVESC-07",
        "name": "iam:PutUserPolicy — inline admin policy",
        "description": "Identity with iam:PutUserPolicy can embed an inline admin policy on any user.",
    },
    {
        "id": "PRIVESC-08",
        "name": "iam:CreateAccessKey — credential hijack",
        "description": "Identity with iam:CreateAccessKey can mint new credentials for another user.",
    },
    {
        "id": "PRIVESC-09",
        "name": "lambda:UpdateFunctionCode — code injection via Lambda",
        "description": (
            "Identity with lambda:UpdateFunctionCode can replace function code on a Lambda that uses an admin role."
        ),
    },
    {
        "id": "PRIVESC-10",
        "name": "iam:PassRole + ec2:RunInstances — admin instance profile",
        "description": (
            "Identity with iam:PassRole and ec2:RunInstances can launch an EC2 with an admin instance profile."
        ),
    },
]

_DANGEROUS_PERMISSION_PATTERNS: dict[str, str] = {
    "iam:createpolicyversion": "PRIVESC-03",
    "iam:setdefaultpolicyversion": "PRIVESC-04",
    "iam:attachrolepolicy": "PRIVESC-05",
    "iam:attachuserpolicy": "PRIVESC-06",
    "iam:putuserpolicy": "PRIVESC-07",
    "iam:createaccesskey": "PRIVESC-08",
    "lambda:updatefunctioncode": "PRIVESC-09",
}


def detect_direct_assume_to_admin(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """PRIVESC-01 and PRIVESC-02: role assumption chain to admin."""
    aql = """
    FOR i IN identities
        FILTER i.tenant_id == @tid
        FILTER i.has_admin_policy != true
        FOR v, e, p IN 1..4 OUTBOUND i
            STS_ASSUMEROLE_ALLOW, ASSUMES
            PRUNE v.tenant_id != @tid
            FILTER v.tenant_id == @tid
            FILTER v.has_admin_policy == true
                OR (v.dangerous_permissions != null AND LENGTH(v.dangerous_permissions) > 0)
            LIMIT 100
            RETURN DISTINCT {
                identity_id: i._id,
                identity_name: i.name,
                target_id: v._id,
                target_name: v.name,
                hops: LENGTH(p.edges),
                pattern: LENGTH(p.edges) == 1 ? "PRIVESC-01" : "PRIVESC-02",
                path_vertex_ids: p.vertices[*]._id
            }
    """
    try:
        return list(db.aql.execute(aql, bind_vars={"tid": tenant_id}, max_runtime=_MAX_RUNTIME_SEC))
    except Exception:
        logger.exception("PRIVESC-01/02 detection failed for tenant=%s", tenant_id)
        return []


def detect_dangerous_permission_patterns(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """PRIVESC-03 through PRIVESC-09: dangerous IAM permissions on identities."""
    results: list[dict[str, Any]] = []
    try:
        cursor = db.aql.execute(
            """
            FOR i IN identities
                FILTER i.tenant_id == @tid
                FILTER i.dangerous_permissions != null AND LENGTH(i.dangerous_permissions) > 0
                RETURN {identity_id: i._id, name: i.name, dangerous_permissions: i.dangerous_permissions}
            """,
            bind_vars={"tid": tenant_id},
        )
        for row in cursor:
            perms = row.get("dangerous_permissions") or []
            if isinstance(perms, list):
                perm_actions = [(p.get("action", "") if isinstance(p, dict) else str(p)).lower() for p in perms]
            else:
                perm_actions = []

            for action, pattern_id in _DANGEROUS_PERMISSION_PATTERNS.items():
                if action in perm_actions or "*" in perm_actions:
                    results.append(
                        {
                            "identity_id": row["identity_id"],
                            "identity_name": row["name"],
                            "target_id": row["identity_id"],
                            "target_name": row["name"],
                            "hops": 0,
                            "pattern": pattern_id,
                            "path_vertex_ids": [row["identity_id"]],
                            "via_action": action,
                        }
                    )
    except Exception:
        logger.exception("Dangerous permission detection failed for tenant=%s", tenant_id)
    return results


def detect_passrole_ec2(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """PRIVESC-10: iam:PassRole + ec2:RunInstances → admin instance profile."""
    results: list[dict[str, Any]] = []
    try:
        cursor = db.aql.execute(
            """
            FOR i IN identities
                FILTER i.tenant_id == @tid
                FILTER i.dangerous_permissions != null
                LET actions = (
                    FOR p IN i.dangerous_permissions
                        RETURN LOWER(IS_OBJECT(p) ? p.action : p)
                )
                FILTER "iam:passrole" IN actions OR "*" IN actions
                FILTER "ec2:runinstances" IN actions OR "*" IN actions
                RETURN {identity_id: i._id, name: i.name}
            """,
            bind_vars={"tid": tenant_id},
        )
        for row in cursor:
            results.append(
                {
                    "identity_id": row["identity_id"],
                    "identity_name": row["name"],
                    "target_id": row["identity_id"],
                    "target_name": row["name"],
                    "hops": 0,
                    "pattern": "PRIVESC-10",
                    "path_vertex_ids": [row["identity_id"]],
                    "via_action": "iam:PassRole + ec2:RunInstances",
                }
            )
    except Exception:
        logger.exception("PRIVESC-10 detection failed for tenant=%s", tenant_id)
    return results


def detect_all_escalation_paths(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Run all 10 detection patterns and return combined results."""
    results: list[dict[str, Any]] = []
    results.extend(detect_direct_assume_to_admin(db, tenant_id))
    results.extend(detect_dangerous_permission_patterns(db, tenant_id))
    results.extend(detect_passrole_ec2(db, tenant_id))
    return results
