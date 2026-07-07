"""
Risk Score engine for Ogum.Graph (Epic 02 Sprint 1).

Score formula (0–100):
    score = clamp(severity_base * exposure_factor * blast_factor, 0, 100)

Components:
    severity_base   = weighted sum of FAIL findings, capped at 50
                      CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1, INFORMATIONAL=0.5
    exposure_factor = 2.0 if resource is internet-facing (is_public=true)
    blast_factor    = 1.0 + min(reachable_sensitive_count / 5, 1.0)
                      reachable = data_assets within 3 hops via any edge

Resources in a confirmed attack path have a minimum score of 40.
Resources with no FAIL findings have score 0.

Path risk score:
    max(node_severity_weight) × depth_factor
    depth_factor = 1.0 + (1.0 / hop_count)  — shorter path = more dangerous
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFORMATIONAL": 0.5,
    "INFO": 0.5,
}

_TRAVERSAL_EDGES = [
    "EXPOSED_TO",
    "ASSUMES_ROLE",
    "ROUTES_TRAFFIC",
    "BELONGS_TO",
    "ATTACHED_TO",
    "STORES_SENSITIVE_DATA",
]

_IN_ATTACK_PATH_MIN_SCORE = 40.0


def _fetch_severity_counts(db: Any, resource_id: str, tenant_id: str) -> dict[str, int]:
    aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.resource_id == @resource_id
        FILTER f.status == "FAIL"
        COLLECT sev = f.severity WITH COUNT INTO cnt
        RETURN {sev: sev, cnt: cnt}
    """
    cursor = db.aql.execute(aql, bind_vars={"tenant_id": tenant_id, "resource_id": resource_id})
    counts: dict[str, int] = {}
    for row in cursor:
        if isinstance(row, dict):
            counts[row.get("sev", "MEDIUM")] = row.get("cnt", 0)
    return counts


def _fetch_resource_doc(db: Any, resource_key: str, collection: str) -> dict[str, Any] | None:
    try:
        return db.collection(collection).get(resource_key)  # type: ignore[no-any-return]
    except Exception:
        return None


def _count_reachable_data_assets(db: Any, resource_id: str, collection: str, tenant_id: str) -> int:
    """Count data_assets reachable within 3 hops from the given resource via graph traversal."""
    edges_str = ", ".join(_TRAVERSAL_EDGES)
    aql = f"""
    LET start = DOCUMENT(@start_id)
    LET reachable = (
        FOR v IN 1..3 OUTBOUND start
            {edges_str}
            PRUNE v.tenant_id != @tenant_id
            FILTER v.tenant_id == @tenant_id
            FILTER STARTS_WITH(v._id, "data_assets/")
            RETURN DISTINCT v._id
    )
    RETURN LENGTH(reachable)
    """
    start_id = f"{collection}/{resource_id}"
    try:
        cursor = db.aql.execute(aql, bind_vars={"start_id": start_id, "tenant_id": tenant_id})
        result = list(cursor)
        return int(result[0]) if result else 0
    except Exception:
        logger.debug("Blast radius traversal failed for %s — defaulting to 0", start_id)
        return 0


def calculate_resource_risk_score(
    db: Any,
    resource_key: str,
    tenant_id: str,
    collection: str = "resources",
    *,
    in_attack_path: bool = False,
) -> float:
    """
    Calculate contextual risk score (0–100) for a single resource.

    Args:
        db: ArangoDB tenant database handle.
        resource_key: ArangoDB ``_key`` of the resource document.
        tenant_id: Tenant identifier (for query scoping).
        collection: Vertex collection the resource lives in.
        in_attack_path: If True, enforce minimum score of 40.

    Returns:
        Float in [0, 100].
    """
    doc = _fetch_resource_doc(db, resource_key, collection)
    if doc is None:
        return 0.0

    resource_id = doc.get("resource_id") or resource_key
    is_public: bool = bool(doc.get("is_public") or doc.get("is_internet_facing"))

    severity_counts = _fetch_severity_counts(db, resource_id, tenant_id)
    if not severity_counts:
        return 0.0

    raw_base = sum(_SEVERITY_WEIGHTS.get(sev, 1.0) * cnt for sev, cnt in severity_counts.items())
    severity_base = min(raw_base, 50.0)

    exposure_factor = 2.0 if is_public else 1.0

    reachable = _count_reachable_data_assets(db, resource_key, collection, tenant_id)
    blast_factor = 1.0 + min(reachable / 5.0, 1.0)

    score = min(severity_base * exposure_factor * blast_factor, 100.0)

    if in_attack_path:
        score = max(score, _IN_ATTACK_PATH_MIN_SCORE)

    return round(score, 2)


def calculate_path_risk_score(path_nodes: list[dict[str, Any]], hop_count: int) -> float:
    """
    Calculate risk score for an attack path.

    Uses the maximum node severity weight along the path, amplified by a
    depth factor (shorter paths are more dangerous — attacker has fewer
    steps to reach the target).

    Args:
        path_nodes: List of resource dicts, each with a ``risk_score`` field.
        hop_count: Number of edges in the path (>= 1).

    Returns:
        Float in [0, 100].
    """
    if not path_nodes or hop_count < 1:
        return 0.0

    max_node_score = max(float(n.get("risk_score", 0) or 0) for n in path_nodes)
    depth_factor = 1.0 + (1.0 / hop_count)

    return round(min(max_node_score * depth_factor, 100.0), 2)


def score_to_severity(score: float) -> str:
    """Map a numeric risk score to a severity label."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFORMATIONAL"
