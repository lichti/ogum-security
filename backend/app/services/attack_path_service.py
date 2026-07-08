"""
Attack Path detection service for Ogum.Graph (Epic 02 Sprint 1).

Runs AQL graph traversal queries to discover:
  - Paths from internet-facing resources to sensitive data assets
  - Privilege escalation chains through IAM role assumptions
  - Toxic combinations of misconfigurations that compound risk

All queries are bounded:
  - max_depth=4 hops (performance vs. coverage tradeoff)
  - maxRuntime=10s per AQL query (configured via ArangoDB option)
  - Tenant isolation enforced via PRUNE + FILTER v.tenant_id == @tenant_id
"""

from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from typing import Any

from app.services.mitre_service import build_mitre_chain_for_tc
from app.services.risk_score import calculate_path_risk_score, score_to_severity

logger = logging.getLogger(__name__)

_TRAVERSAL_EDGES = [
    "EXPOSED_TO",
    "ASSUMES_ROLE",
    "ROUTES_TRAFFIC",
    "BELONGS_TO",
    "ATTACHED_TO",
    "STORES_SENSITIVE_DATA",
]

_MAX_PATHS_PER_QUERY = 50
_QUERY_MAX_RUNTIME_SEC = 10


def _path_id(tenant_id: str, entry_point_id: str, target_id: str, rule: str) -> str:
    raw = f"{tenant_id}|{entry_point_id}|{target_id}|{rule}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def find_paths_from_internet(
    db: Any,
    tenant_id: str,
    max_depth: int = 4,
) -> list[dict[str, Any]]:
    """
    Traverse the graph from internet-facing resources to sensitive data assets.

    Entry points: resources or network_endpoints with is_public=true or is_internet_facing=true.
    Targets: any vertex in the data_assets collection.

    Returns a list of path dicts (one per unique entry_point → target pair).
    """
    edges_str = ", ".join(_TRAVERSAL_EDGES)
    aql = f"""
    LET entry_points = UNION_DISTINCT(
        (FOR r IN resources
            FILTER r.tenant_id == @tenant_id
            FILTER r.is_public == true
            RETURN r._id),
        (FOR n IN network_endpoints
            FILTER n.tenant_id == @tenant_id
            FILTER n.is_internet_facing == true OR n.is_public == true
            RETURN n._id)
    )
    FOR start_id IN entry_points
        LET start = DOCUMENT(start_id)
        FOR v, e, p IN 1..@max_depth OUTBOUND start
            {edges_str}
            PRUNE v.tenant_id != @tenant_id
            FILTER v.tenant_id == @tenant_id
            FILTER STARTS_WITH(v._id, "data_assets/")
            LIMIT @max_paths
            LET hop_count = LENGTH(p.edges)
            RETURN DISTINCT {{
                entry_point_id: start._id,
                entry_point_type: start.resource_type,
                entry_point_name: start.name,
                target_id: v._id,
                target_type: v.resource_type,
                target_name: v.name,
                hops: hop_count,
                is_internet_path: true,
                path_vertex_ids: p.vertices[*]._id,
                rule: "internet_to_data"
            }}
    """
    try:
        cursor = db.aql.execute(
            aql,
            bind_vars={
                "tenant_id": tenant_id,
                "max_depth": max_depth,
                "max_paths": _MAX_PATHS_PER_QUERY,
            },
            max_runtime=_QUERY_MAX_RUNTIME_SEC,
        )
        return list(cursor)
    except Exception:
        logger.exception("find_paths_from_internet query failed for tenant=%s", tenant_id)
        return []


def find_privilege_escalation_paths(
    db: Any,
    tenant_id: str,
    max_depth: int = 4,
) -> list[dict[str, Any]]:
    """
    Detect IAM privilege escalation chains.

    Traverses ASSUMES_ROLE edges from any identity to find paths that reach
    a highly-privileged identity (has_admin_policy=true or dangerous_permissions set).

    Returns a list of escalation path dicts.
    """
    aql = """
    FOR start IN identities
        FILTER start.tenant_id == @tenant_id
        FOR v, e, p IN 1..@max_depth OUTBOUND start
            ASSUMES_ROLE
            PRUNE v.tenant_id != @tenant_id
            FILTER v.tenant_id == @tenant_id
            FILTER STARTS_WITH(v._id, "identities/")
            FILTER v.has_admin_policy == true
                OR (v.dangerous_permissions != null AND LENGTH(v.dangerous_permissions) > 0)
            LIMIT @max_paths
            RETURN DISTINCT {
                start_identity_id: start._id,
                start_identity_name: start.name,
                target_identity_id: v._id,
                target_identity_name: v.name,
                hops: LENGTH(p.edges),
                path_vertex_ids: p.vertices[*]._id,
                rule: "privilege_escalation"
            }
    """
    try:
        cursor = db.aql.execute(
            aql,
            bind_vars={
                "tenant_id": tenant_id,
                "max_depth": max_depth,
                "max_paths": _MAX_PATHS_PER_QUERY,
            },
            max_runtime=_QUERY_MAX_RUNTIME_SEC,
        )
        return list(cursor)
    except Exception:
        logger.exception("find_privilege_escalation_paths query failed for tenant=%s", tenant_id)
        return []


# ---------------------------------------------------------------------------
# Toxic combination rules
# Each rule returns a list of dicts: {entry_point_id, target_id, rule, ...}
# ---------------------------------------------------------------------------

TOXIC_COMBINATION_RULES: list[dict[str, Any]] = [
    {
        "id": "TC-01",
        "name": "Internet-facing resource → sensitive data asset",
        "description": (
            "A resource directly accessible from the internet has a path to a sensitive data asset within 4 hops."
        ),
        "severity": "CRITICAL",
    },
    {
        "id": "TC-02",
        "name": "Public bucket with credentials",
        "description": "A publicly accessible storage asset contains credentials or secrets.",
        "severity": "CRITICAL",
    },
    {
        "id": "TC-03",
        "name": "Overpermissioned identity → production database",
        "description": "An identity with admin or wildcard policies can reach a production database.",
        "severity": "HIGH",
    },
    {
        "id": "TC-04",
        "name": "Kubernetes pod with host network → node",
        "description": "A K8s pod running with hostNetwork=true shares the node network stack.",
        "severity": "HIGH",
    },
]


def _detect_tc02_public_bucket_with_credentials(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    aql = """
    FOR d IN data_assets
        FILTER d.tenant_id == @tenant_id
        FILTER d.is_public == true
        FILTER d.contains_credentials == true
            OR d.contains_secrets == true
            OR d.resource_type IN ["s3_bucket", "azure_storage_container", "gcp_storage_bucket"]
        RETURN {
            entry_point_id: d._id,
            entry_point_type: d.resource_type,
            entry_point_name: d.name,
            target_id: d._id,
            target_type: d.resource_type,
            target_name: d.name,
            hops: 0,
            path_vertex_ids: [d._id],
            rule: "TC-02"
        }
    """
    try:
        cursor = db.aql.execute(aql, bind_vars={"tenant_id": tenant_id})
        return list(cursor)
    except Exception:
        logger.exception("TC-02 detection failed for tenant=%s", tenant_id)
        return []


def _detect_tc03_overpermissioned_to_db(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    aql = """
    FOR i IN identities
        FILTER i.tenant_id == @tenant_id
        FILTER i.has_admin_policy == true
            OR (i.dangerous_permissions != null AND LENGTH(i.dangerous_permissions) > 0)
        FOR v, e, p IN 1..3 OUTBOUND i
            ASSUMES_ROLE, STORES_SENSITIVE_DATA
            PRUNE v.tenant_id != @tenant_id
            FILTER v.tenant_id == @tenant_id
            FILTER STARTS_WITH(v._id, "data_assets/")
            FILTER v.resource_type LIKE "%rds%" OR v.resource_type LIKE "%database%"
                OR v.resource_type LIKE "%sql%" OR v.resource_type LIKE "%dynamo%"
                OR v.resource_type LIKE "%cosmos%" OR v.resource_type LIKE "%db_%"
            LIMIT @max_paths
            RETURN DISTINCT {
                entry_point_id: i._id,
                entry_point_type: i.resource_type,
                entry_point_name: i.name,
                target_id: v._id,
                target_type: v.resource_type,
                target_name: v.name,
                hops: LENGTH(p.edges),
                path_vertex_ids: p.vertices[*]._id,
                rule: "TC-03"
            }
    """
    try:
        cursor = db.aql.execute(
            aql,
            bind_vars={"tenant_id": tenant_id, "max_paths": _MAX_PATHS_PER_QUERY},
            max_runtime=_QUERY_MAX_RUNTIME_SEC,
        )
        return list(cursor)
    except Exception:
        logger.exception("TC-03 detection failed for tenant=%s", tenant_id)
        return []


def _detect_tc04_k8s_host_network(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    aql = """
    FOR r IN resources
        FILTER r.tenant_id == @tenant_id
        FILTER r.provider IN ["k8s", "kubernetes"]
        FILTER r.host_network == true
        RETURN {
            entry_point_id: r._id,
            entry_point_type: r.resource_type,
            entry_point_name: r.name,
            target_id: r._id,
            target_type: r.resource_type,
            target_name: r.name,
            hops: 0,
            path_vertex_ids: [r._id],
            rule: "TC-04"
        }
    """
    try:
        cursor = db.aql.execute(aql, bind_vars={"tenant_id": tenant_id})
        return list(cursor)
    except Exception:
        logger.exception("TC-04 detection failed for tenant=%s", tenant_id)
        return []


def detect_all_toxic_combinations(db: Any, tenant_id: str) -> list[dict[str, Any]]:
    """Run all toxic combination detection queries and return combined results."""
    results: list[dict[str, Any]] = []
    results.extend(_detect_tc02_public_bucket_with_credentials(db, tenant_id))
    results.extend(_detect_tc03_overpermissioned_to_db(db, tenant_id))
    results.extend(_detect_tc04_k8s_host_network(db, tenant_id))
    return results


def build_attack_path_docs(
    db: Any,
    tenant_id: str,
    raw_paths: list[dict[str, Any]],
    *,
    is_toxic_combination: bool = False,
    default_severity: str = "HIGH",
) -> list[dict[str, Any]]:
    """
    Convert raw traversal results to attack_paths collection documents.

    Loads risk_score from existing resource docs where available and
    calculates a path-level risk score.
    """
    docs: list[dict[str, Any]] = []
    now = datetime.now(UTC).isoformat()

    for raw in raw_paths:
        entry_id: str = raw.get("entry_point_id", "") or raw.get("start_identity_id", "")
        target_id: str = raw.get("target_id", "") or raw.get("target_identity_id", "")
        rule: str = raw.get("rule", "unknown")
        hops: int = int(raw.get("hops", 1))

        if not entry_id or not target_id:
            continue

        path_vertex_ids: list[str] = raw.get("path_vertex_ids", [entry_id, target_id])

        # Load risk scores from vertex docs to compute path risk score
        path_nodes: list[dict[str, Any]] = []
        for vid in path_vertex_ids:
            doc = None
            try:
                doc = db.document(vid)
            except Exception:
                pass
            path_nodes.append({"risk_score": (doc or {}).get("risk_score", 0)})

        path_risk = calculate_path_risk_score(path_nodes, max(hops, 1))
        severity = score_to_severity(path_risk) if path_risk > 0 else default_severity
        pid = _path_id(tenant_id, entry_id, target_id, rule)

        mitre_chain = build_mitre_chain_for_tc(rule) if is_toxic_combination else []

        docs.append(
            {
                "_key": pid,
                "path_id": pid,
                "tenant_id": tenant_id,
                "rule": rule,
                "entry_point_id": entry_id,
                "entry_point_type": raw.get("entry_point_type") or raw.get("start_identity_id"),
                "entry_point_name": raw.get("entry_point_name") or raw.get("start_identity_name"),
                "target_id": target_id,
                "target_type": raw.get("target_type") or raw.get("target_identity_type"),
                "target_name": raw.get("target_name") or raw.get("target_identity_name"),
                "hops": hops,
                "path_vertex_ids": path_vertex_ids,
                "risk_score": path_risk,
                "severity": severity,
                "is_toxic_combination": is_toxic_combination,
                "mitre_ttps": mitre_chain,
                "mitre_chain": mitre_chain,
                "actively_exploited": False,
                "last_runtime_event_at": None,
                "detected_at": now,
                "status": "active",
            }
        )

    return docs


def persist_attack_paths(db: Any, docs: list[dict[str, Any]]) -> int:
    """
    Upsert attack_path documents into ArangoDB.

    Returns the count of upserted documents.
    """
    if not docs:
        return 0

    collection = db.collection("attack_paths")
    count = 0
    for doc in docs:
        key = doc["_key"]
        update = {k: v for k, v in doc.items() if k not in {"_key", "path_id", "tenant_id"}}
        try:
            collection.update({"_key": key, **update})
        except Exception:
            try:
                collection.insert(doc)
            except Exception:
                logger.debug("Skipped duplicate attack_path %s", key)
                continue
        count += 1

    return count


def mark_resources_in_attack_path(db: Any, tenant_id: str, attack_path_docs: list[dict[str, Any]]) -> None:
    """Set in_attack_path=true on all resources that participate in any attack path."""
    vertex_ids: set[str] = set()
    for doc in attack_path_docs:
        for vid in doc.get("path_vertex_ids", []):
            vertex_ids.add(vid)

    for vid in vertex_ids:
        try:
            col_name, key = vid.split("/", 1)
            db.collection(col_name).update({"_key": key, "in_attack_path": True, "tenant_id": tenant_id})
        except Exception:
            pass


def run_attack_path_detection(
    db: Any,
    tenant_id: str,
    max_depth: int = 4,
) -> dict[str, int]:
    """
    Full detection pipeline: traversal + toxic combinations + persistence.

    Returns counts of what was detected and persisted.
    """
    internet_paths = find_paths_from_internet(db, tenant_id, max_depth=max_depth)
    escalation_paths = find_privilege_escalation_paths(db, tenant_id, max_depth=max_depth)
    toxic_raw = detect_all_toxic_combinations(db, tenant_id)

    internet_docs = build_attack_path_docs(db, tenant_id, internet_paths, is_toxic_combination=False)
    escalation_docs = build_attack_path_docs(
        db, tenant_id, escalation_paths, is_toxic_combination=False, default_severity="HIGH"
    )
    toxic_docs = build_attack_path_docs(
        db, tenant_id, toxic_raw, is_toxic_combination=True, default_severity="CRITICAL"
    )

    all_docs = internet_docs + escalation_docs + toxic_docs
    persisted = persist_attack_paths(db, all_docs)
    mark_resources_in_attack_path(db, tenant_id, all_docs)

    return {
        "internet_paths": len(internet_docs),
        "escalation_paths": len(escalation_docs),
        "toxic_combinations": len(toxic_docs),
        "total_persisted": persisted,
    }
