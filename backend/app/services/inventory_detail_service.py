from __future__ import annotations

from typing import Any

from arango.database import StandardDatabase

from app.models.api_responses import ResourceDetail
from app.models.inventory_detail import (
    BlastRadiusEdge,
    BlastRadiusNode,
    BlastRadiusResponse,
    NarrativeDeepLink,
    ResourceComplianceControl,
    ResourceComplianceFrameworkOption,
    ResourceComplianceResponse,
    ResourceNarrativeSummary,
)
from app.services.compliance_frameworks import derive_section, resolve_family

_TRAVERSAL_EDGE_COLLECTIONS = [
    "BELONGS_TO",
    "ATTACHED_TO",
    "ROUTES_TRAFFIC",
    "ASSUMES_ROLE",
    "MEMBER_OF",
    "EXPOSED_TO",
    "CONTAINS_BUG",
    "STORES_SENSITIVE_DATA",
]

_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

# Bounds outbound traversal depth (specs/architecture.md: max 4 hops in AQL queries).
_MAX_BLAST_RADIUS_DEPTH = 3


def _count_findings_by_severity(db: StandardDatabase, tenant_id: str, resource_id: str) -> dict[str, int]:
    if not db.has_collection("findings"):
        return {}
    cursor = db.aql.execute(
        "FOR f IN findings "
        "FILTER f.tenant_id == @tenant_id AND f.resource_id == @resource_id AND f.status == 'FAIL' "
        "COLLECT severity = f.severity WITH COUNT INTO count "
        "RETURN {severity, count}",
        bind_vars={"tenant_id": tenant_id, "resource_id": resource_id},
    )
    return {row["severity"]: row["count"] for row in cursor}


def _count_attack_paths(db: StandardDatabase, tenant_id: str, resource_key: str) -> int:
    if not db.has_collection("attack_paths"):
        return 0
    vertex_id = f"resources/{resource_key}"
    cursor = db.aql.execute(
        "RETURN LENGTH(FOR p IN attack_paths "
        "FILTER p.tenant_id == @tenant_id AND p.status == 'active' AND @vertex_id IN p.path_vertex_ids "
        "RETURN 1)",
        bind_vars={"tenant_id": tenant_id, "vertex_id": vertex_id},
    )
    return int(next(iter(cursor), 0))


def _build_narrative(resource: ResourceDetail, finding_counts: dict[str, int], attack_path_count: int) -> str:
    total_findings = sum(finding_counts.values())
    kind = resource.resource_type.replace("_", " ")
    sentences = [
        f"{resource.name} is a {kind} in {resource.region or 'an unspecified region'}, currently {resource.status}."
    ]

    if total_findings:
        breakdown = ", ".join(f"{finding_counts[sev]} {sev.lower()}" for sev in _SEVERITIES if finding_counts.get(sev))
        plural = "s" if total_findings != 1 else ""
        sentences.append(f"It has {total_findings} open finding{plural} ({breakdown}).")
    else:
        sentences.append("No open findings were detected on this resource.")

    if attack_path_count:
        plural = "s" if attack_path_count != 1 else ""
        sentences.append(f"It participates in {attack_path_count} active attack path{plural}.")

    if resource.is_public:
        sentences.append("This resource is publicly exposed.")

    return " ".join(sentences)


def build_resource_summary(db: StandardDatabase, tenant_id: str, resource: ResourceDetail) -> ResourceNarrativeSummary:
    finding_counts = _count_findings_by_severity(db, tenant_id, resource.resource_id)
    attack_path_count = _count_attack_paths(db, tenant_id, resource.key)
    narrative = _build_narrative(resource, finding_counts, attack_path_count)

    deep_links: list[NarrativeDeepLink] = []
    total_findings = sum(finding_counts.values())
    if total_findings:
        deep_links.append(NarrativeDeepLink(label="findings", tab="risk", subtab="alerts", count=total_findings))
    if attack_path_count:
        deep_links.append(
            NarrativeDeepLink(label="attack paths", tab="risk", subtab="attack_paths", count=attack_path_count)
        )

    return ResourceNarrativeSummary(
        resource_key=resource.key,
        narrative=narrative,
        finding_counts=finding_counts,
        attack_path_count=attack_path_count,
        deep_links=deep_links,
    )


def get_blast_radius(db: StandardDatabase, tenant_id: str, resource_key: str) -> BlastRadiusResponse:
    existing = [c for c in _TRAVERSAL_EDGE_COLLECTIONS if db.has_collection(c)]
    if not existing or not db.has_collection("resources"):
        return BlastRadiusResponse(resource_key=resource_key)

    edges_clause = ", ".join(existing)
    start_id = f"resources/{resource_key}"
    aql = f"""
        LET start = DOCUMENT(@start_id)
        FILTER start != null AND start.tenant_id == @tenant_id
        FOR v, e, p IN 1..@max_depth OUTBOUND @start_id
            {edges_clause}
            OPTIONS {{uniqueVertices: "global", bfs: true}}
            FILTER v.tenant_id == @tenant_id
            RETURN {{
                vertex: v, from: e._from, to: e._to,
                edge_type: PARSE_IDENTIFIER(e._id).collection, hop: LENGTH(p.edges)
            }}
    """
    try:
        rows: list[dict[str, Any]] = list(
            db.aql.execute(
                aql,
                bind_vars={"start_id": start_id, "tenant_id": tenant_id, "max_depth": _MAX_BLAST_RADIUS_DEPTH},
                max_runtime=15,
            )
        )
    except Exception:
        return BlastRadiusResponse(resource_key=resource_key)

    nodes: dict[str, BlastRadiusNode] = {}
    edges: list[BlastRadiusEdge] = []
    grouped_counts: dict[str, int] = {}

    for row in rows:
        vertex = row["vertex"]
        vertex_id = vertex.get("_id", "")
        if not vertex_id:
            continue
        if vertex_id not in nodes:
            resource_type = vertex.get("resource_type", "unknown")
            nodes[vertex_id] = BlastRadiusNode(
                id=vertex_id,
                resource_type=resource_type,
                name=vertex.get("name") or vertex.get("resource_id", vertex_id),
                hop=row["hop"],
            )
            grouped_counts[resource_type] = grouped_counts.get(resource_type, 0) + 1
        edges.append(BlastRadiusEdge(source=row["from"], target=row["to"], edge_type=row["edge_type"]))

    return BlastRadiusResponse(
        resource_key=resource_key,
        nodes=list(nodes.values()),
        edges=edges,
        grouped_counts=grouped_counts,
    )


def get_resource_compliance(
    db: StandardDatabase, tenant_id: str, resource: ResourceDetail, framework: str | None = None
) -> ResourceComplianceResponse:
    """Per-resource compliance view (US-14.07): available framework prefixes for this
    resource's findings, plus the control table for one selected framework (defaults
    to the first available one, mirroring the global Compliance page's version switcher).
    """
    if not db.has_collection("findings"):
        return ResourceComplianceResponse(resource_key=resource.key)

    rows = list(
        db.aql.execute(
            "FOR f IN findings "
            "FILTER f.tenant_id == @tenant_id AND f.resource_id == @resource_id "
            'FILTER f.status IN ["FAIL", "PASS"] '
            "FOR fw IN f.framework_mapping "
            'LET parts = SPLIT(fw, "/", 2) '
            "RETURN {prefix: parts[0], control: (LENGTH(parts) > 1 ? parts[1] : null), "
            "finding_key: f._key, status: f.status, title: f.title, severity: f.severity}",
            bind_vars={"tenant_id": tenant_id, "resource_id": resource.resource_id},
        )
    )

    prefixes = sorted({row["prefix"] for row in rows})
    available = [
        ResourceComplianceFrameworkOption(id=prefix, label=f"{resolve_family(prefix)[1]} {resolve_family(prefix)[2]}")
        for prefix in prefixes
    ]

    selected = framework if framework in prefixes else (prefixes[0] if prefixes else None)
    controls: list[ResourceComplianceControl] = []
    if selected:
        family_key = resolve_family(selected)[0]
        for row in rows:
            if row["prefix"] != selected:
                continue
            _, category = derive_section(row["control"], family_key)
            controls.append(
                ResourceComplianceControl(
                    control_id=row["control"],
                    status=row["status"],
                    title=row["title"],
                    category=category,
                    severity=row["severity"],
                    finding_key=row["finding_key"],
                )
            )

    return ResourceComplianceResponse(
        resource_key=resource.key,
        available_frameworks=available,
        selected_framework=selected,
        controls=controls,
    )
