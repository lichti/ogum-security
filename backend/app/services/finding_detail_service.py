from __future__ import annotations

from arango.database import StandardDatabase

from app.models.inventory_detail import BlastRadiusResponse
from app.services.findings_service import get_finding
from app.services.inventory_detail_service import get_blast_radius


def _resolve_resource_key(db: StandardDatabase, tenant_id: str, resource_id: str) -> str | None:
    if not db.has_collection("resources"):
        return None
    cursor = db.aql.execute(
        "FOR r IN resources FILTER r.tenant_id == @tenant_id AND r.resource_id == @resource_id LIMIT 1 RETURN r._key",
        bind_vars={"tenant_id": tenant_id, "resource_id": resource_id},
    )
    return next(iter(cursor), None)


def get_finding_exposure_path(db: StandardDatabase, tenant_id: str, finding_key: str) -> BlastRadiusResponse | None:
    """Finding exposure-path mini-graph (US-14.09) — reuses the resource blast-radius

    traversal (`inventory_detail_service.get_blast_radius`) rooted at the finding's
    own resource, rather than duplicating the AQL traversal.
    """
    finding = get_finding(db, finding_key, tenant_id)
    if finding is None:
        return None

    resource_key = _resolve_resource_key(db, tenant_id, finding["resource_id"])
    if resource_key is None:
        return BlastRadiusResponse(resource_key=finding_key)

    return get_blast_radius(db, tenant_id, resource_key)
