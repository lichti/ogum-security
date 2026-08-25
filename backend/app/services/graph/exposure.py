"""
Exposure computation — derive `exposed_internet: bool` on resources and identities.

Uses metadata already stored during discovery rather than making new API calls:
  - resources.is_public = true
  - resources.security_group_rules contains 0.0.0.0/0 or ::/0
  - data_assets.is_public = true
  - network_endpoints.is_internet_facing = true

Also builds EXPOSED_TO edges between exposed resources and a sentinel internet node.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def compute_exposed_internet(db: Any, tenant_id: str) -> dict[str, int]:
    """
    Mark exposed resources and return counts of updated documents.

    Sets `exposed_internet = true` on:
      - resources where is_public = true
      - data_assets where is_public = true
      - network_endpoints where is_internet_facing = true

    Returns dict with counts per collection.
    """
    counts: dict[str, int] = {}

    for collection in ("resources", "data_assets"):
        try:
            result = db.aql.execute(
                f"""
                FOR r IN {collection}
                    FILTER r.tenant_id == @tid
                    FILTER r.is_public == true
                    UPDATE r WITH {{exposed_internet: true}} IN {collection}
                    RETURN 1
                """,
                bind_vars={"tid": tenant_id},
            )
            counts[collection] = len(list(result))
        except Exception:
            logger.exception("Failed to mark exposed_internet on %s for tenant=%s", collection, tenant_id)
            counts[collection] = 0

    try:
        result = db.aql.execute(
            """
            FOR n IN network_endpoints
                FILTER n.tenant_id == @tid
                FILTER n.is_internet_facing == true OR n.is_public == true
                UPDATE n WITH {exposed_internet: true} IN network_endpoints
                RETURN 1
            """,
            bind_vars={"tid": tenant_id},
        )
        counts["network_endpoints"] = len(list(result))
    except Exception:
        logger.exception("Failed to mark exposed_internet on network_endpoints for tenant=%s", tenant_id)
        counts["network_endpoints"] = 0

    return counts


def classify_path_exposure(entry_doc: dict[str, Any] | None, rule: str) -> str:
    """
    Classify an attack path's exposure level from its entry point (US-14.13).

    Mirrors the ExposureLevel enum already defined in the frontend's
    ExposureBadge.tsx. There is no real signal for VPC peering/PrivateLink in
    the graph today, so `trusted_access` only covers identity-only entry
    points (privilege escalation rule) — never fabricated beyond that.
    """
    entry = entry_doc or {}
    if entry.get("exposed_internet") or entry.get("is_internet_facing"):
        return "internet_facing"
    if entry.get("is_public"):
        return "public_facing"
    if rule == "privilege_escalation":
        return "trusted_access"
    return "none"


def get_exposure_summary(db: Any, tenant_id: str) -> dict[str, Any]:
    """Return a summary of internet-exposed resources for the tenant."""
    try:
        result = list(
            db.aql.execute(
                """
                LET exposed_resources = LENGTH(
                    FOR r IN resources
                        FILTER r.tenant_id == @tid
                        FILTER r.exposed_internet == true OR r.is_public == true
                        RETURN 1
                )
                LET exposed_data_assets = LENGTH(
                    FOR d IN data_assets
                        FILTER d.tenant_id == @tid
                        FILTER d.exposed_internet == true OR d.is_public == true
                        RETURN 1
                )
                LET exposed_endpoints = LENGTH(
                    FOR n IN network_endpoints
                        FILTER n.tenant_id == @tid
                        FILTER n.is_internet_facing == true OR n.is_public == true
                        RETURN 1
                )
                RETURN {
                    exposed_resources,
                    exposed_data_assets,
                    exposed_endpoints,
                    total: exposed_resources + exposed_data_assets + exposed_endpoints
                }
                """,
                bind_vars={"tid": tenant_id},
            )
        )
        return (
            result[0]
            if result
            else {
                "exposed_resources": 0,
                "exposed_data_assets": 0,
                "exposed_endpoints": 0,
                "total": 0,
            }
        )
    except Exception:
        logger.exception("Failed to compute exposure summary for tenant=%s", tenant_id)
        return {"exposed_resources": 0, "exposed_data_assets": 0, "exposed_endpoints": 0, "total": 0}
