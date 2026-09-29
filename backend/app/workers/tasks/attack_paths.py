"""
Attack path detection and risk score recalculation tasks (Epic 02 Sprint 1).

Tasks enqueued automatically after each CSPM scan completes:
  1. recalculate_risk_scores — bulk-updates risk_score on all resources
  2. detect_attack_paths — AQL traversal to find paths + toxic combinations
"""

from __future__ import annotations

import logging
from typing import Any

from app.db.init import init_tenant_schema
from app.services.attack_path_service import run_attack_path_detection
from app.services.risk_score import _SEVERITY_WEIGHTS, _TRAVERSAL_EDGES
from app.workers.celery_app import celery_app
from app.workers.tasks.cloud_utils import _get_tenant_db

logger = logging.getLogger(__name__)

_VERTEX_COLLECTIONS = ["resources", "identities", "network_endpoints", "data_assets"]


# Fórmula fiel a app/services/risk_score.py (calculate_resource_risk_score),
# executada inteira dentro do ArangoDB: 1 query por coleção em vez de
# 2 roundtrips + 1 update por recurso (US-00.11).
_RISK_BATCH_AQL = """
FOR r IN @@col
    FILTER r.tenant_id == @tenant_id
    LET rid = r.resource_id ? r.resource_id : r._key
    LET sev = (
        FOR f IN findings
            FILTER f.tenant_id == @tenant_id
            FILTER f.resource_id == rid
            FILTER f.status == "FAIL"
            COLLECT s = f.severity WITH COUNT INTO cnt
            RETURN { sev: s, cnt: cnt }
    )
    LET raw_base = SUM(
        FOR x IN sev
            RETURN (@weights[x.sev] || 1.0) * x.cnt
    )
    LET exposure = (r.is_public == true || r.is_internet_facing == true) ? 2.0 : 1.0
    LET reachable = LENGTH(
        FOR v IN 1..3 OUTBOUND CONCAT(@colname, '/', r._key) @traversal_edges
            PRUNE v.tenant_id != @tenant_id
            FILTER v.tenant_id == @tenant_id
            FILTER STARTS_WITH(v._id, "data_assets/")
            RETURN DISTINCT v._id
    )
    LET blast = 1.0 + MIN([reachable / 5.0, 1.0])
    LET score0 = raw_base == 0 ? 0.0 : MIN([MIN([raw_base, 50.0]) * exposure * blast, 100.0])
    LET score = r.in_attack_path == true ? MAX([score0, 40.0]) : score0
    UPDATE r._key WITH { risk_score: ROUND(score * 100) / 100 } IN @@col
    RETURN { key: r._key, score: score }
"""


@celery_app.task(bind=True, max_retries=1, default_retry_delay=60)
def recalculate_risk_scores(self: Any, tenant_id: str) -> dict[str, Any]:
    """
    Recalculate and persist risk_score for every resource in the tenant graph.

    US-00.11: batch AQL — uma query por coleção (o loop N+1 com 2 roundtrips
    por recurso virou computação no banco com UPDATE embutido).
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    updated = 0
    errors = 0
    traversal = ", ".join(_TRAVERSAL_EDGES)

    for collection in _VERTEX_COLLECTIONS:
        try:
            cursor = db.aql.execute(
                _RISK_BATCH_AQL.replace("@traversal_edges", traversal),
                bind_vars={
                    "@col": collection,
                    "colname": collection,
                    "tenant_id": tenant_id,
                    "weights": _weights_dict(),
                },
            )
            rows = list(cursor)
            updated += len(rows)
        except Exception:
            errors += 1
            logger.exception("Risk score recalculation failed for collection=%s tenant=%s", collection, tenant_id)

    logger.info(
        "Risk scores recalculated [tenant=%s]: updated=%d errors=%d",
        tenant_id,
        updated,
        errors,
    )
    return {"tenant_id": tenant_id, "updated": updated, "errors": errors}


def _weights_dict() -> dict[str, float]:
    return dict(_SEVERITY_WEIGHTS)


@celery_app.task(bind=True, max_retries=1, default_retry_delay=60)
def detect_attack_paths(self: Any, tenant_id: str, max_depth: int = 4) -> dict[str, Any]:
    """
    Run full attack path detection pipeline for a tenant.

    Executes graph traversal queries, detects toxic combinations,
    and persists results in the attack_paths collection.
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    try:
        result = run_attack_path_detection(db, tenant_id, max_depth=max_depth)
        logger.info(
            "Attack path detection complete [tenant=%s]: %s",
            tenant_id,
            result,
        )
        return {"tenant_id": tenant_id, **result}
    except Exception as exc:
        logger.exception("Attack path detection failed [tenant=%s]: %s", tenant_id, exc)
        raise self.retry(exc=exc)
