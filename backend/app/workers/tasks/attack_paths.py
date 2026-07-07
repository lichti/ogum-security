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
from app.services.risk_score import calculate_resource_risk_score
from app.workers.celery_app import celery_app
from app.workers.tasks.discovery import _get_tenant_db

logger = logging.getLogger(__name__)

_VERTEX_COLLECTIONS = ["resources", "identities", "network_endpoints", "data_assets"]


@celery_app.task(bind=True, max_retries=1, default_retry_delay=60)
def recalculate_risk_scores(self: Any, tenant_id: str) -> dict[str, Any]:
    """
    Recalculate and persist risk_score for every resource in the tenant graph.

    Updates the risk_score field in-place using bulk AQL updates.
    Runs after each CSPM scan so scores reflect the latest finding state.
    """
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    updated = 0
    errors = 0

    for collection in _VERTEX_COLLECTIONS:
        try:
            col = db.collection(collection)
            cursor = db.aql.execute(
                """
                FOR r IN @@col
                    FILTER r.tenant_id == @tenant_id
                    RETURN {_key: r._key, in_attack_path: r.in_attack_path}
                """,
                bind_vars={"@col": collection, "tenant_id": tenant_id},
            )

            for row in cursor:
                resource_key: str = row["_key"]
                in_path: bool = bool(row.get("in_attack_path"))
                try:
                    score = calculate_resource_risk_score(
                        db,
                        resource_key,
                        tenant_id,
                        collection=collection,
                        in_attack_path=in_path,
                    )
                    col.update({"_key": resource_key, "risk_score": score})
                    updated += 1
                except Exception:
                    errors += 1
                    logger.debug("Risk score failed for %s/%s", collection, resource_key)

        except Exception:
            logger.exception("Risk score recalculation failed for collection=%s tenant=%s", collection, tenant_id)

    logger.info(
        "Risk scores recalculated [tenant=%s]: updated=%d errors=%d",
        tenant_id,
        updated,
        errors,
    )
    return {"tenant_id": tenant_id, "updated": updated, "errors": errors}


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
