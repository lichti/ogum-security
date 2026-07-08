"""
Celery tasks for IAM deep model and session refresh (Sprint 6).
"""

from __future__ import annotations

import logging

from celery import shared_task

from app.core.config import settings
from app.services.graph.exposure import compute_exposed_internet
from app.services.graph.iam_edges import build_iam_edges

logger = logging.getLogger(__name__)


@shared_task(
    name="app.workers.tasks.graph.build_iam_graph_edges",
    bind=True,
    max_retries=2,
    default_retry_delay=30,
)
def build_iam_graph_edges(self: object, tenant_id: str, provider_id: str | None = None) -> dict:  # pragma: no cover
    """
    Build IAM deep model edges (STS_ASSUMEROLE_ALLOW, ASSUMES, ATTACHED_POLICY)
    from identity metadata already in ArangoDB. No AWS API calls.
    """
    from arango import ArangoClient

    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    db = client.db(f"ogum_{tenant_id}", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)

    edge_counts = build_iam_edges(db, tenant_id)
    exposure_counts = compute_exposed_internet(db, tenant_id)

    result = {
        "tenant_id": tenant_id,
        "provider_id": provider_id,
        "iam_edges": edge_counts,
        "exposure_updated": exposure_counts,
    }
    logger.info("build_iam_graph_edges completed: %s", result)
    return result


@shared_task(
    name="app.workers.tasks.graph.refresh_active_sessions_from_cloudtrail",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def refresh_active_sessions_from_cloudtrail(self: object, tenant_id: str) -> dict:  # pragma: no cover
    """
    Stub: refresh HAS_ACTIVE_SESSION edges from CloudTrail AssumeRole events.
    Full implementation deferred to Epic 05 (Pulse / NRT pipeline).
    """
    logger.info(
        "refresh_active_sessions_from_cloudtrail: tenant=%s — deferred to Epic 05 (Pulse)",
        tenant_id,
    )
    return {"tenant_id": tenant_id, "status": "deferred", "reason": "Epic 05 — NRT pipeline not yet available"}
