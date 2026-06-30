"""
Celery Beat scheduling and distributed discovery locks.

trigger_all_discoveries is the Beat entry point that routes discovery jobs to
provider-specific tasks. Each provider task acquires and releases its own Redis
distributed lock to prevent concurrent runs when the beat interval is shorter
than the discovery duration.
"""

from __future__ import annotations

import logging
from typing import Any

from redis import Redis

from app.models.inventory import Provider
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

_LOCK_TTL_SECONDS = 3600 * 7  # 7 hours — upper bound for a full discovery run


def acquire_lock(redis: Redis, tenant_id: str, provider: str) -> bool:
    """Try to acquire a per-tenant, per-provider distributed lock. Returns True if acquired."""
    key = f"ogum:discovery:lock:{tenant_id}:{provider}"
    return bool(redis.set(key, "1", nx=True, ex=_LOCK_TTL_SECONDS))


def release_lock(redis: Redis, tenant_id: str, provider: str) -> None:
    """Release the distributed lock for a given tenant and provider."""
    redis.delete(f"ogum:discovery:lock:{tenant_id}:{provider}")


@celery_app.task(name="app.workers.tasks.scheduling.trigger_all_discoveries")
def trigger_all_discoveries(tenant_id: str, provider: str, **kwargs: Any) -> dict[str, Any]:
    """
    Celery Beat router: dispatches a provider discovery task for a given tenant.

    The Beat schedule calls this with (tenant_id, provider, **credentials).
    Each dispatched discovery task manages its own Redis lock so concurrent
    runs are skipped rather than stacked.
    """
    # Lazy imports prevent circular dependencies at module load time.
    from app.workers.tasks.azure_discovery import discover_azure
    from app.workers.tasks.discovery import discover_aws
    from app.workers.tasks.gcp_discovery import discover_gcp
    from app.workers.tasks.k8s_discovery import discover_k8s

    if provider == Provider.AWS:
        regions: list[str] = kwargs.pop("regions", ["us-east-1"])
        discover_aws.apply_async(args=[tenant_id, regions], kwargs=kwargs)
    elif provider == Provider.AZURE:
        discover_azure.apply_async(kwargs={"tenant_id": tenant_id, **kwargs})
    elif provider == Provider.GCP:
        discover_gcp.apply_async(kwargs={"tenant_id": tenant_id, **kwargs})
    elif provider == Provider.K8S:
        discover_k8s.apply_async(kwargs={"tenant_id": tenant_id, **kwargs})
    else:
        logger.warning("Unknown provider '%s' for tenant=%s — task not dispatched", provider, tenant_id)
        return {"dispatched": False, "reason": f"unknown_provider:{provider}"}

    logger.info("Dispatched %s discovery for tenant=%s", provider, tenant_id)
    return {"dispatched": True, "tenant_id": tenant_id, "provider": provider}
