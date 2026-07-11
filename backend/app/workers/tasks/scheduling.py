"""
Celery Beat scheduling and distributed discovery locks.

trigger_all_discoveries routes discovery jobs to provider-specific tasks —
Azure/GCP/K8s only; AWS inventory is built entirely by CSPM scans (see
run_cspm_scan), so there is no separate AWS discovery task to route to.
trigger_all_cspm_scans iterates all tenants and provider configs and dispatches
run_cspm_scan for each enabled provider. Both use Redis distributed locks to
prevent concurrent runs.
"""

from __future__ import annotations

import logging
from typing import Any

from redis import Redis

from app.models.inventory import Provider
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

_LOCK_TTL_SECONDS = 3600 * 7  # 7 hours — upper bound for a full discovery or scan run

# Providers run_cspm_scan/_dispatch_scan know how to route — trigger_all_cspm_scans
# skips anything else (e.g. a provider config in a still-unsupported state).
_CSPM_SUPPORTED_PROVIDERS = frozenset({"aws", "azure", "gcp", "k8s", "kubernetes"})


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

    AWS is not routed here — trigger_all_cspm_scans dispatches run_cspm_scan
    for AWS providers directly, since a CSPM scan is itself the full AWS
    discovery pass.
    """
    from app.workers.tasks.azure_discovery import discover_azure
    from app.workers.tasks.gcp_discovery import discover_gcp
    from app.workers.tasks.k8s_discovery import discover_k8s

    if provider == Provider.AZURE:
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


@celery_app.task(name="app.workers.tasks.scheduling.trigger_all_cspm_scans")
def trigger_all_cspm_scans() -> dict[str, Any]:
    """
    Celery Beat router: dispatches run_cspm_scan for every enabled provider
    across all tenants.

    Reads tenant list from ArangoDB system DB, then reads each tenant's
    provider configs (including stored credentials) and dispatches one
    run_cspm_scan task per enabled provider. Skips providers with no
    supported CSPM framework (e.g. k8s).
    """
    from arango import ArangoClient

    from app.core.config import settings
    from app.services.provider_service import get_provider_credentials, list_providers
    from app.workers.tasks.cspm_scan import run_cspm_scan

    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    sys_db = client.db("_system", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)

    tenant_ids = [
        db_name[len("ogum_") :]
        for db_name in sys_db.databases()
        if db_name.startswith("ogum_") and db_name != "ogum_admin"
    ]

    dispatched = 0
    skipped = 0

    for tenant_id in tenant_ids:
        try:
            tenant_db = client.db(
                f"ogum_{tenant_id}",
                username=settings.ARANGO_USER,
                password=settings.ARANGO_PASSWORD,
            )
            providers = list_providers(tenant_db)
        except Exception:
            logger.exception("Failed to list providers for tenant=%s", tenant_id)
            continue

        for cfg in providers:
            if not cfg.enabled:
                skipped += 1
                continue
            if cfg.provider not in _CSPM_SUPPORTED_PROVIDERS:
                skipped += 1
                continue

            try:
                credentials = get_provider_credentials(tenant_db, cfg.key)
                account_id = cfg.account_id or cfg.subscription_id or cfg.project_id or ""

                run_cspm_scan.apply_async(
                    kwargs={
                        "tenant_id": tenant_id,
                        "provider_id": cfg.key,
                        "provider": cfg.provider,
                        # None -> Prowler's full check catalog, not a curated subset.
                        "frameworks": None,
                        "credentials": credentials,
                        "account_id": account_id,
                        "regions": cfg.regions or None,
                    }
                )
                dispatched += 1
                logger.info(
                    "Dispatched CSPM scan [tenant=%s provider=%s account=%s frameworks=full-catalog]",
                    tenant_id,
                    cfg.provider,
                    account_id,
                )
            except Exception:
                logger.exception(
                    "Failed to dispatch CSPM scan [tenant=%s provider=%s]",
                    tenant_id,
                    cfg.key,
                )
                skipped += 1

    logger.info("trigger_all_cspm_scans complete: dispatched=%d skipped=%d", dispatched, skipped)
    return {"dispatched": dispatched, "skipped": skipped}
