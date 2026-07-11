from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "ogum-security",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.tasks.scheduling",
        "app.workers.tasks.azure_discovery",
        "app.workers.tasks.gcp_discovery",
        "app.workers.tasks.k8s_discovery",
        "app.workers.tasks.cspm_scan",
        "app.workers.tasks.iac_scan",
        "app.workers.tasks.attack_paths",
        "app.workers.tasks.graph",
        "app.workers.tasks.side_scanning",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
)

# Default beat schedule for local development.
# Sprint 7 will replace this with a database-driven schedule per tenant.
celery_app.conf.beat_schedule = {
    # A CSPM scan is the sole inventory-building pass for AWS — it persists
    # findings, resources/identities/data_assets, and graph edges in one run,
    # so no separate discovery step (and no offset to wait for one) is needed.
    # trigger_all_cspm_scans reads all tenants and provider configs from ArangoDB
    # and dispatches run_cspm_scan for each enabled provider automatically.
    "cspm-scan-all-tenants-every-6h": {
        "task": "app.workers.tasks.scheduling.trigger_all_cspm_scans",
        "schedule": 6 * 3600,
    },
    # Sprint 2 (Epic 03): daily SBOM rescan for new CVEs (dev tenant only;
    # Sprint 7 will replace with per-tenant scheduling from ArangoDB)
    "rescan-sboms-daily": {
        "task": "app.workers.tasks.side_scanning.rescan_sboms",
        "schedule": crontab(hour=3, minute=0),
        "kwargs": {"tenant_id": "dev"},
    },
}
