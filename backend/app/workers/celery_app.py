from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "ogum-security",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.tasks.discovery",
        "app.workers.tasks.scheduling",
        "app.workers.tasks.azure_discovery",
        "app.workers.tasks.gcp_discovery",
        "app.workers.tasks.k8s_discovery",
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
    "dev-trigger-aws-every-6h": {
        "task": "app.workers.tasks.scheduling.trigger_all_discoveries",
        "schedule": 6 * 3600,  # seconds
        "args": ["dev", "aws"],
        "kwargs": {"regions": ["us-east-1"]},
    },
}
