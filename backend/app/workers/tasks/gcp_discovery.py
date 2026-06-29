"""
GCP discovery task — Compute instances, GCS buckets, GKE clusters.

GCP SDK calls are mocked at the SDK class level in tests via pytest-mock.
ArangoDB upserts are idempotent: re-running discovery never duplicates resources.
Resources absent from the current scan are soft-deleted (status: "deleted").
"""
from __future__ import annotations

import logging
from typing import Any

from google.cloud.compute_v1 import InstancesClient
from google.cloud.container_v1 import ClusterManagerClient
from google.cloud.storage import Client as GCSClient
from google.oauth2.service_account import Credentials as SACredentials
from redis import Redis

from app.core.config import settings
from app.db.init import init_tenant_schema
from app.models.inventory import GCPResource, Provider
from app.workers.celery_app import celery_app
from app.workers.tasks.discovery import _get_tenant_db, _mark_stale_deleted, _upsert
from app.workers.tasks.scheduling import acquire_lock, release_lock

logger = logging.getLogger(__name__)

_GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

_ALL_GCP_RESOURCE_TYPES = [
    "compute_instance",
    "gcs_bucket",
    "gke_cluster",
]


# ─── Resource list helpers ────────────────────────────────────────────────────

def _list_compute_instances(
    instances_client: InstancesClient,
    tenant_id: str,
    project_id: str,
) -> list[GCPResource]:
    instances: list[GCPResource] = []
    for zone_name, scope in instances_client.aggregated_list(project=project_id):
        for inst in scope.instances or []:
            zone = zone_name.split("/")[-1] if "/" in zone_name else zone_name
            machine_type = inst.machine_type.split("/")[-1] if inst.machine_type else None
            network = None
            nis = list(inst.network_interfaces or [])
            is_public = any(list(ni.access_configs or []) for ni in nis)
            if nis:
                net = nis[0].network or ""
                network = net.split("/")[-1]
            instances.append(
                GCPResource(
                    tenant_id=tenant_id,
                    resource_type="compute_instance",
                    resource_id=f"{project_id}_{zone}_{inst.name}",
                    name=inst.name,
                    region=zone,
                    account_id=project_id,
                    project_id=project_id,
                    tags={k: v for k, v in (inst.labels or {}).items()},
                    is_public=is_public,
                    raw_metadata={
                        "machine_type": machine_type,
                        "status": inst.status,
                        "zone": zone,
                        "network": network,
                        "gcp_instance_id": str(inst.id),
                    },
                )
            )
    return instances


def _list_gcs_buckets(
    storage_client: GCSClient,
    tenant_id: str,
    project_id: str,
) -> list[GCPResource]:
    buckets: list[GCPResource] = []
    for bucket in storage_client.list_buckets():
        buckets.append(
            GCPResource(
                tenant_id=tenant_id,
                resource_type="gcs_bucket",
                resource_id=bucket.name,
                name=bucket.name,
                region=(bucket.location or "").lower() or None,
                account_id=project_id,
                project_id=project_id,
                tags={k: v for k, v in (bucket.labels or {}).items()},
                raw_metadata={
                    "storage_class": bucket.storage_class,
                    "location_type": bucket.location_type,
                    "requester_pays": bucket.requester_pays,
                    "versioning_enabled": bucket.versioning_enabled,
                },
            )
        )
    return buckets


def _list_gke_clusters(
    cluster_client: ClusterManagerClient,
    tenant_id: str,
    project_id: str,
) -> list[GCPResource]:
    clusters: list[GCPResource] = []
    response = cluster_client.list_clusters(parent=f"projects/{project_id}/locations/-")
    for cluster in response.clusters:
        status_name = cluster.status.name if cluster.status else None
        clusters.append(
            GCPResource(
                tenant_id=tenant_id,
                resource_type="gke_cluster",
                resource_id=f"{project_id}_{cluster.location}_{cluster.name}",
                name=cluster.name,
                region=cluster.location,
                account_id=project_id,
                project_id=project_id,
                tags={k: v for k, v in (cluster.resource_labels or {}).items()},
                raw_metadata={
                    "kubernetes_version": cluster.current_master_version,
                    "status": status_name,
                    "node_count": cluster.current_node_count,
                    "location": cluster.location,
                },
            )
        )
    return clusters


# ─── Celery task ──────────────────────────────────────────────────────────────

@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def discover_gcp(
    self: Any,
    tenant_id: str,
    project_id: str,
    service_account_info: dict[str, Any],
) -> dict[str, Any]:
    """
    Discover all GCP resources in a project and persist them to ArangoDB.

    Args:
        tenant_id: Ogum tenant identifier.
        project_id: GCP project ID.
        service_account_info: Service account JSON as a dict (never stored — used only for auth).
    """
    redis = Redis.from_url(settings.REDIS_URL)
    if not acquire_lock(redis, tenant_id, "gcp"):
        logger.info("GCP discovery already running for tenant=%s — skipped", tenant_id)
        return {"skipped": True, "tenant_id": tenant_id, "provider": "gcp"}

    try:
        credentials = SACredentials.from_service_account_info(
            service_account_info, scopes=_GCP_SCOPES
        )

        instances_client = InstancesClient(credentials=credentials)
        storage_client = GCSClient(project=project_id, credentials=credentials)
        cluster_client = ClusterManagerClient(credentials=credentials)

        db = _get_tenant_db(tenant_id)
        init_tenant_schema(db)

        resource_keys: set[str] = set()

        for resource in _list_compute_instances(instances_client, tenant_id, project_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_gcs_buckets(storage_client, tenant_id, project_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_gke_clusters(cluster_client, tenant_id, project_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        deleted = _mark_stale_deleted(
            db,
            collection="resources",
            tenant_id=tenant_id,
            provider=Provider.GCP,
            type_field="resource_type",
            type_values=_ALL_GCP_RESOURCE_TYPES,
            regions=None,
            discovered_keys=resource_keys,
        )

        logger.info(
            "GCP discovery complete [tenant=%s project=%s]: discovered=%d deleted=%d",
            tenant_id, project_id, len(resource_keys), deleted,
        )
        return {
            "tenant_id": tenant_id,
            "provider": "gcp",
            "discovered": len(resource_keys),
            "deleted": deleted,
        }

    except Exception as exc:
        logger.exception("GCP discovery failed [tenant=%s]: %s", tenant_id, exc)
        raise self.retry(exc=exc)

    finally:
        release_lock(redis, tenant_id, "gcp")
