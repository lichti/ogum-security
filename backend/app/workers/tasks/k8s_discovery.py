"""
Kubernetes discovery task — Pods, Deployments, Services, Nodes, Namespaces.

K8s SDK calls are mocked at the API class level in tests via pytest-mock.
ArangoDB upserts are idempotent: re-running discovery never duplicates resources.
Resources absent from the current scan are soft-deleted (status: "deleted").
"""
from __future__ import annotations

import logging
from typing import Any

from kubernetes import config as k8s_config
from kubernetes.client import AppsV1Api, CoreV1Api
from redis import Redis

from app.core.config import settings
from app.db.init import init_tenant_schema
from app.models.inventory import K8sResource, Provider
from app.workers.celery_app import celery_app
from app.workers.tasks.discovery import _get_tenant_db, _mark_stale_deleted, _upsert
from app.workers.tasks.scheduling import acquire_lock, release_lock

logger = logging.getLogger(__name__)

_ALL_K8S_RESOURCE_TYPES = [
    "pod",
    "deployment",
    "service",
    "node",
    "namespace",
]


# ─── Resource list helpers ────────────────────────────────────────────────────

def _list_pods(
    core_v1: CoreV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    pods: list[K8sResource] = []
    for pod in core_v1.list_pod_for_all_namespaces().items:
        meta = pod.metadata
        spec = pod.spec
        pods.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="pod",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "phase": pod.status.phase if pod.status else None,
                    "node_name": spec.node_name if spec else None,
                    "container_count": len(spec.containers) if spec else 0,
                    "restart_policy": spec.restart_policy if spec else None,
                },
            )
        )
    return pods


def _list_deployments(
    apps_v1: AppsV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    deployments: list[K8sResource] = []
    for deploy in apps_v1.list_deployment_for_all_namespaces().items:
        meta = deploy.metadata
        spec = deploy.spec
        status = deploy.status
        deployments.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="deployment",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "replicas": spec.replicas if spec else None,
                    "ready_replicas": status.ready_replicas if status else None,
                    "available_replicas": status.available_replicas if status else None,
                },
            )
        )
    return deployments


def _list_services(
    core_v1: CoreV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    services: list[K8sResource] = []
    for svc in core_v1.list_service_for_all_namespaces().items:
        meta = svc.metadata
        spec = svc.spec
        svc_type = spec.type if spec else None
        is_public = svc_type == "LoadBalancer"
        ports = [
            {"port": p.port, "protocol": p.protocol, "target_port": str(p.target_port)}
            for p in (spec.ports or [])
        ] if spec else []
        services.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="service",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                is_public=is_public,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "service_type": svc_type,
                    "cluster_ip": spec.cluster_ip if spec else None,
                    "ports": ports,
                },
            )
        )
    return services


def _list_nodes(
    core_v1: CoreV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    nodes: list[K8sResource] = []
    for node in core_v1.list_node().items:
        meta = node.metadata
        info = node.status.node_info if node.status else None
        nodes.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="node",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "kubelet_version": info.kubelet_version if info else None,
                    "os_image": info.os_image if info else None,
                    "container_runtime": info.container_runtime_version if info else None,
                    "architecture": info.architecture if info else None,
                },
            )
        )
    return nodes


def _list_namespaces(
    core_v1: CoreV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    nss: list[K8sResource] = []
    for ns in core_v1.list_namespace().items:
        meta = ns.metadata
        status = ns.status
        nss.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="namespace",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "phase": status.phase if status else None,
                },
            )
        )
    return nss


# ─── Celery task ──────────────────────────────────────────────────────────────

@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def discover_k8s(
    self: Any,
    tenant_id: str,
    cluster_name: str,
    kubeconfig: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Discover all Kubernetes resources in a cluster and persist them to ArangoDB.

    Args:
        tenant_id: Ogum tenant identifier.
        cluster_name: Logical cluster name (used as part of ArangoDB key).
        kubeconfig: Kubeconfig dict for remote clusters. None → in-cluster config.
    """
    redis = Redis.from_url(settings.REDIS_URL)
    if not acquire_lock(redis, tenant_id, "k8s"):
        logger.info("K8s discovery already running for tenant=%s — skipped", tenant_id)
        return {"skipped": True, "tenant_id": tenant_id, "provider": "k8s"}

    try:
        if kubeconfig:
            k8s_config.load_kube_config_from_dict(kubeconfig)
        else:
            k8s_config.load_incluster_config()

        core_v1 = CoreV1Api()
        apps_v1 = AppsV1Api()

        db = _get_tenant_db(tenant_id)
        init_tenant_schema(db)

        resource_keys: set[str] = set()

        for resource in _list_pods(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_deployments(apps_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_services(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_nodes(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_namespaces(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        deleted = _mark_stale_deleted(
            db,
            collection="resources",
            tenant_id=tenant_id,
            provider=Provider.K8S,
            type_field="resource_type",
            type_values=_ALL_K8S_RESOURCE_TYPES,
            regions=None,
            discovered_keys=resource_keys,
        )

        logger.info(
            "K8s discovery complete [tenant=%s cluster=%s]: discovered=%d deleted=%d",
            tenant_id, cluster_name, len(resource_keys), deleted,
        )
        return {
            "tenant_id": tenant_id,
            "provider": "k8s",
            "cluster_name": cluster_name,
            "discovered": len(resource_keys),
            "deleted": deleted,
        }

    except Exception as exc:
        logger.exception("K8s discovery failed [tenant=%s cluster=%s]: %s", tenant_id, cluster_name, exc)
        raise self.retry(exc=exc)

    finally:
        release_lock(redis, tenant_id, "k8s")
