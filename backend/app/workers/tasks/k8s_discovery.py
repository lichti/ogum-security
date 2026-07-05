"""
Kubernetes discovery task — Pods, Deployments, DaemonSets, StatefulSets, Services,
Ingresses, NetworkPolicies, ServiceAccounts, ClusterRoles, ClusterRoleBindings,
Nodes, Namespaces, PersistentVolumes.

K8s SDK calls are mocked at the API class level in tests via pytest-mock.
ArangoDB upserts are idempotent: re-running discovery never duplicates resources.
Resources absent from the current scan are soft-deleted (status: "deleted").
"""

from __future__ import annotations

import logging
from typing import Any

from kubernetes import config as k8s_config
from kubernetes.client import AppsV1Api, CoreV1Api, NetworkingV1Api, RbacAuthorizationV1Api
from redis import Redis

from app.core.config import settings
from app.db.init import init_tenant_schema
from app.models.inventory import K8sResource, Provider
from app.workers.celery_app import celery_app
from app.workers.tasks._job_tracking import complete_discovery_job, fail_discovery_job, start_discovery_job
from app.workers.tasks.discovery import (
    _get_tenant_db,
    _mark_stale_deleted,
    _set_provider_status,
    _upsert,
)
from app.workers.tasks.scheduling import acquire_lock, release_lock

logger = logging.getLogger(__name__)

_ALL_K8S_RESOURCE_TYPES = [
    "pod",
    "deployment",
    "daemon_set",
    "stateful_set",
    "service",
    "ingress",
    "network_policy",
    "service_account_k8s",
    "cluster_role",
    "cluster_role_binding",
    "node",
    "namespace",
    "persistent_volume",
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


def _list_daemon_sets(
    apps_v1: AppsV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    daemon_sets: list[K8sResource] = []
    for ds in apps_v1.list_daemon_set_for_all_namespaces().items:
        meta = ds.metadata
        status = ds.status
        daemon_sets.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="daemon_set",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "desired_number_scheduled": status.desired_number_scheduled if status else None,
                    "number_ready": status.number_ready if status else None,
                    "number_available": status.number_available if status else None,
                },
            )
        )
    return daemon_sets


def _list_stateful_sets(
    apps_v1: AppsV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    stateful_sets: list[K8sResource] = []
    for ss in apps_v1.list_stateful_set_for_all_namespaces().items:
        meta = ss.metadata
        spec = ss.spec
        status = ss.status
        stateful_sets.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="stateful_set",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "replicas": spec.replicas if spec else None,
                    "ready_replicas": status.ready_replicas if status else None,
                    "service_name": spec.service_name if spec else None,
                },
            )
        )
    return stateful_sets


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
        ports = (
            [{"port": p.port, "protocol": p.protocol, "target_port": str(p.target_port)} for p in (spec.ports or [])]
            if spec
            else []
        )
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


def _list_ingresses(
    networking_v1: NetworkingV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    ingresses: list[K8sResource] = []
    for ing in networking_v1.list_ingress_for_all_namespaces().items:
        meta = ing.metadata
        spec = ing.spec
        rules = list(spec.rules or []) if spec else []
        has_tls = bool(spec.tls) if spec else False
        hostnames = [r.host for r in rules if r.host]
        ingresses.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="ingress",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                is_public=bool(rules),
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "hostnames": hostnames,
                    "has_tls": has_tls,
                    "rule_count": len(rules),
                    "ingress_class": getattr(spec, "ingress_class_name", None) if spec else None,
                },
            )
        )
    return ingresses


def _list_network_policies(
    networking_v1: NetworkingV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    policies: list[K8sResource] = []
    for np in networking_v1.list_network_policy_for_all_namespaces().items:
        meta = np.metadata
        spec = np.spec
        policy_types = list(spec.policy_types or []) if spec else []
        policies.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="network_policy",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "policy_types": policy_types,
                    "pod_selector": str(spec.pod_selector) if spec and spec.pod_selector else None,
                },
            )
        )
    return policies


def _list_k8s_service_accounts(
    core_v1: CoreV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    service_accounts: list[K8sResource] = []
    for sa in core_v1.list_service_account_for_all_namespaces().items:
        meta = sa.metadata
        secret_count = len(list(sa.secrets or []))
        automount = getattr(sa, "automount_service_account_token", None)
        service_accounts.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="service_account_k8s",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                namespace=meta.namespace,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "secret_count": secret_count,
                    "automount_service_account_token": automount,
                },
            )
        )
    return service_accounts


def _list_cluster_roles(
    rbac_v1: RbacAuthorizationV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    cluster_roles: list[K8sResource] = []
    for cr in rbac_v1.list_cluster_role().items:
        meta = cr.metadata
        resource_id = meta.uid if meta.uid else meta.name
        rule_count = len(list(cr.rules or []))
        is_builtin = meta.name.startswith("system:") if meta.name else False
        cluster_roles.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="cluster_role",
                resource_id=resource_id,
                name=meta.name,
                cluster_name=cluster_name,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "rule_count": rule_count,
                    "is_builtin": is_builtin,
                },
            )
        )
    return cluster_roles


def _list_cluster_role_bindings(
    rbac_v1: RbacAuthorizationV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    bindings: list[K8sResource] = []
    for crb in rbac_v1.list_cluster_role_binding().items:
        meta = crb.metadata
        resource_id = meta.uid if meta.uid else meta.name
        subject_count = len(list(crb.subjects or []))
        role_ref_name = crb.role_ref.name if crb.role_ref else None
        bindings.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="cluster_role_binding",
                resource_id=resource_id,
                name=meta.name,
                cluster_name=cluster_name,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "role_ref": role_ref_name,
                    "subject_count": subject_count,
                },
            )
        )
    return bindings


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


def _list_persistent_volumes(
    core_v1: CoreV1Api,
    tenant_id: str,
    cluster_name: str,
) -> list[K8sResource]:
    pvs: list[K8sResource] = []
    for pv in core_v1.list_persistent_volume().items:
        meta = pv.metadata
        spec = pv.spec
        status = pv.status
        capacity = dict(spec.capacity) if spec and spec.capacity else {}
        access_modes = list(spec.access_modes or []) if spec else []
        pvs.append(
            K8sResource(
                tenant_id=tenant_id,
                resource_type="persistent_volume",
                resource_id=meta.uid,
                name=meta.name,
                cluster_name=cluster_name,
                tags={k: v for k, v in (meta.labels or {}).items()},
                raw_metadata={
                    "capacity": capacity,
                    "access_modes": access_modes,
                    "storage_class": spec.storage_class_name if spec else None,
                    "phase": status.phase if status else None,
                    "reclaim_policy": spec.persistent_volume_reclaim_policy if spec else None,
                },
            )
        )
    return pvs


# ─── Celery task ──────────────────────────────────────────────────────────────


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def discover_k8s(
    self: Any,
    tenant_id: str,
    cluster_name: str,
    kubeconfig: dict[str, Any] | None = None,
    provider_key: str | None = None,
) -> dict[str, Any]:
    """
    Discover all Kubernetes resources in a cluster and persist them to ArangoDB.

    Args:
        tenant_id: Ogum tenant identifier.
        cluster_name: Logical cluster name (used as part of ArangoDB key).
        kubeconfig: Kubeconfig dict for remote clusters (ephemeral — never stored).
            None → in-cluster config (ServiceAccount mounted by Kubernetes).
        provider_key: ArangoDB key of the provider config for status updates.
    """
    redis = Redis.from_url(settings.REDIS_URL)
    if not acquire_lock(redis, tenant_id, "k8s"):
        logger.info("K8s discovery already running for tenant=%s — skipped", tenant_id)
        return {"skipped": True, "tenant_id": tenant_id, "provider": "k8s"}

    db = _get_tenant_db(tenant_id)
    _job_id = start_discovery_job(db, tenant_id, "k8s", provider_key)

    try:
        if kubeconfig:
            k8s_config.load_kube_config_from_dict(kubeconfig)
        else:
            k8s_config.load_incluster_config()

        core_v1 = CoreV1Api()
        apps_v1 = AppsV1Api()
        networking_v1 = NetworkingV1Api()
        rbac_v1 = RbacAuthorizationV1Api()

        init_tenant_schema(db)

        resource_keys: set[str] = set()

        for resource in _list_pods(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_deployments(apps_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_daemon_sets(apps_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_stateful_sets(apps_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_services(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_ingresses(networking_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_network_policies(networking_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_k8s_service_accounts(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_cluster_roles(rbac_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_cluster_role_bindings(rbac_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_nodes(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_namespaces(core_v1, tenant_id, cluster_name):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_persistent_volumes(core_v1, tenant_id, cluster_name):
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
            tenant_id,
            cluster_name,
            len(resource_keys),
            deleted,
        )
        _set_provider_status(db, provider_key, "active")
        complete_discovery_job(db, _job_id, len(resource_keys))
        return {
            "tenant_id": tenant_id,
            "provider": "k8s",
            "cluster_name": cluster_name,
            "discovered": len(resource_keys),
            "deleted": deleted,
        }

    except Exception as exc:
        logger.exception("K8s discovery failed [tenant=%s cluster=%s]: %s", tenant_id, cluster_name, exc)
        _set_provider_status(db, provider_key, "error")
        fail_discovery_job(db, _job_id, str(exc))
        raise self.retry(exc=exc)

    finally:
        release_lock(redis, tenant_id, "k8s")
