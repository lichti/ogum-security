"""
Integration tests for Kubernetes discovery Celery task.

Rules:
- ArangoDB: real instance (provided by db_tenant_a fixture — never mocked)
- Kubernetes SDK: mocked at the API class level via pytest-mock
- Redis lock: mocked so tests focus on discovery logic
- Celery: task.apply() runs synchronously — no broker required
"""
from unittest.mock import MagicMock

import pytest

from app.db.init import init_tenant_schema
from app.workers.tasks.k8s_discovery import discover_k8s

TEST_TENANT_A = "test-tenant-aaa"
CLUSTER_NAME = "test-cluster"

_K8S_KWARGS = {
    "tenant_id": TEST_TENANT_A,
    "cluster_name": CLUSTER_NAME,
    "kubeconfig": {"apiVersion": "v1", "clusters": [], "contexts": [], "users": []},
}


def _make_mock_pod(name: str = "test-pod", namespace: str = "default", uid: str = "pod-uid-001") -> MagicMock:
    pod = MagicMock()
    pod.metadata.name = name
    pod.metadata.namespace = namespace
    pod.metadata.uid = uid
    pod.metadata.labels = {"app": "test"}
    pod.spec.node_name = "node-001"
    pod.spec.containers = [MagicMock()]
    pod.spec.restart_policy = "Always"
    pod.status.phase = "Running"
    return pod


def _patch_k8s_clients(mocker, db, pods=None, deployments=None, services=None, nodes=None, namespaces=None):
    mocker.patch("app.workers.tasks.k8s_discovery._get_tenant_db", return_value=db)
    mocker.patch("app.workers.tasks.k8s_discovery.acquire_lock", return_value=True)
    mocker.patch("app.workers.tasks.k8s_discovery.release_lock")
    mocker.patch("app.workers.tasks.k8s_discovery.k8s_config.load_kube_config_from_dict")

    mock_core = MagicMock()
    mock_core.list_pod_for_all_namespaces.return_value.items = pods if pods is not None else []
    mock_core.list_service_for_all_namespaces.return_value.items = services if services is not None else []
    mock_core.list_node.return_value.items = nodes if nodes is not None else []
    mock_core.list_namespace.return_value.items = namespaces if namespaces is not None else []
    mocker.patch("app.workers.tasks.k8s_discovery.CoreV1Api", return_value=mock_core)

    mock_apps = MagicMock()
    mock_apps.list_deployment_for_all_namespaces.return_value.items = deployments if deployments is not None else []
    mocker.patch("app.workers.tasks.k8s_discovery.AppsV1Api", return_value=mock_apps)

    return mock_core, mock_apps


@pytest.mark.integration
class TestK8sDiscoveryTask:
    """discover_k8s — mocked Kubernetes SDK, real ArangoDB stores results."""

    def test_pods_persisted_after_discovery(self, db_tenant_a, mocker) -> None:
        """Discovered pods must appear as resources in ArangoDB."""
        pod = _make_mock_pod("nginx-pod", "default", "uid-nginx-001")
        _patch_k8s_clients(mocker, db_tenant_a, pods=[pod])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "pod" for r in resources)
        assert any(r["name"] == "nginx-pod" for r in resources)

    def test_discovery_is_idempotent(self, db_tenant_a, mocker) -> None:
        """Running discovery twice must not duplicate pods in ArangoDB."""
        pod = _make_mock_pod("idem-pod", "default", "uid-idem-001")
        _patch_k8s_clients(mocker, db_tenant_a, pods=[pod])
        init_tenant_schema(db_tenant_a)

        discover_k8s.apply(kwargs=_K8S_KWARGS).get()
        discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        pods_in_db = [
            r for r in db_tenant_a.collection("resources").all()
            if r["resource_type"] == "pod"
        ]
        assert len(pods_in_db) == 1

    def test_absent_pods_marked_deleted(self, db_tenant_a, mocker) -> None:
        """Pods not returned by K8s API on second run must be soft-deleted."""
        pod = _make_mock_pod("deleted-pod", "default", "uid-gone-001")

        mocker.patch("app.workers.tasks.k8s_discovery._get_tenant_db", return_value=db_tenant_a)
        mocker.patch("app.workers.tasks.k8s_discovery.acquire_lock", return_value=True)
        mocker.patch("app.workers.tasks.k8s_discovery.release_lock")
        mocker.patch("app.workers.tasks.k8s_discovery.k8s_config.load_kube_config_from_dict")

        mock_core = MagicMock()
        mock_core.list_pod_for_all_namespaces.return_value.items = [pod]
        mock_core.list_service_for_all_namespaces.return_value.items = []
        mock_core.list_node.return_value.items = []
        mock_core.list_namespace.return_value.items = []
        mocker.patch("app.workers.tasks.k8s_discovery.CoreV1Api", return_value=mock_core)

        mock_apps = MagicMock()
        mock_apps.list_deployment_for_all_namespaces.return_value.items = []
        mocker.patch("app.workers.tasks.k8s_discovery.AppsV1Api", return_value=mock_apps)

        init_tenant_schema(db_tenant_a)

        # First run: pod is discovered
        discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        # Second run: pod is gone from cluster
        mock_core.list_pod_for_all_namespaces.return_value.items = []
        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["deleted"] >= 1
        pods_in_db = [
            r for r in db_tenant_a.collection("resources").all()
            if r["resource_type"] == "pod"
        ]
        assert len(pods_in_db) == 1
        assert pods_in_db[0]["status"] == "deleted"

    def test_skipped_when_lock_is_held(self, db_tenant_a, mocker) -> None:
        """Task must return skipped=True if another K8s discovery is running."""
        mocker.patch("app.workers.tasks.k8s_discovery._get_tenant_db", return_value=db_tenant_a)
        mocker.patch("app.workers.tasks.k8s_discovery.acquire_lock", return_value=False)
        mocker.patch("app.workers.tasks.k8s_discovery.release_lock")

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["skipped"] is True
