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


def _patch_k8s_clients(
    mocker,
    db,
    pods=None,
    deployments=None,
    daemon_sets=None,
    stateful_sets=None,
    services=None,
    ingresses=None,
    network_policies=None,
    service_accounts=None,
    cluster_roles=None,
    cluster_role_bindings=None,
    nodes=None,
    namespaces=None,
    persistent_volumes=None,
):
    mocker.patch("app.workers.tasks.k8s_discovery._get_tenant_db", return_value=db)
    mocker.patch("app.workers.tasks.k8s_discovery.acquire_lock", return_value=True)
    mocker.patch("app.workers.tasks.k8s_discovery.release_lock")
    mocker.patch("app.workers.tasks.k8s_discovery.k8s_config.load_kube_config_from_dict")

    mock_core = MagicMock()
    mock_core.list_pod_for_all_namespaces.return_value.items = pods if pods is not None else []
    mock_core.list_service_for_all_namespaces.return_value.items = services if services is not None else []
    mock_core.list_service_account_for_all_namespaces.return_value.items = (
        service_accounts if service_accounts is not None else []
    )
    mock_core.list_node.return_value.items = nodes if nodes is not None else []
    mock_core.list_namespace.return_value.items = namespaces if namespaces is not None else []
    mock_core.list_persistent_volume.return_value.items = persistent_volumes if persistent_volumes is not None else []
    mocker.patch("app.workers.tasks.k8s_discovery.CoreV1Api", return_value=mock_core)

    mock_apps = MagicMock()
    mock_apps.list_deployment_for_all_namespaces.return_value.items = deployments if deployments is not None else []
    mock_apps.list_daemon_set_for_all_namespaces.return_value.items = daemon_sets if daemon_sets is not None else []
    mock_apps.list_stateful_set_for_all_namespaces.return_value.items = (
        stateful_sets if stateful_sets is not None else []
    )
    mocker.patch("app.workers.tasks.k8s_discovery.AppsV1Api", return_value=mock_apps)

    mock_networking = MagicMock()
    mock_networking.list_ingress_for_all_namespaces.return_value.items = ingresses if ingresses is not None else []
    mock_networking.list_network_policy_for_all_namespaces.return_value.items = (
        network_policies if network_policies is not None else []
    )
    mocker.patch("app.workers.tasks.k8s_discovery.NetworkingV1Api", return_value=mock_networking)

    mock_rbac = MagicMock()
    mock_rbac.list_cluster_role.return_value.items = cluster_roles if cluster_roles is not None else []
    mock_rbac.list_cluster_role_binding.return_value.items = (
        cluster_role_bindings if cluster_role_bindings is not None else []
    )
    mocker.patch("app.workers.tasks.k8s_discovery.RbacAuthorizationV1Api", return_value=mock_rbac)

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

        pods_in_db = [r for r in db_tenant_a.collection("resources").all() if r["resource_type"] == "pod"]
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
        mock_apps.list_daemon_set_for_all_namespaces.return_value.items = []
        mock_apps.list_stateful_set_for_all_namespaces.return_value.items = []
        mocker.patch("app.workers.tasks.k8s_discovery.AppsV1Api", return_value=mock_apps)

        mock_networking = MagicMock()
        mock_networking.list_ingress_for_all_namespaces.return_value.items = []
        mock_networking.list_network_policy_for_all_namespaces.return_value.items = []
        mocker.patch("app.workers.tasks.k8s_discovery.NetworkingV1Api", return_value=mock_networking)

        mock_rbac = MagicMock()
        mock_rbac.list_cluster_role.return_value.items = []
        mock_rbac.list_cluster_role_binding.return_value.items = []
        mocker.patch("app.workers.tasks.k8s_discovery.RbacAuthorizationV1Api", return_value=mock_rbac)

        init_tenant_schema(db_tenant_a)

        # First run: pod is discovered
        discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        # Second run: pod is gone from cluster
        mock_core.list_pod_for_all_namespaces.return_value.items = []
        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["deleted"] >= 1
        pods_in_db = [r for r in db_tenant_a.collection("resources").all() if r["resource_type"] == "pod"]
        assert len(pods_in_db) == 1
        assert pods_in_db[0]["status"] == "deleted"

    def test_skipped_when_lock_is_held(self, db_tenant_a, mocker) -> None:
        """Task must return skipped=True if another K8s discovery is running."""
        mocker.patch("app.workers.tasks.k8s_discovery._get_tenant_db", return_value=db_tenant_a)
        mocker.patch("app.workers.tasks.k8s_discovery.acquire_lock", return_value=False)
        mocker.patch("app.workers.tasks.k8s_discovery.release_lock")

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["skipped"] is True

    def test_daemon_sets_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered DaemonSets must appear as resources in ArangoDB."""
        ds = MagicMock()
        ds.metadata.name = "fluentd"
        ds.metadata.namespace = "kube-system"
        ds.metadata.uid = "ds-uid-001"
        ds.metadata.labels = {}
        ds.status.desired_number_scheduled = 3
        ds.status.number_ready = 3
        ds.status.number_available = 3
        _patch_k8s_clients(mocker, db_tenant_a, daemon_sets=[ds])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "daemon_set" for r in resources)
        assert any(r["name"] == "fluentd" for r in resources)

    def test_stateful_sets_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered StatefulSets must appear as resources in ArangoDB."""
        ss = MagicMock()
        ss.metadata.name = "postgres"
        ss.metadata.namespace = "default"
        ss.metadata.uid = "ss-uid-001"
        ss.metadata.labels = {}
        ss.spec.replicas = 3
        ss.spec.service_name = "postgres-svc"
        ss.status.ready_replicas = 3
        _patch_k8s_clients(mocker, db_tenant_a, stateful_sets=[ss])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "stateful_set" for r in resources)
        assert any(r["name"] == "postgres" for r in resources)

    def test_ingresses_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered Ingresses must appear as resources in ArangoDB with is_public=True when rules exist."""
        ing = MagicMock()
        ing.metadata.name = "web-ingress"
        ing.metadata.namespace = "default"
        ing.metadata.uid = "ing-uid-001"
        ing.metadata.labels = {}
        rule = MagicMock()
        rule.host = "example.com"
        ing.spec.rules = [rule]
        ing.spec.tls = None
        ing.spec.ingress_class_name = "nginx"
        _patch_k8s_clients(mocker, db_tenant_a, ingresses=[ing])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        ingress_res = next((r for r in resources if r["resource_type"] == "ingress"), None)
        assert ingress_res is not None
        assert ingress_res["name"] == "web-ingress"
        assert ingress_res["is_public"] is True

    def test_network_policies_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered NetworkPolicies must appear as resources in ArangoDB."""
        np = MagicMock()
        np.metadata.name = "deny-all"
        np.metadata.namespace = "default"
        np.metadata.uid = "np-uid-001"
        np.metadata.labels = {}
        np.spec.policy_types = ["Ingress", "Egress"]
        np.spec.pod_selector = MagicMock()
        _patch_k8s_clients(mocker, db_tenant_a, network_policies=[np])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "network_policy" for r in resources)
        assert any(r["name"] == "deny-all" for r in resources)

    def test_service_accounts_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered ServiceAccounts must appear as resources in ArangoDB."""
        sa = MagicMock()
        sa.metadata.name = "app-sa"
        sa.metadata.namespace = "default"
        sa.metadata.uid = "sa-uid-001"
        sa.metadata.labels = {}
        sa.secrets = []
        sa.automount_service_account_token = True
        _patch_k8s_clients(mocker, db_tenant_a, service_accounts=[sa])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "service_account_k8s" for r in resources)
        assert any(r["name"] == "app-sa" for r in resources)

    def test_cluster_roles_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered ClusterRoles must appear as resources in ArangoDB."""
        cr = MagicMock()
        cr.metadata.name = "view"
        cr.metadata.uid = "cr-uid-001"
        cr.metadata.labels = {}
        cr.rules = [MagicMock(), MagicMock()]
        _patch_k8s_clients(mocker, db_tenant_a, cluster_roles=[cr])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        cr_res = next((r for r in resources if r["resource_type"] == "cluster_role"), None)
        assert cr_res is not None
        assert cr_res["name"] == "view"
        assert cr_res["raw_metadata"]["rule_count"] == 2

    def test_cluster_role_bindings_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered ClusterRoleBindings must appear as resources in ArangoDB."""
        crb = MagicMock()
        crb.metadata.name = "view-binding"
        crb.metadata.uid = "crb-uid-001"
        crb.metadata.labels = {}
        crb.role_ref.name = "view"
        crb.subjects = [MagicMock(), MagicMock()]
        _patch_k8s_clients(mocker, db_tenant_a, cluster_role_bindings=[crb])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        crb_res = next((r for r in resources if r["resource_type"] == "cluster_role_binding"), None)
        assert crb_res is not None
        assert crb_res["name"] == "view-binding"
        assert crb_res["raw_metadata"]["subject_count"] == 2

    def test_persistent_volumes_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered PersistentVolumes must appear as resources in ArangoDB."""
        pv = MagicMock()
        pv.metadata.name = "pv-data"
        pv.metadata.uid = "pv-uid-001"
        pv.metadata.labels = {}
        pv.spec.capacity = {"storage": "10Gi"}
        pv.spec.access_modes = ["ReadWriteOnce"]
        pv.spec.storage_class_name = "standard"
        pv.spec.persistent_volume_reclaim_policy = "Retain"
        pv.status.phase = "Bound"
        _patch_k8s_clients(mocker, db_tenant_a, persistent_volumes=[pv])
        init_tenant_schema(db_tenant_a)

        result = discover_k8s.apply(kwargs=_K8S_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        pv_res = next((r for r in resources if r["resource_type"] == "persistent_volume"), None)
        assert pv_res is not None
        assert pv_res["name"] == "pv-data"
        assert pv_res["raw_metadata"]["phase"] == "Bound"
