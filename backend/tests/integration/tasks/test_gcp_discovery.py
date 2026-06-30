"""
Integration tests for GCP discovery Celery task.

Rules:
- ArangoDB: real instance (provided by db_tenant_a fixture — never mocked)
- GCP SDK: mocked at the class level via pytest-mock
- Redis lock: mocked so tests focus on discovery logic
- Celery: task.apply() runs synchronously — no broker required
"""
from unittest.mock import MagicMock

import pytest

from app.db.init import init_tenant_schema
from app.workers.tasks.gcp_discovery import discover_gcp

TEST_TENANT_A = "test-tenant-aaa"
PROJECT_ID = "test-gcp-project"

_GCP_KWARGS = {
    "tenant_id": TEST_TENANT_A,
    "project_id": PROJECT_ID,
    "service_account_info": {
        "type": "service_account",
        "project_id": PROJECT_ID,
        "private_key_id": "key-id",
        "private_key": "fake-key",
        "client_email": "test@test-gcp-project.iam.gserviceaccount.com",
        "client_id": "123456",
    },
}


def _make_mock_instance(name: str = "test-vm", zone: str = "us-central1-a") -> MagicMock:
    inst = MagicMock()
    inst.name = name
    inst.id = 9876543210
    inst.machine_type = f"zones/{zone}/machineTypes/n1-standard-1"
    inst.status = "RUNNING"
    inst.labels = {"env": "test"}
    inst.network_interfaces = []
    return inst


def _patch_gcp_clients(mocker, db, instances=None, buckets=None, clusters=None):
    mocker.patch("app.workers.tasks.gcp_discovery._get_tenant_db", return_value=db)
    mocker.patch("app.workers.tasks.gcp_discovery.acquire_lock", return_value=True)
    mocker.patch("app.workers.tasks.gcp_discovery.release_lock")
    mocker.patch("app.workers.tasks.gcp_discovery.SACredentials")

    zone_scope = MagicMock()
    zone_scope.instances = instances if instances is not None else []

    mock_instances_client = MagicMock()
    mock_instances_client.aggregated_list.return_value = [("zones/us-central1-a", zone_scope)]
    mocker.patch(
        "app.workers.tasks.gcp_discovery.InstancesClient",
        return_value=mock_instances_client,
    )

    mock_storage = MagicMock()
    mock_storage.list_buckets.return_value = buckets if buckets is not None else []
    mocker.patch("app.workers.tasks.gcp_discovery.GCSClient", return_value=mock_storage)

    mock_cluster_response = MagicMock()
    mock_cluster_response.clusters = clusters if clusters is not None else []
    mock_cluster_client = MagicMock()
    mock_cluster_client.list_clusters.return_value = mock_cluster_response
    mocker.patch(
        "app.workers.tasks.gcp_discovery.ClusterManagerClient",
        return_value=mock_cluster_client,
    )


@pytest.mark.integration
class TestGCPDiscoveryTask:
    """discover_gcp — mocked GCP SDK, real ArangoDB stores results."""

    def test_compute_instances_persisted_after_discovery(self, db_tenant_a, mocker) -> None:
        """Discovered compute instances must appear as resources in ArangoDB."""
        instance = _make_mock_instance("web-vm", "us-central1-a")
        _patch_gcp_clients(mocker, db_tenant_a, instances=[instance])
        init_tenant_schema(db_tenant_a)

        result = discover_gcp.apply(kwargs=_GCP_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "compute_instance" for r in resources)
        assert any(r["name"] == "web-vm" for r in resources)

    def test_discovery_is_idempotent(self, db_tenant_a, mocker) -> None:
        """Running discovery twice must not duplicate resources in ArangoDB."""
        instance = _make_mock_instance("idem-vm")
        _patch_gcp_clients(mocker, db_tenant_a, instances=[instance])
        init_tenant_schema(db_tenant_a)

        discover_gcp.apply(kwargs=_GCP_KWARGS).get()
        discover_gcp.apply(kwargs=_GCP_KWARGS).get()

        instances_in_db = [
            r for r in db_tenant_a.collection("resources").all()
            if r["resource_type"] == "compute_instance"
        ]
        assert len(instances_in_db) == 1

    def test_absent_instances_marked_deleted(self, db_tenant_a, mocker) -> None:
        """Instances not returned by GCP API on second run must be soft-deleted."""
        instance = _make_mock_instance("to-be-deleted")
        zone_scope_with = MagicMock()
        zone_scope_with.instances = [instance]
        zone_scope_empty = MagicMock()
        zone_scope_empty.instances = []

        mock_instances_client = MagicMock()
        mock_instances_client.aggregated_list.side_effect = [
            [("zones/us-central1-a", zone_scope_with)],
            [("zones/us-central1-a", zone_scope_empty)],
        ]

        mocker.patch("app.workers.tasks.gcp_discovery._get_tenant_db", return_value=db_tenant_a)
        mocker.patch("app.workers.tasks.gcp_discovery.acquire_lock", return_value=True)
        mocker.patch("app.workers.tasks.gcp_discovery.release_lock")
        mocker.patch("app.workers.tasks.gcp_discovery.SACredentials")
        mocker.patch(
            "app.workers.tasks.gcp_discovery.InstancesClient",
            return_value=mock_instances_client,
        )

        empty_storage = MagicMock()
        empty_storage.list_buckets.return_value = []
        mocker.patch("app.workers.tasks.gcp_discovery.GCSClient", return_value=empty_storage)

        empty_clusters = MagicMock()
        empty_clusters.list_clusters.return_value.clusters = []
        mocker.patch(
            "app.workers.tasks.gcp_discovery.ClusterManagerClient",
            return_value=empty_clusters,
        )

        init_tenant_schema(db_tenant_a)

        discover_gcp.apply(kwargs=_GCP_KWARGS).get()
        result = discover_gcp.apply(kwargs=_GCP_KWARGS).get()

        assert result["deleted"] >= 1
        instances_in_db = [
            r for r in db_tenant_a.collection("resources").all()
            if r["resource_type"] == "compute_instance"
        ]
        assert len(instances_in_db) == 1
        assert instances_in_db[0]["status"] == "deleted"

    def test_skipped_when_lock_is_held(self, db_tenant_a, mocker) -> None:
        """Task must return skipped=True if another GCP discovery is running."""
        mocker.patch("app.workers.tasks.gcp_discovery._get_tenant_db", return_value=db_tenant_a)
        mocker.patch("app.workers.tasks.gcp_discovery.acquire_lock", return_value=False)
        mocker.patch("app.workers.tasks.gcp_discovery.release_lock")

        result = discover_gcp.apply(kwargs=_GCP_KWARGS).get()

        assert result["skipped"] is True
