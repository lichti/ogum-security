"""
Integration tests for Azure discovery Celery task.

Rules:
- ArangoDB: real instance (provided by db_tenant_a fixture — never mocked)
- Azure SDK: mocked at the class level via pytest-mock
- Redis lock: mocked so tests focus on discovery logic
- Celery: task.apply() runs synchronously — no broker required
"""

from unittest.mock import MagicMock

import pytest

from app.db.init import init_tenant_schema
from app.workers.tasks.azure_discovery import discover_azure

TEST_TENANT_A = "test-tenant-aaa"
SUB_ID = "sub-00000001"

_AZURE_KWARGS = {
    "tenant_id": TEST_TENANT_A,
    "subscription_id": SUB_ID,
    "client_id": "client-id",
    "client_secret": "client-secret",
    "azure_tenant_id": "azure-tenant-id",
}


def _make_mock_vm(
    name: str = "test-vm",
    rg: str = "rg-test",
    location: str = "eastus",
) -> MagicMock:
    vm = MagicMock()
    vm.name = name
    vm.location = location
    vm.id = f"/subscriptions/{SUB_ID}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}"
    vm.tags = {"env": "test"}
    vm.hardware_profile.vm_size = "Standard_D2s_v3"
    vm.os_profile.computer_name = name
    vm.storage_profile.os_disk.os_type = "Linux"
    vm.provisioning_state = "Succeeded"
    return vm


def _patch_azure_clients(
    mocker,
    db,
    vms=None,
    disks=None,
    vnets=None,
    nsgs=None,
    public_ips=None,
    load_balancers=None,
    storage=None,
    blob_containers=None,
    aks=None,
    vaults=None,
):
    mocker.patch("app.workers.tasks.azure_discovery._get_tenant_db", return_value=db)
    mocker.patch("app.workers.tasks.azure_discovery.acquire_lock", return_value=True)
    mocker.patch("app.workers.tasks.azure_discovery.release_lock")
    mocker.patch("app.workers.tasks.azure_discovery.ClientSecretCredential")

    mock_compute = MagicMock()
    mock_compute.virtual_machines.list_all.return_value = vms if vms is not None else []
    mock_compute.disks.list_all.return_value = disks if disks is not None else []
    mocker.patch("app.workers.tasks.azure_discovery.ComputeManagementClient", return_value=mock_compute)

    mock_network = MagicMock()
    mock_network.virtual_networks.list_all.return_value = vnets if vnets is not None else []
    mock_network.network_security_groups.list_all.return_value = nsgs if nsgs is not None else []
    mock_network.public_ip_addresses.list_all.return_value = public_ips if public_ips is not None else []
    mock_network.load_balancers.list_all.return_value = load_balancers if load_balancers is not None else []
    mocker.patch("app.workers.tasks.azure_discovery.NetworkManagementClient", return_value=mock_network)

    mock_storage = MagicMock()
    mock_storage.storage_accounts.list.return_value = storage if storage is not None else []
    mock_storage.blob_containers.list.return_value = blob_containers if blob_containers is not None else []
    mocker.patch("app.workers.tasks.azure_discovery.StorageManagementClient", return_value=mock_storage)

    mock_container = MagicMock()
    mock_container.managed_clusters.list.return_value = aks if aks is not None else []
    mocker.patch("app.workers.tasks.azure_discovery.ContainerServiceClient", return_value=mock_container)

    mock_keyvault = MagicMock()
    mock_keyvault.vaults.list.return_value = vaults if vaults is not None else []
    mocker.patch("app.workers.tasks.azure_discovery.KeyVaultManagementClient", return_value=mock_keyvault)

    return mock_compute


@pytest.mark.integration
class TestAzureDiscoveryTask:
    """discover_azure — mocked Azure SDK, real ArangoDB stores results."""

    def test_vms_persisted_after_discovery(self, db_tenant_a, mocker) -> None:
        """Discovered VMs must appear as resources in ArangoDB."""
        vm = _make_mock_vm("web-server", "rg-prod")
        _patch_azure_clients(mocker, db_tenant_a, vms=[vm])
        init_tenant_schema(db_tenant_a)

        result = discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "virtual_machine" for r in resources)
        assert any(r["name"] == "web-server" for r in resources)

    def test_discovery_is_idempotent(self, db_tenant_a, mocker) -> None:
        """Running discovery twice must not duplicate resources in ArangoDB."""
        vm = _make_mock_vm("idempotent-vm", "rg-test")
        _patch_azure_clients(mocker, db_tenant_a, vms=[vm])
        init_tenant_schema(db_tenant_a)

        discover_azure.apply(kwargs=_AZURE_KWARGS).get()
        discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        vms_in_db = [r for r in db_tenant_a.collection("resources").all() if r["resource_type"] == "virtual_machine"]
        assert len(vms_in_db) == 1

    def test_absent_vms_marked_deleted(self, db_tenant_a, mocker) -> None:
        """VMs not returned by Azure API on second run must be soft-deleted."""
        vm = _make_mock_vm("to-be-deleted", "rg-gone")

        mock_compute = MagicMock()
        mock_compute.virtual_machines.list_all.side_effect = [[vm], []]
        mocker.patch("app.workers.tasks.azure_discovery._get_tenant_db", return_value=db_tenant_a)
        mocker.patch("app.workers.tasks.azure_discovery.acquire_lock", return_value=True)
        mocker.patch("app.workers.tasks.azure_discovery.release_lock")
        mocker.patch("app.workers.tasks.azure_discovery.ClientSecretCredential")
        mocker.patch(
            "app.workers.tasks.azure_discovery.ComputeManagementClient",
            return_value=mock_compute,
        )
        for cls in [
            "app.workers.tasks.azure_discovery.NetworkManagementClient",
            "app.workers.tasks.azure_discovery.StorageManagementClient",
            "app.workers.tasks.azure_discovery.ContainerServiceClient",
            "app.workers.tasks.azure_discovery.KeyVaultManagementClient",
        ]:
            mock_client = MagicMock()
            for attr in ["virtual_networks", "network_security_groups"]:
                getattr(mock_client, attr, MagicMock()).list_all.return_value = []
            mock_client.storage_accounts = MagicMock()
            mock_client.storage_accounts.list.return_value = []
            mock_client.managed_clusters = MagicMock()
            mock_client.managed_clusters.list.return_value = []
            mock_client.vaults = MagicMock()
            mock_client.vaults.list.return_value = []
            mocker.patch(cls, return_value=mock_client)

        init_tenant_schema(db_tenant_a)

        # First run: VM is discovered
        discover_azure.apply(kwargs=_AZURE_KWARGS).get()
        vms_first = [r for r in db_tenant_a.collection("resources").all() if r["resource_type"] == "virtual_machine"]
        assert len(vms_first) == 1
        assert vms_first[0]["status"] == "active"

        # Second run: VM is gone from Azure
        result = discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        assert result["deleted"] >= 1
        vms_after = [r for r in db_tenant_a.collection("resources").all() if r["resource_type"] == "virtual_machine"]
        assert len(vms_after) == 1
        assert vms_after[0]["status"] == "deleted"

    def test_skipped_when_lock_is_held(self, db_tenant_a, mocker) -> None:
        """Task must return skipped=True if another discovery is running."""
        mocker.patch("app.workers.tasks.azure_discovery._get_tenant_db", return_value=db_tenant_a)
        mocker.patch("app.workers.tasks.azure_discovery.acquire_lock", return_value=False)
        mocker.patch("app.workers.tasks.azure_discovery.release_lock")

        result = discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        assert result["skipped"] is True

    def test_managed_disks_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered managed disks must appear as resources in ArangoDB."""
        disk = MagicMock()
        disk.id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-test/providers/Microsoft.Compute/disks/os-disk"
        disk.name = "os-disk"
        disk.location = "eastus"
        disk.tags = {}
        disk.disk_size_gb = 128
        disk.os_type = "Linux"
        disk.sku.name = "Premium_LRS"
        disk.provisioning_state = "Succeeded"
        _patch_azure_clients(mocker, db_tenant_a, disks=[disk])
        init_tenant_schema(db_tenant_a)

        result = discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "managed_disk" for r in resources)
        assert any(r["name"] == "os-disk" for r in resources)

    def test_public_ips_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered public IPs must appear as resources in ArangoDB with is_public=True."""
        ip = MagicMock()
        ip.id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-test/providers/Microsoft.Network/publicIPAddresses/my-pip"
        ip.name = "my-pip"
        ip.location = "westeurope"
        ip.tags = {}
        ip.ip_address = "1.2.3.4"
        ip.public_ip_allocation_method = "Static"
        ip.provisioning_state = "Succeeded"
        _patch_azure_clients(mocker, db_tenant_a, public_ips=[ip])
        init_tenant_schema(db_tenant_a)

        result = discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        pip = next((r for r in resources if r["resource_type"] == "public_ip_address"), None)
        assert pip is not None
        assert pip["name"] == "my-pip"
        assert pip["is_public"] is True

    def test_load_balancers_persisted(self, db_tenant_a, mocker) -> None:
        """Discovered load balancers must appear as resources in ArangoDB."""
        lb = MagicMock()
        lb.id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-test/providers/Microsoft.Network/loadBalancers/my-lb"
        lb.name = "my-lb"
        lb.location = "eastus"
        lb.tags = {}
        lb.sku.name = "Standard"
        lb.frontend_ip_configurations = [MagicMock()]
        lb.provisioning_state = "Succeeded"
        _patch_azure_clients(mocker, db_tenant_a, load_balancers=[lb])
        init_tenant_schema(db_tenant_a)

        result = discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "load_balancer" for r in resources)
        assert any(r["name"] == "my-lb" for r in resources)

    def test_blob_containers_persisted(self, db_tenant_a, mocker) -> None:
        """Blob containers under a storage account must be discovered and persisted."""
        acct = MagicMock()
        acct.id = f"/subscriptions/{SUB_ID}/resourceGroups/rg-test/providers/Microsoft.Storage/storageAccounts/myacct"
        acct.name = "myacct"
        acct.location = "eastus"
        acct.tags = {}
        acct.sku.name = "Standard_LRS"
        acct.kind = "StorageV2"
        acct.access_tier = "Hot"
        acct.enable_https_traffic_only = True
        acct.allow_blob_public_access = False
        acct.public_network_access = "Enabled"

        container = MagicMock()
        container.name = "logs-container"
        container.public_access = None
        container.last_modified_time = None

        _patch_azure_clients(mocker, db_tenant_a, storage=[acct], blob_containers=[container])
        init_tenant_schema(db_tenant_a)

        result = discover_azure.apply(kwargs=_AZURE_KWARGS).get()

        assert result["discovered"] >= 1
        resources = list(db_tenant_a.collection("resources").all())
        assert any(r["resource_type"] == "blob_container" for r in resources)
        assert any(r["name"] == "logs-container" for r in resources)
