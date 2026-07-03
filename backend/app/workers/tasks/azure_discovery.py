"""
Azure discovery task — VMs, Managed Disks, VNets, NSGs, Public IPs, Load Balancers,
Storage Accounts, Blob Containers, AKS clusters, Key Vaults.

Azure SDK calls are mocked at the SDK class level in tests via pytest-mock.
ArangoDB upserts are idempotent: re-running discovery never duplicates resources.
Resources absent from the current scan are soft-deleted (status: "deleted").
"""

from __future__ import annotations

import logging
from typing import Any

from azure.identity import ClientSecretCredential, DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from redis import Redis

from app.core.config import settings
from app.db.init import init_tenant_schema
from app.models.inventory import AzureResource, Provider
from app.workers.celery_app import celery_app
from app.workers.tasks.discovery import (
    _get_tenant_db,
    _mark_stale_deleted,
    _set_provider_status,
    _upsert,
)
from app.workers.tasks.scheduling import acquire_lock, release_lock

logger = logging.getLogger(__name__)

_ALL_AZURE_RESOURCE_TYPES = [
    "virtual_machine",
    "managed_disk",
    "virtual_network",
    "network_security_group",
    "public_ip_address",
    "load_balancer",
    "storage_account",
    "blob_container",
    "aks_cluster",
    "key_vault",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _extract_rg_and_name(azure_id: str) -> tuple[str, str]:
    """Parse Azure resource path → (resource_group, resource_name)."""
    parts = azure_id.split("/")
    name = parts[-1] if parts else azure_id
    try:
        rg_idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        rg = parts[rg_idx + 1]
    except StopIteration:
        rg = "global"
    return rg, name


def _compact_id(subscription_id: str, azure_id: str) -> str:
    """Build a short, unique resource_id from subscription prefix + resource path."""
    rg, name = _extract_rg_and_name(azure_id)
    return f"{subscription_id[:8]}_{rg}_{name}"


# ─── Resource list helpers ────────────────────────────────────────────────────


def _list_vms(
    compute_client: ComputeManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    vms: list[AzureResource] = []
    for vm in compute_client.virtual_machines.list_all():
        tags = {k: v for k, v in (vm.tags or {}).items()}
        hw = vm.hardware_profile
        sp = vm.storage_profile
        op = vm.os_profile
        vms.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="virtual_machine",
                resource_id=_compact_id(subscription_id, vm.id),
                name=vm.name,
                region=vm.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                raw_metadata={
                    "azure_resource_id": vm.id,
                    "vm_size": hw.vm_size if hw else None,
                    "os_type": (sp.os_disk.os_type if sp and sp.os_disk else None),
                    "computer_name": op.computer_name if op else None,
                    "provisioning_state": vm.provisioning_state,
                },
            )
        )
    return vms


def _list_managed_disks(
    compute_client: ComputeManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    disks: list[AzureResource] = []
    for disk in compute_client.disks.list_all():
        if disk.id is None or disk.name is None:
            continue
        tags = {k: v for k, v in (disk.tags or {}).items()}
        disks.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="managed_disk",
                resource_id=_compact_id(subscription_id, disk.id),
                name=disk.name,
                region=disk.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                raw_metadata={
                    "azure_resource_id": disk.id,
                    "disk_size_gb": getattr(disk, "disk_size_gb", None),
                    "os_type": str(disk.os_type) if disk.os_type else None,
                    "sku": getattr(disk.sku, "name", None) if disk.sku else None,
                    "provisioning_state": disk.provisioning_state,
                },
            )
        )
    return disks


def _list_vnets(
    network_client: NetworkManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    vnets: list[AzureResource] = []
    for vnet in network_client.virtual_networks.list_all():
        if vnet.id is None or vnet.name is None:
            continue
        tags = {k: v for k, v in (vnet.tags or {}).items()}
        prefixes: list[str] = []
        if vnet.address_space and vnet.address_space.address_prefixes:
            prefixes = list(vnet.address_space.address_prefixes)
        vnets.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="virtual_network",
                resource_id=_compact_id(subscription_id, vnet.id),
                name=vnet.name,
                region=vnet.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                raw_metadata={
                    "azure_resource_id": vnet.id,
                    "address_prefixes": prefixes,
                    "provisioning_state": vnet.provisioning_state,
                },
            )
        )
    return vnets


def _list_nsgs(
    network_client: NetworkManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    nsgs: list[AzureResource] = []
    for nsg in network_client.network_security_groups.list_all():
        if nsg.id is None or nsg.name is None:
            continue
        tags = {k: v for k, v in (nsg.tags or {}).items()}
        rules = list(nsg.security_rules or [])
        is_public = any(
            getattr(r, "direction", None) == "Inbound"
            and getattr(r, "access", None) == "Allow"
            and getattr(r, "source_address_prefix", "") in ("*", "Internet", "0.0.0.0/0")
            for r in rules
        )
        nsgs.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="network_security_group",
                resource_id=_compact_id(subscription_id, nsg.id),
                name=nsg.name,
                region=nsg.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                is_public=is_public,
                raw_metadata={
                    "azure_resource_id": nsg.id,
                    "security_rule_count": len(rules),
                    "provisioning_state": nsg.provisioning_state,
                },
            )
        )
    return nsgs


def _list_public_ips(
    network_client: NetworkManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    ips: list[AzureResource] = []
    for ip in network_client.public_ip_addresses.list_all():
        if ip.id is None or ip.name is None:
            continue
        tags = {k: v for k, v in (ip.tags or {}).items()}
        ips.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="public_ip_address",
                resource_id=_compact_id(subscription_id, ip.id),
                name=ip.name,
                region=ip.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                is_public=True,
                raw_metadata={
                    "azure_resource_id": ip.id,
                    "ip_address": getattr(ip, "ip_address", None),
                    "allocation_method": str(ip.public_ip_allocation_method) if ip.public_ip_allocation_method else None,
                    "provisioning_state": ip.provisioning_state,
                },
            )
        )
    return ips


def _list_load_balancers(
    network_client: NetworkManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    lbs: list[AzureResource] = []
    for lb in network_client.load_balancers.list_all():
        if lb.id is None or lb.name is None:
            continue
        tags = {k: v for k, v in (lb.tags or {}).items()}
        frontend_count = len(list(lb.frontend_ip_configurations or []))
        lbs.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="load_balancer",
                resource_id=_compact_id(subscription_id, lb.id),
                name=lb.name,
                region=lb.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                raw_metadata={
                    "azure_resource_id": lb.id,
                    "sku": getattr(lb.sku, "name", None) if lb.sku else None,
                    "frontend_ip_count": frontend_count,
                    "provisioning_state": lb.provisioning_state,
                },
            )
        )
    return lbs


def _list_storage_accounts(
    storage_client: StorageManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    accounts: list[AzureResource] = []
    for acct in storage_client.storage_accounts.list():
        tags = {k: v for k, v in (acct.tags or {}).items()}
        is_public = (
            getattr(acct, "public_network_access", None) == "Enabled"
            or getattr(acct, "allow_blob_public_access", False) is True
        )
        sku_name = acct.sku.name if acct.sku else None
        accounts.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="storage_account",
                resource_id=_compact_id(subscription_id, acct.id),
                name=acct.name,
                region=acct.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                is_public=is_public,
                raw_metadata={
                    "azure_resource_id": acct.id,
                    "sku": sku_name,
                    "kind": acct.kind,
                    "access_tier": acct.access_tier,
                    "https_traffic_only": acct.enable_https_traffic_only,
                    "allow_blob_public_access": acct.allow_blob_public_access,
                },
            )
        )
    return accounts


def _list_blob_containers(
    storage_client: StorageManagementClient,
    tenant_id: str,
    subscription_id: str,
    storage_account_ids: list[str],
) -> list[AzureResource]:
    containers: list[AzureResource] = []
    for azure_id in storage_account_ids:
        parts = azure_id.split("/")
        try:
            rg_idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
            rg = parts[rg_idx + 1]
        except StopIteration:
            continue
        account_name = parts[-1]
        try:
            for container in storage_client.blob_containers.list(resource_group_name=rg, account_name=account_name):
                if container.name is None:
                    continue
                public_access = getattr(container, "public_access", None)
                is_public = public_access is not None and str(public_access).lower() not in ("none", "null", "")
                containers.append(
                    AzureResource(
                        tenant_id=tenant_id,
                        resource_type="blob_container",
                        resource_id=f"{subscription_id[:8]}_{rg}_{account_name}_{container.name}",
                        name=container.name,
                        region=None,
                        account_id=subscription_id,
                        subscription_id=subscription_id,
                        is_public=is_public,
                        raw_metadata={
                            "storage_account": account_name,
                            "resource_group": rg,
                            "public_access": str(public_access) if public_access else None,
                            "last_modified_time": (
                                container.last_modified_time.isoformat()
                                if getattr(container, "last_modified_time", None)
                                else None
                            ),
                        },
                    )
                )
        except Exception:
            logger.warning("Failed to list blob containers for account=%s rg=%s — skipping", account_name, rg)
    return containers


def _list_aks_clusters(
    container_client: ContainerServiceClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    clusters: list[AzureResource] = []
    for cluster in container_client.managed_clusters.list():
        tags = {k: v for k, v in (cluster.tags or {}).items()}
        clusters.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="aks_cluster",
                resource_id=_compact_id(subscription_id, cluster.id),
                name=cluster.name,
                region=cluster.location,
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                raw_metadata={
                    "azure_resource_id": cluster.id,
                    "kubernetes_version": cluster.kubernetes_version,
                    "provisioning_state": cluster.provisioning_state,
                    "node_resource_group": cluster.node_resource_group,
                    "enable_rbac": cluster.enable_rbac,
                },
            )
        )
    return clusters


def _list_key_vaults(
    keyvault_client: KeyVaultManagementClient,
    tenant_id: str,
    subscription_id: str,
) -> list[AzureResource]:
    vaults: list[AzureResource] = []
    for vault in keyvault_client.vaults.list():
        tags = {k: v for k, v in (getattr(vault, "tags", None) or {}).items()}
        props = getattr(vault, "properties", None)
        vaults.append(
            AzureResource(
                tenant_id=tenant_id,
                resource_type="key_vault",
                resource_id=_compact_id(subscription_id, vault.id),
                name=vault.name,
                region=getattr(vault, "location", None),
                account_id=subscription_id,
                subscription_id=subscription_id,
                tags=tags,
                raw_metadata={
                    "azure_resource_id": vault.id,
                    "vault_uri": getattr(props, "vault_uri", None) if props else None,
                    "sku": getattr(getattr(props, "sku", None), "name", None) if props else None,
                    "enabled_for_deployment": getattr(props, "enabled_for_deployment", None) if props else None,
                    "soft_delete_enabled": getattr(props, "enable_soft_delete", None) if props else None,
                },
            )
        )
    return vaults


# ─── Celery task ──────────────────────────────────────────────────────────────


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def discover_azure(
    self: Any,
    tenant_id: str,
    subscription_id: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    azure_tenant_id: str | None = None,
    provider_key: str | None = None,
) -> dict[str, Any]:
    """
    Discover all Azure resources for a subscription and persist them to ArangoDB.

    Args:
        tenant_id: Ogum tenant identifier.
        subscription_id: Azure subscription ID.
        client_id: Azure service principal client ID (optional — uses DefaultAzureCredential if absent).
        client_secret: Azure service principal client secret (ephemeral — never stored).
        azure_tenant_id: Azure Active Directory tenant ID (optional with Service Principal).
        provider_key: ArangoDB key of the provider config for status updates.
    """
    redis = Redis.from_url(settings.REDIS_URL)
    if not acquire_lock(redis, tenant_id, "azure"):
        logger.info("Azure discovery already running for tenant=%s — skipped", tenant_id)
        return {"skipped": True, "tenant_id": tenant_id, "provider": "azure"}

    db = _get_tenant_db(tenant_id)

    try:
        if client_id and client_secret and azure_tenant_id:
            credential: ClientSecretCredential | DefaultAzureCredential = ClientSecretCredential(
                tenant_id=azure_tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )
        else:
            credential = DefaultAzureCredential()

        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)
        container_client = ContainerServiceClient(credential, subscription_id)
        keyvault_client = KeyVaultManagementClient(credential, subscription_id)

        init_tenant_schema(db)

        resource_keys: set[str] = set()

        for resource in _list_vms(compute_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_managed_disks(compute_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_vnets(network_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_nsgs(network_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_public_ips(network_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_load_balancers(network_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        storage_account_ids: list[str] = []
        for resource in _list_storage_accounts(storage_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())
            storage_account_ids.append(resource.raw_metadata["azure_resource_id"])

        for resource in _list_blob_containers(storage_client, tenant_id, subscription_id, storage_account_ids):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_aks_clusters(container_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        for resource in _list_key_vaults(keyvault_client, tenant_id, subscription_id):
            _upsert(db, "resources", resource.to_arango_doc(), resource.to_arango_update())
            resource_keys.add(resource.arango_key())

        deleted = _mark_stale_deleted(
            db,
            collection="resources",
            tenant_id=tenant_id,
            provider=Provider.AZURE,
            type_field="resource_type",
            type_values=_ALL_AZURE_RESOURCE_TYPES,
            regions=None,
            discovered_keys=resource_keys,
        )

        logger.info(
            "Azure discovery complete [tenant=%s sub=%s]: discovered=%d deleted=%d",
            tenant_id,
            subscription_id,
            len(resource_keys),
            deleted,
        )
        _set_provider_status(db, provider_key, "active")
        return {
            "tenant_id": tenant_id,
            "provider": "azure",
            "discovered": len(resource_keys),
            "deleted": deleted,
        }

    except Exception as exc:
        logger.exception("Azure discovery failed [tenant=%s]: %s", tenant_id, exc)
        _set_provider_status(db, provider_key, "error")
        raise self.retry(exc=exc)

    finally:
        release_lock(redis, tenant_id, "azure")
