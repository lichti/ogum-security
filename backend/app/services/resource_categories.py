"""
Resource type → asset category mapping (US-14.11).

Direct Python port of frontend/src/lib/inventoryCategories.ts, kept in
lockstep — same precedent already used for sla_service.py/classifySLA
(Epic 14 Sprint 3). Any resource_type not listed here falls back to "other"
so new discovery types never disappear from the UI, they just land
uncategorized until this map is updated.
"""

from __future__ import annotations

RESOURCE_TYPE_CATEGORY: dict[str, str] = {
    # Compute
    "ec2_instance": "compute",
    "virtual_machine": "compute",
    "compute_instance": "compute",
    "lambda_function": "compute",
    # Containers / Kubernetes
    "eks_cluster": "containers",
    "aks_cluster": "containers",
    "gke_cluster": "containers",
    "k8s_container": "containers",
    "container_image": "containers",
    "ecr_repository": "containers",
    "pod": "containers",
    "deployment": "containers",
    "daemon_set": "containers",
    "stateful_set": "containers",
    "namespace": "containers",
    "node": "containers",
    "service": "containers",
    "ingress": "containers",
    "network_policy": "containers",
    "persistent_volume": "containers",
    # Storage
    "blob_container": "storage",
    "gcs_bucket": "storage",
    "managed_disk": "storage",
    "storage_account": "storage",
    # Database
    "rds_instance": "database",
    # Networking
    "vpc": "networking",
    "vpc_network": "networking",
    "virtual_network": "networking",
    "subnet": "networking",
    "security_group": "networking",
    "network_security_group": "networking",
    "firewall_rule": "networking",
    "internet_gateway": "networking",
    "load_balancer": "networking",
    "public_ip_address": "networking",
    "elastic_ip": "networking",
    # Security & Identity
    "kms_key": "security_identity",
    "key_vault": "security_identity",
    "secrets_manager_secret": "security_identity",
    "cloudtrail_trail": "security_identity",
    "cluster_role": "security_identity",
    "cluster_role_binding": "security_identity",
    "service_account_k8s": "security_identity",
}


def category_of(resource_type: str | None) -> str:
    if not resource_type:
        return "other"
    return RESOURCE_TYPE_CATEGORY.get(resource_type, "other")


def resource_types_for_category(category: str) -> list[str]:
    return [rt for rt, cat in RESOURCE_TYPE_CATEGORY.items() if cat == category]
