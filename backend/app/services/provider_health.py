"""Provider connection health — cached evaluation and live credential probes.

Two entry points back US-14.20:

- `evaluate_cached_health(config)` — pure derivation from stored signals
  (`status`, `last_discovery_at`); cheap enough to call per card on every page
  render, no cloud API calls.
- `run_connection_test(db, config)` — performs a real, minimal read-only call
  against the provider using the stored credentials (the same construction the
  discovery tasks use), persists the outcome on `tenant_config`, and returns a
  `live=True` result. This is the "Test Connection" action.

A probe never raises: any exception becomes `health="failed"` with the error in
`detail`. Probes are strictly read-only (list/get calls) — same permission set
discovery already needs, nothing new granted.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from arango.database import StandardDatabase

from app.models.provider import ProviderConfig, ProviderHealth
from app.services.provider_service import get_provider_credentials

# A provider whose last successful discovery is older than this reads as
# "degraded" even with status=active — data is likely stale.
STALE_AFTER_HOURS = 48

_DETAIL_TRUNCATE = 300


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _truncate(msg: str) -> str:
    msg = " ".join(str(msg).split())
    return msg[:_DETAIL_TRUNCATE]


def evaluate_cached_health(config: ProviderConfig) -> ProviderHealth:
    """Derive health from stored signals only — no network I/O."""
    base = {
        "provider_id": config.key,
        "status": config.status,
        "enabled": config.enabled,
        "last_discovery_at": config.last_discovery_at,
        "checked_at": config.last_health_check_at,
        "live": False,
    }
    if not config.enabled:
        return ProviderHealth(health="degraded", reason="provider is disabled", **base)
    if config.status == "error":
        return ProviderHealth(health="failed", reason=config.last_health_result or "last run reported an error", **base)
    if config.status == "pending" or not config.last_discovery_at:
        return ProviderHealth(
            health="degraded", reason="no successful discovery yet", detail=config.last_health_result, **base
        )

    age_hours = (datetime.now(UTC) - datetime.fromisoformat(config.last_discovery_at)).total_seconds() / 3600
    if age_hours > STALE_AFTER_HOURS:
        reason = f"last discovery {int(age_hours)}h ago (> {STALE_AFTER_HOURS}h)"
        return ProviderHealth(health="degraded", reason=reason, **base)
    return ProviderHealth(health="healthy", detail=config.last_health_result, **base)


# ──────────────────────────────────────────────────────────────────────────────
# Live probes — one minimal read-only call per provider, mirroring exactly how
# each discovery task builds its credentials.
# ──────────────────────────────────────────────────────────────────────────────


def _probe_aws(config: ProviderConfig, stored: dict[str, Any]) -> str:
    from app.workers.tasks.cloud_utils import _get_aws_session

    session = _get_aws_session(
        config.role_arn,
        config.external_id,
        aws_access_key_id=stored.get("aws_access_key_id"),
        aws_secret_access_key=stored.get("aws_secret_access_key"),
    )
    region = config.regions[0] if config.regions else "us-east-1"
    identity = session.client("sts", region_name=region).get_caller_identity()
    return f"AWS account {identity.get('Account', '?')} reachable via sts:GetCallerIdentity"


def _probe_azure(config: ProviderConfig, stored: dict[str, Any]) -> str:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient

    if config.azure_client_id and stored.get("azure_client_secret") and config.azure_tenant_id:
        credential: ClientSecretCredential | DefaultAzureCredential = ClientSecretCredential(
            tenant_id=config.azure_tenant_id,
            client_id=config.azure_client_id,
            client_secret=stored["azure_client_secret"],
        )
    else:
        credential = DefaultAzureCredential()
    client = ComputeManagementClient(credential, config.subscription_id)
    next(iter(client.virtual_machines.list_all()), None)
    return f"Azure subscription {config.subscription_id or '?'} reachable (auth + list VMs)"


def _probe_gcp(config: ProviderConfig, stored: dict[str, Any]) -> str:
    from google.cloud.compute_v1.services.instances import InstancesClient
    from google.oauth2 import service_account as sa_credentials

    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    info = stored.get("gcp_service_account_json")
    credentials = sa_credentials.Credentials.from_service_account_info(info, scopes=scopes) if info else None
    project = config.project_id or ""
    next(iter(InstancesClient(credentials=credentials).aggregated_list(project=project)), None)
    return f"GCP project {project or '?'} reachable (aggregated instance list)"


def _probe_k8s(config: ProviderConfig, stored: dict[str, Any]) -> str:
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config

    kubeconfig = stored.get("kubeconfig")
    if kubeconfig:
        k8s_config.load_kube_config_from_dict(kubeconfig)
    else:
        k8s_config.load_incluster_config()
    ns = k8s_client.CoreV1Api().list_namespace(limit=1)
    return f"Kubernetes cluster '{config.cluster_name or '?'}' reachable ({len(ns.items)} namespace(s) visible)"


_PROBES: dict[str, Callable[[ProviderConfig, dict[str, Any]], str]] = {
    "aws": _probe_aws,
    "azure": _probe_azure,
    "gcp": _probe_gcp,
    "k8s": _probe_k8s,
}


def run_connection_test(db: StandardDatabase, config: ProviderConfig) -> ProviderHealth:
    """Run the live probe for this provider and persist the outcome.

    Persists on `tenant_config`: `status` flips to active/error following the
    same convention the discovery tasks use (`_set_provider_status`), plus
    `last_health_check_at` / `last_health_result` for the cards.
    """
    base = {
        "provider_id": config.key,
        "status": config.status,
        "enabled": config.enabled,
        "last_discovery_at": config.last_discovery_at,
        "live": True,
    }
    probe = _PROBES.get(config.provider)
    if probe is None:
        reason = f"no probe implemented for provider '{config.provider}'"
        return ProviderHealth(health="failed", reason=reason, checked_at=_utcnow_iso(), **base)

    started = time.monotonic()
    try:
        stored = get_provider_credentials(db, config.key)
        detail = probe(config, stored or {})
        latency_ms = int((time.monotonic() - started) * 1000)
        _persist_result(db, config.key, status="active", result=detail)
        return ProviderHealth(
            health="healthy",
            status="active",
            detail=_truncate(detail),
            latency_ms=latency_ms,
            checked_at=_utcnow_iso(),
            **{k: v for k, v in base.items() if k != "status"},
        )
    except Exception as exc:
        latency_ms = int((time.monotonic() - started) * 1000)
        detail = _truncate(f"{type(exc).__name__}: {exc}")
        _persist_result(db, config.key, status="error", result=detail)
        return ProviderHealth(
            health="failed",
            status="error",
            reason="connection test failed",
            detail=detail,
            latency_ms=latency_ms,
            checked_at=_utcnow_iso(),
            **{k: v for k, v in base.items() if k != "status"},
        )


def _persist_result(db: StandardDatabase, provider_key: str, *, status: str, result: str) -> None:
    from arango.exceptions import DocumentUpdateError

    try:
        update = {
            "_key": provider_key,
            "status": status,
            "last_health_check_at": _utcnow_iso(),
            "last_health_result": result,
        }
        db.collection("tenant_config").update(update)
    except DocumentUpdateError:
        pass  # config vanished mid-test — nothing to persist
