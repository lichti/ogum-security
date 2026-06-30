from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from arango.database import StandardDatabase

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.provider import (
    DiscoverRequest,
    DiscoverResponse,
    ProviderConfig,
    ProviderRegisterRequest,
    ProviderRegisterResponse,
    ProviderUpdateRequest,
)
from app.services.provider_service import (
    delete_provider,
    get_provider,
    get_provider_credentials,
    list_providers,
    register_provider,
    update_provider,
    update_provider_last_discovery,
)
from app.workers.tasks.azure_discovery import discover_azure
from app.workers.tasks.discovery import _get_aws_session, discover_aws
from app.workers.tasks.gcp_discovery import discover_gcp
from app.workers.tasks.k8s_discovery import discover_k8s

router = APIRouter(prefix="/api/v1/providers", tags=["providers"])


def _validate_aws(
    regions: list[str],
    role_arn: str | None = None,
    external_id: str | None = None,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> str:
    """Validate AWS credentials via ec2:DescribeRegions + sts:GetCallerIdentity."""
    try:
        session = _get_aws_session(
            role_arn, external_id,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )
        region = regions[0] if regions else "us-east-1"
        ec2 = session.client("ec2", region_name=region)
        ec2.describe_regions(RegionNames=regions[:1])
        sts = session.client("sts", region_name=region)
        return sts.get_caller_identity().get("Account", "")
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"AWS validation failed: {exc}")


def _dispatch_discovery(
    provider: str,
    tenant_id: str,
    config_key: str,
    request: ProviderRegisterRequest,
    db: StandardDatabase,
    role_arn: str | None = None,
    external_id: str | None = None,
) -> str | None:
    """Dispatch discovery task for the given provider. Returns job_id or None.

    Sensitive credentials (aws_secret_access_key, azure_client_secret,
    gcp_service_account_json, kubeconfig) are passed as task kwargs and are
    ephemeral — they live only in the Celery message broker and worker memory,
    never in ArangoDB or application logs.

    For re-triggered discovery (POST /{id}/discover), credentials are not
    available (not stored). The task falls back to ambient worker credentials.
    """
    job_id: str | None = None
    try:
        if provider == "aws":
            job_id = discover_aws.delay(
                tenant_id,
                request.regions,
                request.account_id,
                role_arn=role_arn,
                external_id=external_id,
                provider_key=config_key,
                aws_access_key_id=request.aws_access_key_id,
                aws_secret_access_key=request.aws_secret_access_key,
            ).id
        elif provider == "azure":
            job_id = discover_azure.delay(
                tenant_id,
                request.subscription_id or "",
                client_id=request.azure_client_id,
                client_secret=request.azure_client_secret,
                azure_tenant_id=request.azure_tenant_id,
                provider_key=config_key,
            ).id
        elif provider == "gcp":
            job_id = discover_gcp.delay(
                tenant_id,
                request.project_id or "",
                service_account_info=request.gcp_service_account_json,
                provider_key=config_key,
            ).id
        elif provider == "k8s":
            job_id = discover_k8s.delay(
                tenant_id,
                request.cluster_name or "",
                kubeconfig=request.kubeconfig,
                provider_key=config_key,
            ).id

        if job_id:
            update_provider_last_discovery(db, config_key, job_id)
    except Exception:
        pass  # config saved even if dispatch fails — user can retry via POST /{id}/discover
    return job_id


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/v1/providers
# ──────────────────────────────────────────────────────────────────────────────

@router.post("", response_model=ApiResponse[ProviderRegisterResponse], status_code=201)
async def register_provider_endpoint(
    request: ProviderRegisterRequest,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[ProviderRegisterResponse]:
    if request.validate_connection and request.provider == "aws":
        detected = _validate_aws(
            request.regions,
            role_arn=request.role_arn,
            external_id=None,
            aws_access_key_id=request.aws_access_key_id,
            aws_secret_access_key=request.aws_secret_access_key,
        )
        if not request.account_id and detected:
            request = request.model_copy(update={"account_id": detected})

    config = register_provider(db, x_tenant_id, request)
    job_id = _dispatch_discovery(
        request.provider, x_tenant_id, config.key, request, db,
        role_arn=config.role_arn,
        external_id=config.external_id,
    )

    queued = "queued" if job_id else "not started"
    return ApiResponse(
        data=ProviderRegisterResponse(
            provider_id=config.key,
            discovery_job_id=job_id,
            message=f"Provider registered. Discovery job {queued} — check /api/v1/inventory for resources.",
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/providers
# ──────────────────────────────────────────────────────────────────────────────

@router.get("", response_model=ApiResponse[list[ProviderConfig]])
async def list_providers_endpoint(
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[list[ProviderConfig]]:
    return ApiResponse(data=list_providers(db))


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/providers/{provider_id}
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/{provider_id}", response_model=ApiResponse[ProviderConfig])
async def get_provider_endpoint(
    provider_id: str,
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ProviderConfig]:
    config = get_provider(db, provider_id)
    if not config:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ApiResponse(data=config)


# ──────────────────────────────────────────────────────────────────────────────
# PATCH /api/v1/providers/{provider_id}
# ──────────────────────────────────────────────────────────────────────────────

@router.patch("/{provider_id}", response_model=ApiResponse[ProviderConfig])
async def update_provider_endpoint(
    provider_id: str,
    update: ProviderUpdateRequest,
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[ProviderConfig]:
    config = update_provider(db, provider_id, update)
    if not config:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ApiResponse(data=config)


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/v1/providers/{provider_id}/discover
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/{provider_id}/discover", response_model=ApiResponse[DiscoverResponse])
async def trigger_discovery_endpoint(
    provider_id: str,
    body: DiscoverRequest | None = None,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[DiscoverResponse]:
    config = get_provider(db, provider_id)
    if not config:
        raise HTTPException(status_code=404, detail="Provider not found")
    if not config.enabled:
        raise HTTPException(status_code=409, detail="Provider is disabled. Enable it before triggering discovery.")

    # Body credentials override stored ones; stored credentials are the fallback for scheduled jobs.
    body_creds = body or DiscoverRequest()
    stored = get_provider_credentials(db, provider_id)
    from app.models.provider import ProviderRegisterRequest as _Req
    stub = _Req(
        provider=config.provider,
        display_name=config.display_name,
        account_id=config.account_id,
        subscription_id=config.subscription_id,
        project_id=config.project_id,
        cluster_name=config.cluster_name,
        regions=config.regions,
        validate_connection=False,
        azure_tenant_id=config.azure_tenant_id,
        azure_client_id=config.azure_client_id,
        aws_access_key_id=body_creds.aws_access_key_id or stored.get("aws_access_key_id"),
        aws_secret_access_key=body_creds.aws_secret_access_key or stored.get("aws_secret_access_key"),
        azure_client_secret=body_creds.azure_client_secret or stored.get("azure_client_secret"),
        gcp_service_account_json=body_creds.gcp_service_account_json or stored.get("gcp_service_account_json"),
        kubeconfig=body_creds.kubeconfig or stored.get("kubeconfig"),
    )
    job_id = _dispatch_discovery(
        config.provider, x_tenant_id, provider_id, stub, db,
        role_arn=config.role_arn,
        external_id=config.external_id,
    )
    if not job_id:
        raise HTTPException(status_code=503, detail="Failed to dispatch discovery job. Check worker connectivity.")

    return ApiResponse(
        data=DiscoverResponse(
            provider_id=provider_id,
            discovery_job_id=job_id,
            message="Discovery job queued — check /api/v1/inventory for resources.",
        )
    )


# ──────────────────────────────────────────────────────────────────────────────
# DELETE /api/v1/providers/{provider_id}
# ──────────────────────────────────────────────────────────────────────────────

@router.delete("/{provider_id}", response_model=ApiResponse[dict])
async def delete_provider_endpoint(
    provider_id: str,
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict]:
    ok, purge_counts = delete_provider(db, provider_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Provider not found")
    return ApiResponse(data={
        "deleted": True,
        "provider_id": provider_id,
        "purged": purge_counts,
    })
