from __future__ import annotations

import boto3
from fastapi import APIRouter, Depends, Header, HTTPException
from arango.database import StandardDatabase

from app.api.v1.inventory import get_tenant_db
from app.models.api_responses import ApiResponse
from app.models.provider import ProviderConfig, ProviderRegisterRequest, ProviderRegisterResponse
from app.services.provider_service import (
    delete_provider,
    list_providers,
    register_provider,
    update_provider_last_discovery,
)
from app.workers.tasks.discovery import discover_aws
from app.workers.tasks.azure_discovery import discover_azure
from app.workers.tasks.gcp_discovery import discover_gcp
from app.workers.tasks.k8s_discovery import discover_k8s

router = APIRouter(prefix="/api/v1/providers", tags=["providers"])


def _validate_aws(regions: list[str]) -> str:
    """Validate AWS credentials via ec2:DescribeRegions + sts:GetCallerIdentity."""
    try:
        region = regions[0] if regions else "us-east-1"
        ec2 = boto3.client("ec2", region_name=region)
        ec2.describe_regions(RegionNames=regions[:1])
        sts = boto3.client("sts", region_name=region)
        return sts.get_caller_identity().get("Account", "")
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"AWS validation failed: {exc}")


@router.post("", response_model=ApiResponse[ProviderRegisterResponse], status_code=201)
async def register_provider_endpoint(
    request: ProviderRegisterRequest,
    db: StandardDatabase = Depends(get_tenant_db),
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> ApiResponse[ProviderRegisterResponse]:
    if request.validate_connection and request.provider == "aws":
        detected = _validate_aws(request.regions)
        if not request.account_id and detected:
            request = request.model_copy(update={"account_id": detected})

    config = register_provider(db, x_tenant_id, request)

    job_id: str | None = None
    try:
        if request.provider == "aws":
            job_id = discover_aws.delay(x_tenant_id, request.regions, request.account_id).id
        elif request.provider == "azure":
            job_id = discover_azure.delay(x_tenant_id, request.subscription_id or "").id
        elif request.provider == "gcp":
            job_id = discover_gcp.delay(x_tenant_id, request.project_id or "").id
        elif request.provider == "k8s":
            job_id = discover_k8s.delay(x_tenant_id, request.cluster_name or "").id

        if job_id:
            update_provider_last_discovery(db, config.key, job_id)
    except Exception:
        pass  # config saved even if dispatch fails — user can retry manually

    queued = "queued" if job_id else "not started"
    return ApiResponse(
        data=ProviderRegisterResponse(
            provider_id=config.key,
            discovery_job_id=job_id,
            message=f"Provider registered. Discovery job {queued} — check /api/v1/inventory for resources.",
        )
    )


@router.get("", response_model=ApiResponse[list[ProviderConfig]])
async def list_providers_endpoint(
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[list[ProviderConfig]]:
    return ApiResponse(data=list_providers(db))


@router.delete("/{provider_id}", response_model=ApiResponse[dict])
async def delete_provider_endpoint(
    provider_id: str,
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict]:
    if not delete_provider(db, provider_id):
        raise HTTPException(status_code=404, detail="Provider not found")
    return ApiResponse(data={"deleted": True, "provider_id": provider_id})
