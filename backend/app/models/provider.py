from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

ProviderType = Literal["aws", "azure", "gcp", "k8s"]
ProviderStatus = Literal["pending", "active", "error", "disabled"]


class ProviderConfig(BaseModel):
    """Stored configuration for a connected cloud provider (no secrets)."""

    key: str
    provider: ProviderType
    display_name: str
    account_id: str | None = None
    subscription_id: str | None = None
    project_id: str | None = None
    cluster_name: str | None = None
    regions: list[str] = Field(default_factory=list)
    enabled: bool = True
    status: ProviderStatus = "pending"
    last_discovery_at: str | None = None
    last_discovery_job_id: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ProviderRegisterRequest(BaseModel):
    provider: ProviderType
    display_name: str
    account_id: str | None = None
    subscription_id: str | None = None
    project_id: str | None = None
    cluster_name: str | None = None
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    validate_connection: bool = True


class ProviderUpdateRequest(BaseModel):
    display_name: str | None = None
    regions: list[str] | None = None
    enabled: bool | None = None


class ProviderRegisterResponse(BaseModel):
    provider_id: str
    discovery_job_id: str | None = None
    message: str


class DiscoverResponse(BaseModel):
    provider_id: str
    discovery_job_id: str
    message: str
