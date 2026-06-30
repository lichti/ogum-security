from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Meta(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    total: int | None = None
    limit: int | None = None
    offset: int | None = None


class ApiResponse(BaseModel, Generic[T]):  # noqa: UP046
    data: T
    meta: Meta = Field(default_factory=Meta)
    error: str | None = None


class ResourceSummary(BaseModel):
    """Compact resource representation for list endpoints."""

    key: str
    tenant_id: str
    provider: str
    resource_type: str
    resource_id: str
    name: str
    region: str | None
    account_id: str | None
    status: str
    is_public: bool
    tags: dict[str, str]
    last_scanned_at: str | None
    updated_at: str | None


class EdgeSummary(BaseModel):
    """Edge representation for the detail endpoint."""

    edge_type: str
    direction: str
    peer_key: str
    peer_collection: str
    peer_type: str | None


class ResourceDetail(ResourceSummary):
    """Full resource with metadata and edges."""

    arn: str | None
    raw_metadata: dict[str, Any]
    edges: list[EdgeSummary]


class InventoryStats(BaseModel):
    by_provider: dict[str, int]
    by_resource_type: dict[str, int]
    by_status: dict[str, int]
    identity_count: int
    data_asset_count: int
    last_discovery_at: str | None


class DiscoverJobResponse(BaseModel):
    job_id: str
    tenant_id: str
    provider: str
    regions: list[str]
    status: str = "queued"
