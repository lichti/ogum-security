from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, model_validator


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize_key_part(value: str) -> str:
    """Replace slash (invalid in ArangoDB keys) with underscore."""
    return value.replace("/", "_")


class ResourceStatus(StrEnum):
    ACTIVE = "active"
    DELETED = "deleted"


class Provider(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    K8S = "k8s"


class IdentityType(StrEnum):
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    SERVICE_ACCOUNT = "service_account"


class ResourceBase(BaseModel):
    """Base schema for all cloud resources stored in the graph."""

    tenant_id: str
    provider: Provider
    resource_type: str
    resource_id: str
    name: str
    region: str | None = None
    account_id: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    status: ResourceStatus = ResourceStatus.ACTIVE
    is_public: bool = False
    base_severity: int = 0
    last_scanned_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    deleted_at: datetime | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    scan_source: str = "ogum.inventory"

    def arango_key(self) -> str:
        resource_type = self.resource_type.replace(".", "_")
        resource_id = _sanitize_key_part(self.resource_id)
        return f"{self.provider}_{resource_type}_{resource_id}"

    def to_arango_doc(self) -> dict[str, Any]:
        doc = self.model_dump(mode="json")
        doc["_key"] = self.arango_key()
        return doc

    def to_arango_update(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "updated_at": self.updated_at.isoformat(),
            "last_scanned_at": self.last_scanned_at.isoformat(),
            "status": self.status,
            "tags": self.tags,
            "is_public": self.is_public,
            "base_severity": self.base_severity,
            "raw_metadata": self.raw_metadata,
        }


class AWSResource(ResourceBase):
    """AWS cloud resource. account_id is extracted from the ARN when omitted."""

    provider: Provider = Provider.AWS
    arn: str

    @model_validator(mode="after")
    def _extract_account_id(self) -> AWSResource:
        if self.account_id is None and self.arn:
            parts = self.arn.split(":")
            if len(parts) >= 5 and parts[4]:
                self.account_id = parts[4]
        return self


class Identity(BaseModel):
    """IAM role, user, or service account."""

    tenant_id: str
    provider: Provider
    account_id: str | None = None
    identity_type: IdentityType
    name: str
    arn: str
    policies: list[str] = Field(default_factory=list)
    granted_actions: list[str] = Field(default_factory=list)
    used_actions_90d: list[str] = Field(default_factory=list)
    privilege_gap_score: int = 0
    status: ResourceStatus = ResourceStatus.ACTIVE
    last_scanned_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    deleted_at: datetime | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _extract_account_id(self) -> Identity:
        if self.account_id is None and self.arn:
            parts = self.arn.split(":")
            if len(parts) >= 5 and parts[4]:
                self.account_id = parts[4]
        return self

    def arango_key(self) -> str:
        id_type = self.identity_type.replace("iam_", "")
        name = _sanitize_key_part(self.name)
        return f"{self.provider}_{id_type}_{name}"

    def to_arango_doc(self) -> dict[str, Any]:
        doc = self.model_dump(mode="json")
        doc["_key"] = self.arango_key()
        return doc

    def to_arango_update(self) -> dict[str, Any]:
        return {
            "updated_at": self.updated_at.isoformat(),
            "last_scanned_at": self.last_scanned_at.isoformat(),
            "status": self.status,
            "policies": self.policies,
            "granted_actions": self.granted_actions,
            "raw_metadata": self.raw_metadata,
        }


class NetworkEndpoint(BaseModel):
    """Open port, security group rule, or internet gateway."""

    tenant_id: str
    provider: Provider
    account_id: str | None = None
    endpoint_type: str
    protocol: str | None = None
    port: int | None = None
    cidr: str | None = None
    is_public: bool = False
    resource_id: str
    status: ResourceStatus = ResourceStatus.ACTIVE
    last_scanned_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    def arango_key(self) -> str:
        endpoint_type = self.endpoint_type.replace(".", "_")
        resource_id = _sanitize_key_part(self.resource_id)
        port_suffix = f"_{self.port}" if self.port is not None else ""
        return f"{self.provider}_{endpoint_type}_{resource_id}{port_suffix}"

    def to_arango_doc(self) -> dict[str, Any]:
        doc = self.model_dump(mode="json")
        doc["_key"] = self.arango_key()
        return doc


class DataAsset(BaseModel):
    """Data store with classification metadata (S3 bucket, RDS, database)."""

    tenant_id: str
    provider: Provider
    account_id: str | None = None
    asset_type: str
    name: str
    arn: str
    contains_pii: bool = False
    contains_pci: bool = False
    classification_tags: list[str] = Field(default_factory=list)
    is_public: bool = False
    encryption_enabled: bool = False
    status: ResourceStatus = ResourceStatus.ACTIVE
    last_scanned_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    deleted_at: datetime | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _extract_account_id(self) -> DataAsset:
        if self.account_id is None and self.arn:
            parts = self.arn.split(":")
            if len(parts) >= 5 and parts[4]:
                self.account_id = parts[4]
        return self

    def arango_key(self) -> str:
        asset_type = self.asset_type.replace(".", "_")
        name = _sanitize_key_part(self.name)
        return f"{self.provider}_{asset_type}_{name}"

    def to_arango_doc(self) -> dict[str, Any]:
        doc = self.model_dump(mode="json")
        doc["_key"] = self.arango_key()
        return doc

    def to_arango_update(self) -> dict[str, Any]:
        return {
            "updated_at": self.updated_at.isoformat(),
            "last_scanned_at": self.last_scanned_at.isoformat(),
            "status": self.status,
            "is_public": self.is_public,
            "encryption_enabled": self.encryption_enabled,
            "contains_pii": self.contains_pii,
            "contains_pci": self.contains_pci,
            "classification_tags": self.classification_tags,
            "raw_metadata": self.raw_metadata,
        }
