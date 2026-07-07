from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SeverityLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FindingStatus(StrEnum):
    FAIL = "FAIL"
    PASS_ = "PASS"
    MUTED = "MUTED"
    ACCEPTED = "ACCEPTED"


class FindingSource(StrEnum):
    CSPM = "cspm"
    IAC = "iac"
    SIDE_SCANNING = "side_scanning"


class ScanJobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Finding(BaseModel):
    finding_id: str
    tenant_id: str
    check_id: str
    title: str
    description: str
    resource_id: str
    resource_arn: str | None = None
    resource_type: str
    severity: SeverityLevel
    status: FindingStatus
    provider: str
    region: str | None = None
    account_id: str
    framework_mapping: list[str] = Field(default_factory=list)
    remediation: str | None = None
    remediation_code: str | None = None
    source: FindingSource = FindingSource.CSPM
    detected_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    mute_reason: str | None = None
    scan_job_id: str | None = None
    raw_output: dict[str, Any] = Field(default_factory=dict)

    def arango_key(self) -> str:
        # ArangoDB _key only allows [a-zA-Z0-9_-]. Prowler resource names/UIDs
        # can contain ARNs, dots, parens, @ signs, etc. — hash avoids any edge case.
        raw = f"{self.check_id}|{self.resource_id}|{self.tenant_id}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_arango_doc(self) -> dict[str, Any]:
        doc = self.model_dump(mode="json")
        doc["_key"] = self.arango_key()
        return doc

    def to_arango_update(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "severity": self.severity,
            "updated_at": self.updated_at.isoformat(),
            "framework_mapping": self.framework_mapping,
            "remediation": self.remediation,
            "remediation_code": self.remediation_code,
            "raw_output": self.raw_output,
        }


class ScanJob(BaseModel):
    job_id: str
    tenant_id: str
    provider_id: str
    provider: str
    frameworks: list[str]
    regions: list[str] = Field(default_factory=list)
    status: ScanJobStatus = ScanJobStatus.QUEUED
    checks_total: int = 0
    checks_completed: int = 0
    findings_found: int = 0
    findings_fail: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    iac_config: dict[str, Any] | None = None
    created_at: datetime = Field(default_factory=_utcnow)

    def to_arango_doc(self) -> dict[str, Any]:
        doc = self.model_dump(mode="json")
        doc["_key"] = self.job_id
        return doc
