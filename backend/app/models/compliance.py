from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ComplianceRequirementNode(BaseModel):
    """A single control, resolved against the AWS catalog when available (US-14.16)."""

    control_id: str
    name: str
    description: str | None = None
    status: Literal["PASS", "FAIL", "UNSCORED"]
    finding_key: str | None = None
    pass_count: int = 0
    fail_count: int = 0


class ComplianceSectionNode(BaseModel):
    """One level of the section -> sub-section -> requirement tree (US-14.15/US-14.16).

    `subsections` is only populated when the catalog's Attributes carry an explicit
    sub-section (NIST 800-53 does; most other frameworks don't) — a section with no
    sub-section data attaches its `requirements` directly, so the accordion degrades
    from 3 levels to 2 rather than rendering an empty middle tier.
    """

    key: str
    label: str
    pass_count: int
    fail_count: int
    unscored_count: int
    total: int
    score_by_control: float
    subsections: list[ComplianceSectionNode] = Field(default_factory=list)
    requirements: list[ComplianceRequirementNode] = Field(default_factory=list)


ComplianceSectionNode.model_rebuild()


class ComplianceFrameworkDetail(BaseModel):
    """Response for `GET /api/v1/compliance/frameworks/{id}` (US-14.14/US-14.15/US-14.16)."""

    id: str
    family: str
    family_label: str
    version_label: str
    score_by_control: float
    score_by_asset: float
    pass_count: int
    fail_count: int
    unscored_count: int
    total_controls: int
    catalog_available: bool
    sections: list[ComplianceSectionNode] = Field(default_factory=list)


class ComplianceScoreTrendPoint(BaseModel):
    """One daily snapshot for the Score Trend chart (US-14.15)."""

    date: str
    score_by_control: float
    score_by_asset: float
    pass_count: int
    fail_count: int
    unscored_count: int
