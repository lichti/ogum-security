from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ComplianceRequirementNode(BaseModel):
    """A single control, resolved against the AWS catalog when available (US-14.16).

    `status` is always the Control view's status (ACCEPTED folded into PASS, MUTED
    folded into UNSCORED — see `compliance_service._score_by_control`) since a single
    requirement row needs one canonical badge regardless of which top-level view is
    active. The raw `*_count` fields carry the real per-status finding counts so the
    Findings view can still show the untouched breakdown elsewhere in the UI.
    """

    control_id: str
    name: str
    description: str | None = None
    status: Literal["PASS", "FAIL", "UNSCORED"]
    finding_key: str | None = None
    pass_count: int = 0
    fail_count: int = 0
    accepted_count: int = 0
    muted_count: int = 0


class ComplianceSectionNode(BaseModel):
    """One level of the section -> sub-section -> requirement tree (US-14.15/US-14.16).

    Carries both views' aggregates so the frontend can toggle between them without a
    refetch: `control_*`/`score_by_control` count *controls* (ACCEPTED folded into
    Pass, MUTED folded into Unscored); `finding_*`/`score_by_asset` count raw
    *findings* by their real status, MUTED/ACCEPTED included but excluded from the
    score_by_asset ratio itself (same denominator rule as before).

    `subsections` is only populated when the catalog's Attributes carry an explicit
    sub-section (NIST 800-53 does; most other frameworks don't) — a section with no
    sub-section data attaches its `requirements` directly, so the accordion degrades
    from 3 levels to 2 rather than rendering an empty middle tier.
    """

    key: str
    label: str
    control_pass_count: int
    control_fail_count: int
    control_unscored_count: int
    control_total: int
    score_by_control: float
    finding_pass_count: int
    finding_fail_count: int
    finding_accepted_count: int
    finding_muted_count: int
    score_by_asset: float
    subsections: list[ComplianceSectionNode] = Field(default_factory=list)
    requirements: list[ComplianceRequirementNode] = Field(default_factory=list)


ComplianceSectionNode.model_rebuild()


class ComplianceFrameworkDetail(BaseModel):
    """Response for `GET /api/v1/compliance/frameworks/{id}` (US-14.14/US-14.15/US-14.16).

    See `ComplianceSectionNode` for the Control vs. Findings view field split —
    mirrored here at the framework-total level.
    """

    id: str
    family: str
    family_label: str
    version_label: str
    score_by_control: float
    score_by_asset: float
    control_pass_count: int
    control_fail_count: int
    control_unscored_count: int
    control_total: int
    finding_pass_count: int
    finding_fail_count: int
    finding_accepted_count: int
    finding_muted_count: int
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
