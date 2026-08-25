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
    accepted_count: int = 0
    muted_count: int = 0


class ComplianceSectionNode(BaseModel):
    """One level of the section -> sub-section -> requirement tree (US-14.15/16),
    By Control: ACCEPTED folded into Pass, MUTED folded into Unscored, any FAIL on
    the control wins regardless of how many assets pass. Score = (Pass + Unscored) /
    Total — a control nobody has evaluated yet counts toward the compliant side, not
    against it (see `compliance_service._score_by_control`).

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
    subsections: list[ComplianceSectionNode] = Field(default_factory=list)
    requirements: list[ComplianceRequirementNode] = Field(default_factory=list)


ComplianceSectionNode.model_rebuild()


class ComplianceFrameworkDetail(BaseModel):
    """Response for `GET /api/v1/compliance/frameworks/{id}` (US-14.14/15/16/19).

    See `ComplianceSectionNode` for the By Control fold rule, mirrored here at the
    framework-total level. `target_by_control` is the desired score from Compliance
    Settings (US-14.19), `None` when no goal is configured for this framework's
    family — display-only today (a vs-goal indicator wherever the score appears),
    not enforced anywhere.
    """

    id: str
    family: str
    family_label: str
    version_label: str
    score_by_control: float
    target_by_control: float | None
    control_pass_count: int
    control_fail_count: int
    control_unscored_count: int
    control_total: int
    catalog_available: bool
    sections: list[ComplianceSectionNode] = Field(default_factory=list)


class ComplianceControlAsset(BaseModel):
    """One asset's Pass/Fail tally for a single control (the compliance page's
    control drill-down panel, Assets tab). ACCEPTED folds into `pass_count`, same as
    everywhere else in this module; MUTED findings are excluded from both counts
    (they show up under the panel's "All" filter, not under Pass or Fail)."""

    resource_id: str
    resource_type: str
    provider: str
    region: str | None = None
    account_id: str
    pass_count: int
    fail_count: int


class ComplianceScoreTrendPoint(BaseModel):
    """One daily By Control snapshot for the Score Trend chart (US-14.15/US-14.18)."""

    date: str
    score_by_control: float
    pass_count: int
    fail_count: int
    unscored_count: int
