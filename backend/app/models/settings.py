from __future__ import annotations

from pydantic import BaseModel


class SLASettings(BaseModel):
    """Per-severity remediation SLA, in days (US-14.08). Defaults per the epic spec."""

    critical_days: int = 7
    high_days: int = 30
    medium_days: int = 90
    low_days: int = 180


class SLASettingsUpdateRequest(BaseModel):
    critical_days: int | None = None
    high_days: int | None = None
    medium_days: int | None = None
    low_days: int | None = None


class ComplianceFamilySettings(BaseModel):
    """Per-framework-family configuration (US-14.19): whether it's shown on the
    Compliance page and counted in tenant-wide aggregates (ThreatScore, top failing
    checks), plus the desired By Control score. The target is display-only today (a
    vs-goal indicator wherever the score already appears) but is modeled as its own
    field so a future alerting job (Ogum.Pulse) can read it without a schema change —
    see `compliance_service` doc for how `enabled` filters aggregates.
    """

    enabled: bool = True
    target_by_control: float | None = None


class ComplianceFamilySettingsUpdateRequest(BaseModel):
    enabled: bool | None = None
    target_by_control: float | None = None
    # A plain `None` in the update request means "leave unchanged" (matches
    # SLASettingsUpdateRequest's partial-update semantics), so clearing a
    # previously-set target back to "no goal" needs its own explicit signal.
    clear_target_by_control: bool = False


class ComplianceFamilySettingsView(ComplianceFamilySettings):
    """One row of `GET /api/v1/settings/compliance` — settings merged with the
    family's identity so the frontend doesn't need a second lookup to label the row.
    """

    family_key: str
    family_label: str
