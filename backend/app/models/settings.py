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
