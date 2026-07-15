from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from arango.database import StandardDatabase

from app.models.settings import SLASettings

SLAStatus = Literal["within_sla", "at_risk", "overdue"]

_DAYS_BY_SEVERITY = {
    "CRITICAL": "critical_days",
    "HIGH": "high_days",
    "MEDIUM": "medium_days",
    "LOW": "low_days",
}


def deadline_days_for_severity(severity: str, sla: SLASettings) -> int | None:
    attr = _DAYS_BY_SEVERITY.get(severity)
    return getattr(sla, attr) if attr else None


def classify_sla(detected_at: datetime, severity: str, sla: SLASettings, now: datetime) -> SLAStatus | None:
    """Port of the frontend's `classifySLA` (SLABadge.tsx) — kept in lockstep with it.

    At Risk = within 20% of the remaining SLA window. Overdue = past the deadline.
    Returns None for severities with no configured SLA (e.g. INFORMATIONAL).
    """
    deadline_days = deadline_days_for_severity(severity, sla)
    if deadline_days is None:
        return None

    deadline = detected_at + timedelta(days=deadline_days)
    total = deadline - detected_at
    remaining = deadline - now

    if remaining.total_seconds() <= 0:
        return "overdue"
    if remaining.total_seconds() <= total.total_seconds() * 0.2:
        return "at_risk"
    return "within_sla"


def sla_summary(db: StandardDatabase, tenant_id: str, sla: SLASettings, now: datetime) -> dict[str, int]:
    counts = {"within_sla": 0, "at_risk": 0, "overdue": 0}
    if not db.has_collection("findings"):
        return counts

    cursor = db.aql.execute(
        "FOR f IN findings "
        'FILTER f.tenant_id == @tenant_id AND f.status == "FAIL" '
        "RETURN {detected_at: f.detected_at, severity: f.severity}",
        bind_vars={"tenant_id": tenant_id},
    )
    for row in cursor:
        detected_at = datetime.fromisoformat(row["detected_at"])
        status = classify_sla(detected_at, row["severity"], sla, now)
        if status:
            counts[status] += 1
    return counts
