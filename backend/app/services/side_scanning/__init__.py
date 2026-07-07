"""Side-scanning (Ogum.Dynamic) — agentless deep filesystem analysis."""

from __future__ import annotations

from app.models.finding import SeverityLevel


def cvss_to_severity(score: float) -> SeverityLevel:
    """Map a CVSS v3 base score to an Ogum severity tier.

    Ranges:
        CRITICAL  >= 9.0
        HIGH      >= 7.0
        MEDIUM    >= 4.0
        LOW       > 0.0
        INFO      == 0.0 (no CVSS data available)
    """
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    if score > 0.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFORMATIONAL
