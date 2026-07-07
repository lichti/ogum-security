"""Unit tests for side-scanning service helpers."""

import pytest

from app.models.finding import SeverityLevel
from app.services.side_scanning import cvss_to_severity
from app.services.side_scanning.analyzers.trivy_analyzer import _extract_cvss


@pytest.mark.unit
class TestCvssToSeverity:
    def test_critical_threshold(self):
        assert cvss_to_severity(9.0) == SeverityLevel.CRITICAL

    def test_critical_above_threshold(self):
        assert cvss_to_severity(10.0) == SeverityLevel.CRITICAL

    def test_high_threshold(self):
        assert cvss_to_severity(7.0) == SeverityLevel.HIGH

    def test_high_below_critical(self):
        assert cvss_to_severity(8.9) == SeverityLevel.HIGH

    def test_medium_threshold(self):
        assert cvss_to_severity(4.0) == SeverityLevel.MEDIUM

    def test_medium_below_high(self):
        assert cvss_to_severity(6.9) == SeverityLevel.MEDIUM

    def test_low_above_zero(self):
        assert cvss_to_severity(3.9) == SeverityLevel.LOW

    def test_low_minimum(self):
        assert cvss_to_severity(0.1) == SeverityLevel.LOW

    def test_informational_zero(self):
        assert cvss_to_severity(0.0) == SeverityLevel.INFORMATIONAL

    def test_informational_negative(self):
        # Defensive: negative score (malformed input) maps to INFORMATIONAL
        assert cvss_to_severity(-1.0) == SeverityLevel.INFORMATIONAL


@pytest.mark.unit
class TestExtractCvss:
    def test_extracts_nvd_v3_score(self):
        vuln = {"CVSS": {"nvd": {"V3Score": 7.5}}}
        assert _extract_cvss(vuln) == 7.5

    def test_extracts_vendor_score(self):
        vuln = {"CVSS": {"redhat": {"V3Score": 5.0}}}
        assert _extract_cvss(vuln) == 5.0

    def test_returns_zero_when_no_cvss(self):
        assert _extract_cvss({}) == 0.0

    def test_returns_zero_when_no_v3(self):
        vuln = {"CVSS": {"nvd": {"V2Score": 6.0}}}
        assert _extract_cvss(vuln) == 0.0

    def test_handles_malformed_cvss(self):
        vuln = {"CVSS": {"nvd": {"V3Score": "not-a-number"}}}
        assert _extract_cvss(vuln) == 0.0
