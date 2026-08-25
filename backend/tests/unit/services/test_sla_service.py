from datetime import UTC, datetime, timedelta

import pytest

from app.models.settings import SLASettings
from app.services.sla_service import classify_sla

SLA = SLASettings(critical_days=7, high_days=30, medium_days=90, low_days=180)


@pytest.mark.unit
class TestClassifySla:
    def test_freshly_detected_finding_is_within_sla(self):
        now = datetime(2026, 1, 8, tzinfo=UTC)
        detected_at = now - timedelta(days=1)
        assert classify_sla(detected_at, "CRITICAL", SLA, now) == "within_sla"

    def test_exactly_at_the_deadline_is_overdue(self):
        now = datetime(2026, 1, 8, tzinfo=UTC)
        detected_at = now - timedelta(days=7)  # CRITICAL deadline is exactly 7 days
        assert classify_sla(detected_at, "CRITICAL", SLA, now) == "overdue"

    def test_one_second_past_the_deadline_is_overdue(self):
        now = datetime(2026, 1, 8, tzinfo=UTC)
        detected_at = now - timedelta(days=7, seconds=1)
        assert classify_sla(detected_at, "CRITICAL", SLA, now) == "overdue"

    def test_exactly_at_the_20_percent_remaining_threshold_is_at_risk(self):
        # HIGH: 30-day window. 20% remaining = 6 days left = detected 24 days ago.
        now = datetime(2026, 1, 25, tzinfo=UTC)
        detected_at = now - timedelta(days=24)
        assert classify_sla(detected_at, "HIGH", SLA, now) == "at_risk"

    def test_just_above_the_20_percent_remaining_threshold_is_within_sla(self):
        now = datetime(2026, 1, 25, tzinfo=UTC)
        detected_at = now - timedelta(days=23, hours=23)
        assert classify_sla(detected_at, "HIGH", SLA, now) == "within_sla"

    def test_severity_with_no_configured_sla_returns_none(self):
        now = datetime(2026, 1, 8, tzinfo=UTC)
        assert classify_sla(now - timedelta(days=400), "INFORMATIONAL", SLA, now) is None
