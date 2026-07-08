"""Unit tests for graph exposure service logic (no ArangoDB required)."""

import pytest

from app.services.graph.privilege_escalation import (
    _DANGEROUS_PERMISSION_PATTERNS,
    ESCALATION_PATTERNS,
)


@pytest.mark.unit
class TestEscalationPatterns:
    def test_has_ten_patterns(self) -> None:
        assert len(ESCALATION_PATTERNS) == 10

    def test_pattern_ids_are_unique(self) -> None:
        ids = [p["id"] for p in ESCALATION_PATTERNS]
        assert len(ids) == len(set(ids))

    def test_all_patterns_have_required_fields(self) -> None:
        for pattern in ESCALATION_PATTERNS:
            assert "id" in pattern
            assert "name" in pattern
            assert "description" in pattern

    def test_dangerous_permission_map_coverage(self) -> None:
        # Must cover PRIVESC-03 through PRIVESC-09
        mapped_ids = set(_DANGEROUS_PERMISSION_PATTERNS.values())
        expected = {"PRIVESC-03", "PRIVESC-04", "PRIVESC-05", "PRIVESC-06", "PRIVESC-07", "PRIVESC-08", "PRIVESC-09"}
        assert expected.issubset(mapped_ids)

    def test_dangerous_permission_keys_are_lowercase(self) -> None:
        for action in _DANGEROUS_PERMISSION_PATTERNS:
            assert action == action.lower(), f"Action key should be lowercase: {action}"
