"""Unit tests for mitre_service.py — chain mapping and helper functions."""

from __future__ import annotations

import pytest

from app.services.mitre_service import MITRE_CHAINS, build_mitre_chain_for_tc, get_techniques_for_path


@pytest.mark.unit
class TestMitreChains:
    def test_tc01_returns_three_techniques(self) -> None:
        assert MITRE_CHAINS["TC-01"] == ["T1190", "T1078.004", "T1537"]

    def test_tc02_returns_two_techniques(self) -> None:
        assert MITRE_CHAINS["TC-02"] == ["T1530", "T1552.005"]

    def test_tc03_returns_two_techniques(self) -> None:
        assert MITRE_CHAINS["TC-03"] == ["T1078", "T1213"]

    def test_tc04_returns_two_techniques(self) -> None:
        assert MITRE_CHAINS["TC-04"] == ["T1611", "T1552.005"]

    def test_all_four_rules_present(self) -> None:
        assert set(MITRE_CHAINS.keys()) == {"TC-01", "TC-02", "TC-03", "TC-04"}


@pytest.mark.unit
class TestBuildMitreChainForTC:
    def test_tc01_chain(self) -> None:
        chain = build_mitre_chain_for_tc("TC-01")
        assert chain == ["T1190", "T1078.004", "T1537"]

    def test_tc02_chain(self) -> None:
        chain = build_mitre_chain_for_tc("TC-02")
        assert chain == ["T1530", "T1552.005"]

    def test_tc03_chain(self) -> None:
        chain = build_mitre_chain_for_tc("TC-03")
        assert chain == ["T1078", "T1213"]

    def test_tc04_chain(self) -> None:
        chain = build_mitre_chain_for_tc("TC-04")
        assert chain == ["T1611", "T1552.005"]

    def test_unknown_rule_returns_empty_list(self) -> None:
        assert build_mitre_chain_for_tc("TC-99") == []
        assert build_mitre_chain_for_tc("") == []
        assert build_mitre_chain_for_tc("internet_to_data") == []

    def test_returns_list_of_strings(self) -> None:
        for rule_id in MITRE_CHAINS:
            result = build_mitre_chain_for_tc(rule_id)
            assert isinstance(result, list)
            assert all(isinstance(item, str) for item in result)

    def test_returns_independent_copy(self) -> None:
        chain1 = build_mitre_chain_for_tc("TC-01")
        chain2 = build_mitre_chain_for_tc("TC-01")
        chain1.append("INJECTED")
        assert "INJECTED" not in chain2
        assert "INJECTED" not in MITRE_CHAINS["TC-01"]


@pytest.mark.unit
class TestGetTechniquesForPath:
    def test_returns_empty_structure_when_no_mitre_ttps(self) -> None:
        result = get_techniques_for_path({"mitre_ttps": [], "mitre_chain": []}, None)
        assert result["techniques"] == []
        assert result["tactics"] == []
        assert result["apt_groups"] == []

    def test_returns_empty_when_admin_db_is_none(self) -> None:
        path = {"mitre_ttps": ["T1190", "T1078"], "mitre_chain": ["T1190"]}
        result = get_techniques_for_path(path, None)
        assert result["techniques"] == []
        assert result["mitre_chain"] == ["T1190"]

    def test_returns_empty_when_collection_missing(self) -> None:
        class FakeDB:
            def has_collection(self, name: str) -> bool:  # noqa: ARG002
                return False

        path = {"mitre_ttps": ["T1190"], "mitre_chain": []}
        result = get_techniques_for_path(path, FakeDB())
        assert result["techniques"] == []

    def test_preserves_mitre_chain_in_output(self) -> None:
        path = {"mitre_ttps": [], "mitre_chain": ["T1190", "T1537"]}
        result = get_techniques_for_path(path, None)
        assert result["mitre_chain"] == ["T1190", "T1537"]

    def test_missing_fields_are_treated_as_empty(self) -> None:
        result = get_techniques_for_path({}, None)
        assert result["techniques"] == []
        assert result["mitre_chain"] == []
