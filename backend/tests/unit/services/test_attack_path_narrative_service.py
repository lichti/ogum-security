"""Unit tests for attack_path_narrative_service.py (no ArangoDB required)."""

from __future__ import annotations

import pytest

from app.services.attack_path_narrative_service import build_path_narrative

_BASE_PATH_DOC = {
    "path_id": "path-001",
    "entry_point_name": "ec2-public-01",
    "entry_point_type": "aws_ec2_instance",
    "target_name": "s3-creds-bucket",
    "target_type": "aws_s3_bucket",
    "rule": "internet_to_data",
    "hops": 2,
    "exposure": "internet_facing",
    "is_cross_account": False,
    "is_cross_cloud_provider": False,
    "account_ids": ["111111111111"],
    "mitre_chain": [],
    "is_toxic_combination": False,
    "target_crown_jewel_reason": None,
}


@pytest.mark.unit
class TestBuildPathNarrative:
    def test_always_returns_four_steps_in_order(self) -> None:
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=[])
        assert [s.index for s in narrative.steps] == [1, 2, 3, 4]
        assert all(s.total == 4 for s in narrative.steps)
        assert [s.title for s in narrative.steps] == [
            "Entry Point",
            "Path & Pivot",
            "Target & Impact",
            "Findings & Evidence",
        ]

    def test_generated_by_is_always_template(self) -> None:
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=[])
        assert narrative.generated_by == "template"

    def test_path_id_carried_through(self) -> None:
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=[])
        assert narrative.path_id == "path-001"

    def test_entry_point_step_mentions_exposure(self) -> None:
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=[])
        assert "public internet" in narrative.steps[0].text

    def test_entry_point_step_reflects_trusted_access(self) -> None:
        doc = {**_BASE_PATH_DOC, "exposure": "trusted_access"}
        narrative = build_path_narrative(doc, findings=[])
        assert "trusted" in narrative.steps[0].text

    def test_path_pivot_step_mentions_cross_account(self) -> None:
        doc = {**_BASE_PATH_DOC, "is_cross_account": True, "account_ids": ["111", "222"]}
        narrative = build_path_narrative(doc, findings=[])
        assert "2 distinct cloud accounts" in narrative.steps[1].text

    def test_path_pivot_step_omits_cross_account_when_false(self) -> None:
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=[])
        assert "cloud accounts" not in narrative.steps[1].text

    def test_path_pivot_step_mentions_cross_cloud_provider(self) -> None:
        doc = {**_BASE_PATH_DOC, "is_cross_cloud_provider": True}
        narrative = build_path_narrative(doc, findings=[])
        assert "more than one cloud provider" in narrative.steps[1].text

    def test_target_impact_step_mentions_crown_jewel_reason(self) -> None:
        doc = {**_BASE_PATH_DOC, "target_crown_jewel_reason": "stores_sensitive_data"}
        narrative = build_path_narrative(doc, findings=[])
        assert "crown jewel" in narrative.steps[2].text
        assert "stores sensitive data" in narrative.steps[2].text

    def test_target_impact_step_mentions_toxic_combination(self) -> None:
        doc = {**_BASE_PATH_DOC, "is_toxic_combination": True}
        narrative = build_path_narrative(doc, findings=[])
        assert "toxic combination" in narrative.steps[2].text

    def test_findings_step_no_findings(self) -> None:
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=[])
        assert "No open findings" in narrative.steps[3].text

    def test_findings_step_counts_by_severity(self) -> None:
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
        ]
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=findings)
        text = narrative.steps[3].text
        assert "3 open findings" in text
        assert "2 critical" in text
        assert "1 high" in text

    def test_findings_step_singular_wording(self) -> None:
        narrative = build_path_narrative(_BASE_PATH_DOC, findings=[{"severity": "LOW"}])
        assert "1 open finding support this path (" in narrative.steps[3].text
