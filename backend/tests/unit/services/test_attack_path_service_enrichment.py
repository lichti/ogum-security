"""
Unit tests for attack_path_service.build_attack_path_docs' new US-14.13 fields
(exposure, is_cross_account, is_cross_cloud_provider, account_ids).

Uses a MagicMock db instead of the graph fixture — the fixture seed doesn't
set account_id on any vertex, so cross-account/cross-cloud scenarios need
explicit control over what db.document() returns per vertex id.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.attack_path_service import build_attack_path_docs

_RAW_PATH = {
    "entry_point_id": "resources/ep-1",
    "entry_point_type": "aws_ec2_instance",
    "entry_point_name": "ec2-public",
    "target_id": "data_assets/tgt-1",
    "target_type": "aws_s3_bucket",
    "target_name": "s3-bucket",
    "hops": 2,
    "path_vertex_ids": ["resources/ep-1", "data_assets/tgt-1"],
    "rule": "internet_to_data",
}


def _mock_db(vertex_docs: dict[str, dict]) -> MagicMock:
    db = MagicMock()
    db.document.side_effect = lambda vid: vertex_docs.get(vid, {})
    return db


@pytest.mark.unit
class TestBuildAttackPathDocsEnrichment:
    def test_same_account_is_not_cross_account(self) -> None:
        db = _mock_db(
            {
                "resources/ep-1": {"account_id": "111111111111", "provider": "aws"},
                "data_assets/tgt-1": {"account_id": "111111111111", "provider": "aws"},
            }
        )
        docs = build_attack_path_docs(db, "tenant-1", [_RAW_PATH])
        assert docs[0]["is_cross_account"] is False
        assert docs[0]["account_ids"] == ["111111111111"]

    def test_different_accounts_is_cross_account(self) -> None:
        db = _mock_db(
            {
                "resources/ep-1": {"account_id": "111111111111", "provider": "aws"},
                "data_assets/tgt-1": {"account_id": "222222222222", "provider": "aws"},
            }
        )
        docs = build_attack_path_docs(db, "tenant-1", [_RAW_PATH])
        assert docs[0]["is_cross_account"] is True
        assert docs[0]["account_ids"] == ["111111111111", "222222222222"]

    def test_same_provider_is_not_cross_cloud(self) -> None:
        db = _mock_db(
            {
                "resources/ep-1": {"provider": "aws"},
                "data_assets/tgt-1": {"provider": "aws"},
            }
        )
        docs = build_attack_path_docs(db, "tenant-1", [_RAW_PATH])
        assert docs[0]["is_cross_cloud_provider"] is False

    def test_different_providers_is_cross_cloud(self) -> None:
        db = _mock_db(
            {
                "resources/ep-1": {"provider": "aws"},
                "data_assets/tgt-1": {"provider": "azure"},
            }
        )
        docs = build_attack_path_docs(db, "tenant-1", [_RAW_PATH])
        assert docs[0]["is_cross_cloud_provider"] is True

    def test_missing_account_id_excluded_from_account_ids(self) -> None:
        db = _mock_db({"resources/ep-1": {}, "data_assets/tgt-1": {}})
        docs = build_attack_path_docs(db, "tenant-1", [_RAW_PATH])
        assert docs[0]["account_ids"] == []
        assert docs[0]["is_cross_account"] is False

    def test_exposure_internet_facing_from_entry_point(self) -> None:
        db = _mock_db({"resources/ep-1": {"exposed_internet": True}, "data_assets/tgt-1": {}})
        docs = build_attack_path_docs(db, "tenant-1", [_RAW_PATH])
        assert docs[0]["exposure"] == "internet_facing"

    def test_exposure_trusted_access_for_privilege_escalation(self) -> None:
        db = _mock_db({"resources/ep-1": {}, "data_assets/tgt-1": {}})
        raw = {**_RAW_PATH, "rule": "privilege_escalation"}
        docs = build_attack_path_docs(db, "tenant-1", [raw])
        assert docs[0]["exposure"] == "trusted_access"

    def test_exposure_none_when_no_signal(self) -> None:
        db = _mock_db({"resources/ep-1": {}, "data_assets/tgt-1": {}})
        docs = build_attack_path_docs(db, "tenant-1", [_RAW_PATH])
        assert docs[0]["exposure"] == "none"
