"""Unit tests for graph exposure and privilege escalation services (no ArangoDB required)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.graph.exposure import compute_exposed_internet, get_exposure_summary
from app.services.graph.privilege_escalation import (
    _DANGEROUS_PERMISSION_PATTERNS,
    ESCALATION_PATTERNS,
    detect_all_escalation_paths,
    detect_dangerous_permission_patterns,
    detect_direct_assume_to_admin,
    detect_passrole_ec2,
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


@pytest.mark.unit
class TestDetectDirectAssumeToAdmin:
    def test_returns_empty_when_no_escalations(self) -> None:
        db = MagicMock()
        db.aql.execute.return_value = iter([])
        assert detect_direct_assume_to_admin(db, "tenant1") == []

    def test_returns_escalation_path_when_found(self) -> None:
        escalation = {
            "identity_id": "identities/user1",
            "identity_name": "developer",
            "target_id": "identities/role_admin",
            "target_name": "AdminRole",
            "hops": 1,
            "pattern": "PRIVESC-01",
            "path_vertex_ids": ["identities/user1", "identities/role_admin"],
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([escalation])
        result = detect_direct_assume_to_admin(db, "tenant1")
        assert len(result) == 1
        assert result[0]["pattern"] == "PRIVESC-01"

    def test_db_error_returns_empty_list(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = Exception("AQL error")
        assert detect_direct_assume_to_admin(db, "tenant1") == []


@pytest.mark.unit
class TestDetectDangerousPermissionPatterns:
    def test_returns_empty_when_no_dangerous_perms(self) -> None:
        db = MagicMock()
        db.aql.execute.return_value = iter([])
        assert detect_dangerous_permission_patterns(db, "tenant1") == []

    def test_creates_result_for_each_matching_permission(self) -> None:
        identity_row = {
            "identity_id": "identities/role1",
            "name": "DevRole",
            "dangerous_permissions": [
                {"action": "iam:CreatePolicyVersion"},
                {"action": "iam:AttachRolePolicy"},
            ],
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([identity_row])
        result = detect_dangerous_permission_patterns(db, "tenant1")
        patterns_found = {r["pattern"] for r in result}
        assert "PRIVESC-03" in patterns_found
        assert "PRIVESC-05" in patterns_found

    def test_wildcard_permission_matches_all_patterns(self) -> None:
        identity_row = {
            "identity_id": "identities/role1",
            "name": "AdminRole",
            "dangerous_permissions": ["*"],
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([identity_row])
        result = detect_dangerous_permission_patterns(db, "tenant1")
        assert len(result) == len(_DANGEROUS_PERMISSION_PATTERNS)

    def test_string_permissions_handled(self) -> None:
        identity_row = {
            "identity_id": "identities/role1",
            "name": "DevRole",
            "dangerous_permissions": ["iam:createaccesskey"],
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([identity_row])
        result = detect_dangerous_permission_patterns(db, "tenant1")
        assert any(r["pattern"] == "PRIVESC-08" for r in result)

    def test_db_error_returns_empty_list(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = Exception("AQL error")
        assert detect_dangerous_permission_patterns(db, "tenant1") == []


@pytest.mark.unit
class TestDetectPassroleEc2:
    def test_returns_empty_when_no_matches(self) -> None:
        db = MagicMock()
        db.aql.execute.return_value = iter([])
        assert detect_passrole_ec2(db, "tenant1") == []

    def test_returns_privesc10_when_matched(self) -> None:
        db = MagicMock()
        db.aql.execute.return_value = iter([{"identity_id": "identities/role1", "name": "DevWithEC2Role"}])
        result = detect_passrole_ec2(db, "tenant1")
        assert len(result) == 1
        assert result[0]["pattern"] == "PRIVESC-10"
        assert result[0]["via_action"] == "iam:PassRole + ec2:RunInstances"

    def test_db_error_returns_empty_list(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = Exception("AQL error")
        assert detect_passrole_ec2(db, "tenant1") == []


@pytest.mark.unit
class TestDetectAllEscalationPaths:
    def test_combines_results_from_all_detectors(self) -> None:
        privesc01 = {
            "identity_id": "identities/user1",
            "identity_name": "dev",
            "target_id": "identities/admin",
            "target_name": "Admin",
            "hops": 1,
            "pattern": "PRIVESC-01",
            "path_vertex_ids": ["identities/user1", "identities/admin"],
        }
        db = MagicMock()
        db.aql.execute.side_effect = [
            iter([privesc01]),  # detect_direct_assume_to_admin
            iter([]),  # detect_dangerous_permission_patterns
            iter([]),  # detect_passrole_ec2
        ]
        result = detect_all_escalation_paths(db, "tenant1")
        assert len(result) == 1
        assert result[0]["pattern"] == "PRIVESC-01"

    def test_returns_empty_when_no_escalations(self) -> None:
        db = MagicMock()
        db.aql.execute.return_value = iter([])
        assert detect_all_escalation_paths(db, "tenant1") == []


@pytest.mark.unit
class TestComputeExposedInternet:
    def test_returns_counts_for_all_collections(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = [
            iter([1, 1, 1]),  # 3 resources
            iter([1]),  # 1 data_asset
            iter([1, 1]),  # 2 network_endpoints
        ]
        result = compute_exposed_internet(db, "tenant1")
        assert result["resources"] == 3
        assert result["data_assets"] == 1
        assert result["network_endpoints"] == 2

    def test_returns_zero_on_db_error(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = Exception("DB error")
        result = compute_exposed_internet(db, "tenant1")
        assert result["resources"] == 0
        assert result["data_assets"] == 0
        assert result["network_endpoints"] == 0

    def test_empty_results_return_zero_counts(self) -> None:
        db = MagicMock()
        db.aql.execute.return_value = iter([])
        result = compute_exposed_internet(db, "tenant1")
        assert result["resources"] == 0


@pytest.mark.unit
class TestGetExposureSummary:
    def test_returns_summary_with_all_keys(self) -> None:
        summary = {"exposed_resources": 5, "exposed_data_assets": 2, "exposed_endpoints": 3, "total": 10}
        db = MagicMock()
        db.aql.execute.return_value = iter([summary])
        result = get_exposure_summary(db, "tenant1")
        assert result["exposed_resources"] == 5
        assert result["total"] == 10

    def test_returns_zeros_on_empty_result(self) -> None:
        db = MagicMock()
        db.aql.execute.return_value = iter([])
        result = get_exposure_summary(db, "tenant1")
        assert result["total"] == 0

    def test_returns_zeros_on_db_error(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = Exception("AQL timeout")
        result = get_exposure_summary(db, "tenant1")
        assert result["total"] == 0
