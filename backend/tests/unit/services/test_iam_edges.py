"""Unit tests for IAM edge builder (no ArangoDB required)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.graph.iam_edges import (
    _edge_key,
    _extract_principal_arns,
    build_iam_edges,
)


@pytest.mark.unit
class TestExtractPrincipalArns:
    def test_simple_allow_assumerole(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert arns == ["arn:aws:iam::123456789012:root"]

    def test_multiple_principals(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::111111111111:role/DevRole",
                            "arn:aws:iam::222222222222:role/ProdRole",
                        ]
                    },
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert len(arns) == 2
        assert "arn:aws:iam::111111111111:role/DevRole" in arns

    def test_wildcard_action(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/AdminRole"},
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert arns == ["arn:aws:iam::123456789012:role/AdminRole"]

    def test_deny_statement_excluded(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert arns == []

    def test_non_assumerole_action_excluded(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert arns == []

    def test_service_principal(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert arns == ["ec2.amazonaws.com"]

    def test_empty_policy(self) -> None:
        assert _extract_principal_arns({}) == []
        assert _extract_principal_arns(None) == []  # type: ignore[arg-type]
        assert _extract_principal_arns("not-a-dict") == []  # type: ignore[arg-type]

    def test_list_of_actions(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                    "Principal": {"AWS": "arn:aws:iam::123456789012:role/CI"},
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert arns == ["arn:aws:iam::123456789012:role/CI"]

    def test_string_principal(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": "*",
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert arns == ["*"]

    def test_list_principal(self) -> None:
        trust_policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": ["arn:aws:iam::111:role/A", "arn:aws:iam::222:role/B"],
                }
            ]
        }
        arns = _extract_principal_arns(trust_policy)
        assert len(arns) == 2


@pytest.mark.unit
class TestEdgeKey:
    def test_deterministic(self) -> None:
        k1 = _edge_key("identities/a", "identities/b", "STS_ASSUMEROLE_ALLOW")
        k2 = _edge_key("identities/a", "identities/b", "STS_ASSUMEROLE_ALLOW")
        assert k1 == k2

    def test_different_types_produce_different_keys(self) -> None:
        k1 = _edge_key("identities/a", "identities/b", "STS_ASSUMEROLE_ALLOW")
        k2 = _edge_key("identities/a", "identities/b", "ASSUMES")
        assert k1 != k2

    def test_key_is_32_chars(self) -> None:
        k = _edge_key("a", "b", "c")
        assert len(k) == 32


@pytest.mark.unit
class TestBuildIamEdges:
    def _make_db(self, identities: list[dict]) -> MagicMock:
        db = MagicMock()
        db.aql.execute.return_value = iter(identities)
        db.collection.return_value = MagicMock()
        return db

    def test_no_identities_returns_zero_counts(self) -> None:
        db = self._make_db([])
        result = build_iam_edges(db, "tenant1")
        assert result == {"STS_ASSUMEROLE_ALLOW": 0, "ASSUMES": 0, "ATTACHED_POLICY": 0}

    def test_identity_with_trust_policy_creates_sts_edge(self) -> None:
        role_identity = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/TargetRole",
            "tenant_id": "tenant1",
            "trust_policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Principal": {"AWS": "arn:aws:iam::123:user/developer"},
                    }
                ]
            },
        }
        user_identity = {
            "_id": "identities/user1",
            "arn": "arn:aws:iam::123:user/developer",
            "tenant_id": "tenant1",
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([role_identity, user_identity])
        mock_col = MagicMock()
        db.collection.return_value = mock_col

        result = build_iam_edges(db, "tenant1")

        assert result["STS_ASSUMEROLE_ALLOW"] == 1
        mock_col.insert.assert_called()

    def test_identity_with_assumed_role_arn_creates_assumes_edge(self) -> None:
        user = {
            "_id": "identities/user1",
            "arn": "arn:aws:iam::123:user/dev",
            "tenant_id": "tenant1",
            "assumed_role_arn": "arn:aws:iam::123:role/AdminRole",
        }
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/AdminRole",
            "tenant_id": "tenant1",
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([user, role])
        mock_col = MagicMock()
        db.collection.return_value = mock_col

        result = build_iam_edges(db, "tenant1")

        assert result["ASSUMES"] == 1

    def test_identity_with_policies_creates_attached_policy_edges(self) -> None:
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/DevRole",
            "tenant_id": "tenant1",
            "policies": [
                "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "arn:aws:iam::123:policy/CustomPolicy",
            ],
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([role])
        mock_col = MagicMock()
        db.collection.return_value = mock_col

        result = build_iam_edges(db, "tenant1")

        assert result["ATTACHED_POLICY"] == 2

    def test_policies_as_string_single_policy(self) -> None:
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/DevRole",
            "tenant_id": "tenant1",
            "policies": "arn:aws:iam::aws:policy/AdministratorAccess",
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([role])
        db.collection.return_value = MagicMock()

        result = build_iam_edges(db, "tenant1")

        assert result["ATTACHED_POLICY"] == 1

    def test_identity_assuming_itself_skipped(self) -> None:
        """An identity referencing its own ARN in trust policy should not create a self-loop."""
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/SelfRef",
            "tenant_id": "tenant1",
            "trust_policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Principal": {"AWS": "arn:aws:iam::123:role/SelfRef"},
                    }
                ]
            },
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([role])
        mock_col = MagicMock()
        db.collection.return_value = mock_col

        result = build_iam_edges(db, "tenant1")

        assert result["STS_ASSUMEROLE_ALLOW"] == 0

    def test_db_error_returns_zero_counts(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = Exception("DB unavailable")

        result = build_iam_edges(db, "tenant1")

        assert result == {"STS_ASSUMEROLE_ALLOW": 0, "ASSUMES": 0, "ATTACHED_POLICY": 0}

    def test_insert_failure_logged_not_raised(self) -> None:
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/AdminRole",
            "tenant_id": "tenant1",
            "policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
        }
        db = MagicMock()
        db.aql.execute.return_value = iter([role])
        mock_col = MagicMock()
        mock_col.insert.side_effect = Exception("duplicate key")
        db.collection.return_value = mock_col

        # Should not raise — duplicate inserts are logged and skipped
        result = build_iam_edges(db, "tenant1")
        assert result["ATTACHED_POLICY"] == 0
