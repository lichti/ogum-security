"""Unit tests for IAM edge builder (no ArangoDB required)."""

import pytest

from app.services.graph.iam_edges import _extract_principal_arns


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
