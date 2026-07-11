"""Unit tests for the decoupled resource edge builder (no ArangoDB required).

Mirrors test_iam_edges.py's approach: mock db.aql.execute/db.collection and
assert on edge-type counts, using field shapes that match what
prowler_inventory.py actually persists (raw_metadata carries security_groups,
subnet_id, iam_instance_profile, execution_role_arn, member_arns, vpc_id).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.graph.resource_edges import (
    _edge_key,
    _raw_aws_id,
    _role_name,
    build_resource_edges,
)


def _make_db(resources: list[dict], identities: list[dict]) -> MagicMock:
    db = MagicMock()
    db.aql.execute.side_effect = [iter(resources), iter(identities)]
    db.collection.return_value = MagicMock()
    return db


@pytest.mark.unit
class TestRawAwsId:
    def test_extracts_trailing_id(self) -> None:
        assert _raw_aws_id("arn:aws:ec2:us-east-1:123:vpc/vpc-0123") == "vpc-0123"

    def test_none_without_slash(self) -> None:
        assert _raw_aws_id("not-an-arn") is None

    def test_none_for_empty(self) -> None:
        assert _raw_aws_id(None) is None
        assert _raw_aws_id("") is None


@pytest.mark.unit
class TestRoleName:
    def test_strips_path(self) -> None:
        assert _role_name("arn:aws:iam::123:role/MyRole") == "MyRole"

    def test_strips_trailing_slash(self) -> None:
        assert _role_name("arn:aws:iam::123:instance-profile/MyProfile/") == "MyProfile"


@pytest.mark.unit
class TestEdgeKey:
    def test_deterministic(self) -> None:
        assert _edge_key("a", "b", "BELONGS_TO") == _edge_key("a", "b", "BELONGS_TO")

    def test_different_types_differ(self) -> None:
        assert _edge_key("a", "b", "BELONGS_TO") != _edge_key("a", "b", "ATTACHED_TO")


@pytest.mark.unit
class TestBuildResourceEdges:
    def test_no_resources_returns_zero_counts(self) -> None:
        db = _make_db([], [])
        result = build_resource_edges(db, "tenant1")
        assert result == {"BELONGS_TO": 0, "ATTACHED_TO": 0, "ASSUMES_ROLE": 0, "MEMBER_OF": 0}

    def test_ec2_belongs_to_vpc_via_subnet(self) -> None:
        vpc = {
            "_id": "resources/vpc1",
            "arn": "arn:aws:ec2:us-east-1:123:vpc/vpc-abc",
            "resource_type": "ec2_vpc",
            "raw_metadata": {},
        }
        subnet = {
            "_id": "resources/subnet1",
            "arn": "arn:aws:ec2:us-east-1:123:subnet/subnet-abc",
            "resource_type": "ec2_subnet",
            "raw_metadata": {"vpc_id": "vpc-abc"},
        }
        ec2 = {
            "_id": "resources/ec2-1",
            "arn": "arn:aws:ec2:us-east-1:123:instance/i-abc",
            "resource_type": "ec2_instance",
            "raw_metadata": {"subnet_id": "subnet-abc"},
        }
        db = _make_db([vpc, subnet, ec2], [])
        result = build_resource_edges(db, "tenant1")
        assert result["BELONGS_TO"] == 1

    def test_ec2_attached_to_security_group(self) -> None:
        sg = {
            "_id": "resources/sg1",
            "arn": "arn:aws:ec2:us-east-1:123:security-group/sg-abc",
            "resource_type": "ec2_security_group",
            "raw_metadata": {},
        }
        ec2 = {
            "_id": "resources/ec2-1",
            "arn": "arn:aws:ec2:us-east-1:123:instance/i-abc",
            "resource_type": "ec2_instance",
            "raw_metadata": {"security_groups": ["sg-abc"]},
        }
        db = _make_db([sg, ec2], [])
        result = build_resource_edges(db, "tenant1")
        assert result["ATTACHED_TO"] == 1

    def test_ec2_assumes_role_via_instance_profile_name_match(self) -> None:
        ec2 = {
            "_id": "resources/ec2-1",
            "arn": "arn:aws:ec2:us-east-1:123:instance/i-abc",
            "resource_type": "ec2_instance",
            "raw_metadata": {"iam_instance_profile": "arn:aws:iam::123:instance-profile/AppRole"},
        }
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/AppRole",
            "identity_type": "iam_role",
        }
        db = _make_db([ec2], [role])
        result = build_resource_edges(db, "tenant1")
        assert result["ASSUMES_ROLE"] == 1

    def test_ec2_instance_profile_name_mismatch_skipped(self) -> None:
        ec2 = {
            "_id": "resources/ec2-1",
            "arn": "arn:aws:ec2:us-east-1:123:instance/i-abc",
            "resource_type": "ec2_instance",
            "raw_metadata": {"iam_instance_profile": "arn:aws:iam::123:instance-profile/SomeProfile"},
        }
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/UnrelatedRole",
            "identity_type": "iam_role",
        }
        db = _make_db([ec2], [role])
        result = build_resource_edges(db, "tenant1")
        assert result["ASSUMES_ROLE"] == 0

    def test_lambda_assumes_execution_role(self) -> None:
        lam = {
            "_id": "resources/lambda1",
            "arn": "arn:aws:lambda:us-east-1:123:function:my-fn",
            "resource_type": "lambda_function",
            "raw_metadata": {"execution_role_arn": "arn:aws:iam::123:role/lambda-exec"},
        }
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/lambda-exec",
            "identity_type": "iam_role",
        }
        db = _make_db([lam], [role])
        result = build_resource_edges(db, "tenant1")
        assert result["ASSUMES_ROLE"] == 1

    def test_lambda_without_execution_role_skipped(self) -> None:
        lam = {
            "_id": "resources/lambda1",
            "arn": "arn:aws:lambda:us-east-1:123:function:my-fn",
            "resource_type": "lambda_function",
            "raw_metadata": {},
        }
        db = _make_db([lam], [])
        result = build_resource_edges(db, "tenant1")
        assert result["ASSUMES_ROLE"] == 0

    def test_member_of_group(self) -> None:
        group = {
            "_id": "identities/group1",
            "arn": "arn:aws:iam::123:group/Devs",
            "identity_type": "iam_group",
            "raw_metadata": {"member_arns": ["arn:aws:iam::123:user/alice"]},
        }
        user = {
            "_id": "identities/user1",
            "arn": "arn:aws:iam::123:user/alice",
            "identity_type": "iam_user",
        }
        db = _make_db([], [group, user])
        result = build_resource_edges(db, "tenant1")
        assert result["MEMBER_OF"] == 1

    def test_member_of_unmatched_arn_skipped(self) -> None:
        group = {
            "_id": "identities/group1",
            "arn": "arn:aws:iam::123:group/Devs",
            "identity_type": "iam_group",
            "raw_metadata": {"member_arns": ["arn:aws:iam::123:user/ghost"]},
        }
        db = _make_db([], [group])
        result = build_resource_edges(db, "tenant1")
        assert result["MEMBER_OF"] == 0

    def test_db_error_returns_zero_counts(self) -> None:
        db = MagicMock()
        db.aql.execute.side_effect = Exception("DB unavailable")
        result = build_resource_edges(db, "tenant1")
        assert result == {"BELONGS_TO": 0, "ATTACHED_TO": 0, "ASSUMES_ROLE": 0, "MEMBER_OF": 0}

    def test_insert_failure_logged_not_raised(self) -> None:
        sg = {
            "_id": "resources/sg1",
            "arn": "arn:aws:ec2:us-east-1:123:security-group/sg-abc",
            "resource_type": "ec2_security_group",
            "raw_metadata": {},
        }
        ec2 = {
            "_id": "resources/ec2-1",
            "arn": "arn:aws:ec2:us-east-1:123:instance/i-abc",
            "resource_type": "ec2_instance",
            "raw_metadata": {"security_groups": ["sg-abc"]},
        }
        db = MagicMock()
        db.aql.execute.side_effect = [iter([sg, ec2]), iter([])]
        mock_col = MagicMock()
        mock_col.insert.side_effect = Exception("duplicate key")
        db.collection.return_value = mock_col

        result = build_resource_edges(db, "tenant1")
        assert result["ATTACHED_TO"] == 0

    def test_full_scenario_all_edge_types(self) -> None:
        vpc = {
            "_id": "resources/vpc1",
            "arn": "arn:aws:ec2:us-east-1:123:vpc/vpc-abc",
            "resource_type": "ec2_vpc",
            "raw_metadata": {},
        }
        subnet = {
            "_id": "resources/subnet1",
            "arn": "arn:aws:ec2:us-east-1:123:subnet/subnet-abc",
            "resource_type": "ec2_subnet",
            "raw_metadata": {"vpc_id": "vpc-abc"},
        }
        sg = {
            "_id": "resources/sg1",
            "arn": "arn:aws:ec2:us-east-1:123:security-group/sg-abc",
            "resource_type": "ec2_security_group",
            "raw_metadata": {},
        }
        ec2 = {
            "_id": "resources/ec2-1",
            "arn": "arn:aws:ec2:us-east-1:123:instance/i-abc",
            "resource_type": "ec2_instance",
            "raw_metadata": {
                "subnet_id": "subnet-abc",
                "security_groups": ["sg-abc"],
                "iam_instance_profile": "arn:aws:iam::123:instance-profile/AppRole",
            },
        }
        lam = {
            "_id": "resources/lambda1",
            "arn": "arn:aws:lambda:us-east-1:123:function:my-fn",
            "resource_type": "lambda_function",
            "raw_metadata": {"execution_role_arn": "arn:aws:iam::123:role/lambda-exec"},
        }
        role = {
            "_id": "identities/role1",
            "arn": "arn:aws:iam::123:role/AppRole",
            "identity_type": "iam_role",
        }
        lambda_role = {
            "_id": "identities/role2",
            "arn": "arn:aws:iam::123:role/lambda-exec",
            "identity_type": "iam_role",
        }
        group = {
            "_id": "identities/group1",
            "arn": "arn:aws:iam::123:group/Devs",
            "identity_type": "iam_group",
            "raw_metadata": {"member_arns": ["arn:aws:iam::123:user/alice"]},
        }
        user = {
            "_id": "identities/user1",
            "arn": "arn:aws:iam::123:user/alice",
            "identity_type": "iam_user",
        }
        db = _make_db(
            [vpc, subnet, sg, ec2, lam],
            [role, lambda_role, group, user],
        )
        result = build_resource_edges(db, "tenant1")
        assert result == {"BELONGS_TO": 1, "ATTACHED_TO": 1, "ASSUMES_ROLE": 2, "MEMBER_OF": 1}
