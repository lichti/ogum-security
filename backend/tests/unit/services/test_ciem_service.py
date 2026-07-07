"""Unit tests for ciem_service — static permission analysis."""

import pytest

from app.services.ciem_service import (
    DANGEROUS_PERMISSIONS,
    analyze_dangerous_permissions,
)


@pytest.mark.unit
class TestAnalyzeDangerousPermissions:
    def test_returns_empty_for_safe_identity(self):
        doc = {"granted_actions": ["s3:GetObject", "ec2:DescribeInstances"], "policies": []}
        assert analyze_dangerous_permissions(doc) == []

    def test_detects_iam_passrole(self):
        doc = {"granted_actions": ["iam:PassRole", "s3:GetObject"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "iam:PassRole" in actions

    def test_detects_wildcard_iam_grant(self):
        # iam:* as a granted action is dangerous (unrestricted IAM access)
        doc = {"granted_actions": ["iam:*"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "iam:*" in actions

    def test_detects_wildcard_s3_grant(self):
        # s3:* as a granted action is dangerous
        doc = {"granted_actions": ["s3:*"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "s3:*" in actions

    def test_detects_wildcard_ec2_grant(self):
        # ec2:* as a granted action is dangerous
        doc = {"granted_actions": ["ec2:*"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "ec2:*" in actions

    def test_specific_ec2_action_is_not_flagged(self):
        # ec2:DescribeInstances is read-only and not inherently dangerous
        doc = {"granted_actions": ["ec2:DescribeInstances", "s3:GetObject"], "policies": []}
        assert analyze_dangerous_permissions(doc) == []

    def test_detects_administrator_access_policy(self):
        doc = {"granted_actions": [], "policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "iam:*" in actions

    def test_detects_power_user_access_policy(self):
        doc = {"granted_actions": [], "policies": ["arn:aws:iam::aws:policy/PowerUserAccess"]}
        result = analyze_dangerous_permissions(doc)
        assert len(result) >= 1

    def test_no_duplicates_when_same_action_listed_twice(self):
        # iam:PassRole listed twice should appear only once in results
        doc = {"granted_actions": ["iam:PassRole", "iam:PassRole"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert actions.count("iam:PassRole") == 1

    def test_safe_iam_action_not_flagged(self):
        # iam:CreateUser alone is not in the dangerous list
        doc = {"granted_actions": ["iam:CreateUser"], "policies": []}
        assert analyze_dangerous_permissions(doc) == []

    def test_multiple_dangerous_actions_detected(self):
        doc = {
            "granted_actions": ["iam:PassRole", "iam:CreateAccessKey", "lambda:UpdateFunctionCode"],
            "policies": [],
        }
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "iam:PassRole" in actions
        assert "iam:CreateAccessKey" in actions
        assert "lambda:UpdateFunctionCode" in actions

    def test_handles_missing_fields(self):
        assert analyze_dangerous_permissions({}) == []
        assert analyze_dangerous_permissions({"granted_actions": None, "policies": None}) == []

    def test_exact_dangerous_actions_have_risk_description(self):
        doc = {"granted_actions": ["iam:CreatePolicyVersion"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        assert len(result) == 1
        assert "risk" in result[0]
        assert len(result[0]["risk"]) > 10

    def test_all_dangerous_permissions_constants_have_action_and_risk(self):
        for entry in DANGEROUS_PERMISSIONS:
            assert "action" in entry
            assert "risk" in entry
            assert len(entry["action"]) > 0
            assert len(entry["risk"]) > 10

    def test_sts_assumerole_detected(self):
        doc = {"granted_actions": ["sts:AssumeRole"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "sts:AssumeRole" in actions
