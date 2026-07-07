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

    def test_detects_wildcard_iam(self):
        doc = {"granted_actions": ["iam:CreateUser"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        # iam:CreateUser matches the iam:* wildcard
        assert "iam:*" in actions

    def test_detects_wildcard_s3(self):
        doc = {"granted_actions": ["s3:DeleteBucket"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "s3:*" in actions

    def test_wildcard_ec2_matches_ec2_action(self):
        doc = {"granted_actions": ["ec2:RunInstances"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "ec2:*" in actions

    def test_detects_administrator_access_policy(self):
        doc = {"granted_actions": [], "policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert "iam:*" in actions

    def test_detects_power_user_access_policy(self):
        doc = {"granted_actions": [], "policies": ["arn:aws:iam::aws:policy/PowerUserAccess"]}
        result = analyze_dangerous_permissions(doc)
        assert len(result) >= 1

    def test_no_duplicates_when_action_and_wildcard_both_match(self):
        # iam:PassRole matches directly AND the iam:* wildcard — should appear once
        doc = {"granted_actions": ["iam:PassRole", "iam:CreateUser"], "policies": []}
        result = analyze_dangerous_permissions(doc)
        actions = [r["action"] for r in result]
        assert actions.count("iam:*") <= 1
        assert actions.count("iam:PassRole") <= 1

    def test_multiple_dangerous_actions_detected(self):
        doc = {
            "granted_actions": ["iam:PassRole", "iam:CreateAccessKey", "lambda:UpdateFunctionCode"],
            "policies": [],
        }
        result = analyze_dangerous_permissions(doc)
        assert len(result) >= 3

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
