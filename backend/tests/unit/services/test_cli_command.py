"""Unit tests for CLI command generation."""

import pytest

from app.services.cli_command import build_cli_command


@pytest.mark.unit
class TestBuildCliCommand:
    def test_returns_remediation_code_when_present(self):
        """Stored remediation_code takes priority over any generated command."""
        result = build_cli_command(
            provider="aws",
            resource_type="s3_bucket",
            resource_id="my-bucket",
            remediation_code="aws s3api put-bucket-acl --bucket my-bucket --acl private",
        )
        assert result == "aws s3api put-bucket-acl --bucket my-bucket --acl private"

    def test_aws_known_resource_type_returns_template(self):
        result = build_cli_command(
            provider="aws",
            resource_type="s3_bucket",
            resource_id="my-bucket",
        )
        assert result is not None
        assert "aws" in result
        assert "my-bucket" in result

    def test_aws_unknown_resource_type_returns_fallback(self):
        result = build_cli_command(
            provider="aws",
            resource_type="unknown_service",
            resource_id="res-123",
        )
        assert result is not None
        assert "aws" in result

    def test_azure_known_resource_type(self):
        result = build_cli_command(
            provider="azure",
            resource_type="virtual_machine",
            resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
        )
        assert result is not None
        assert "az vm show" in result

    def test_gcp_known_resource_type(self):
        result = build_cli_command(
            provider="gcp",
            resource_type="compute_instance",
            resource_id="my-instance",
        )
        assert result is not None
        assert "gcloud compute instances describe" in result

    def test_k8s_known_resource_type(self):
        result = build_cli_command(
            provider="k8s",
            resource_type="cluster_role",
            resource_id="admin",
        )
        assert result is not None
        assert "kubectl describe clusterrole" in result

    def test_unknown_provider_returns_none(self):
        result = build_cli_command(
            provider="oci",
            resource_type="compute_instance",
            resource_id="ocid1.instance.xxx",
        )
        assert result is None

    def test_arn_resource_id_is_simplified(self):
        """ARNs should be simplified to the last component for CLI commands."""
        result = build_cli_command(
            provider="aws",
            resource_type="ec2_instance",
            resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
        )
        assert result is not None
        assert "arn:aws" not in result
        assert "i-0abc123" in result
