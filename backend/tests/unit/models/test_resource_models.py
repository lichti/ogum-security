"""
Unit tests for inventory resource Pydantic models.
No external dependencies — all tests run in-process.
"""
import pytest
from pydantic import ValidationError

from app.models.inventory import (
    AWSResource,
    DataAsset,
    Identity,
    IdentityType,
    NetworkEndpoint,
    Provider,
    ResourceBase,
    ResourceStatus,
)


@pytest.mark.unit
class TestResourceBaseModel:
    """ResourceBase is the root schema for every resource in the graph."""

    def test_resource_requires_tenant_id(self) -> None:
        with pytest.raises(ValidationError):
            ResourceBase(  # type: ignore[call-arg]
                provider=Provider.AWS,
                resource_type="ec2_instance",
                resource_id="i-001",
                name="web-server",
            )

    def test_status_defaults_to_active(self) -> None:
        resource = ResourceBase(
            tenant_id="t-001",
            provider=Provider.AWS,
            resource_type="ec2_instance",
            resource_id="i-001",
            name="web-server",
        )
        assert resource.status == ResourceStatus.ACTIVE

    def test_deleted_resource_retains_id(self) -> None:
        resource = ResourceBase(
            tenant_id="t-001",
            provider=Provider.AWS,
            resource_type="ec2_instance",
            resource_id="i-001",
            name="web-server",
            status=ResourceStatus.DELETED,
        )
        assert resource.resource_id == "i-001"
        assert resource.status == ResourceStatus.DELETED

    def test_secret_value_not_accepted_in_raw_metadata_by_convention(self) -> None:
        """raw_metadata stores descriptive metadata only — never secret values.
        Validated by convention: keys must not suggest stored credentials."""
        resource = ResourceBase(
            tenant_id="t-001",
            provider=Provider.AWS,
            resource_type="secretsmanager_secret",
            resource_id="prod-db-password",
            name="prod-db-password",
            raw_metadata={"arn": "arn:aws:secretsmanager:us-east-1:111:secret:prod"},
        )
        assert "value" not in resource.raw_metadata
        assert "secret_value" not in resource.raw_metadata

    def test_arango_key_format(self) -> None:
        resource = ResourceBase(
            tenant_id="t-001",
            provider=Provider.AWS,
            resource_type="ec2_instance",
            resource_id="i-0abc123",
            name="web-server",
        )
        assert resource.arango_key() == "aws_ec2_instance_i-0abc123"

    def test_arango_key_sanitizes_slashes(self) -> None:
        resource = ResourceBase(
            tenant_id="t-001",
            provider=Provider.GCP,
            resource_type="compute_instance",
            resource_id="projects/my-project/zones/us-central1-a/instances/vm-001",
            name="vm-001",
        )
        key = resource.arango_key()
        assert "/" not in key

    def test_to_arango_doc_includes_key(self) -> None:
        resource = ResourceBase(
            tenant_id="t-001",
            provider=Provider.AWS,
            resource_type="ec2_instance",
            resource_id="i-0abc123",
            name="web-server",
        )
        doc = resource.to_arango_doc()
        assert doc["_key"] == resource.arango_key()
        assert doc["tenant_id"] == "t-001"

    def test_to_arango_update_excludes_immutable_fields(self) -> None:
        resource = ResourceBase(
            tenant_id="t-001",
            provider=Provider.AWS,
            resource_type="ec2_instance",
            resource_id="i-0abc123",
            name="web-server",
        )
        update = resource.to_arango_update()
        assert "tenant_id" not in update
        assert "resource_id" not in update
        assert "provider" not in update
        assert "updated_at" in update


@pytest.mark.unit
class TestAWSResourceModel:
    """AWSResource extends ResourceBase with AWS-specific fields."""

    def test_arn_is_required(self) -> None:
        with pytest.raises(ValidationError):
            AWSResource(  # type: ignore[call-arg]
                tenant_id="t-001",
                resource_type="ec2_instance",
                resource_id="i-001",
                name="web-server",
            )

    def test_account_id_extracted_from_arn(self) -> None:
        resource = AWSResource(
            tenant_id="t-001",
            resource_type="ec2_instance",
            resource_id="i-0abc123",
            name="web-server",
            arn="arn:aws:ec2:us-east-1:111111111111:instance/i-0abc123",
            region="us-east-1",
        )
        assert resource.account_id == "111111111111"

    def test_explicit_account_id_not_overwritten(self) -> None:
        resource = AWSResource(
            tenant_id="t-001",
            resource_type="ec2_instance",
            resource_id="i-0abc123",
            name="web-server",
            arn="arn:aws:ec2:us-east-1:111111111111:instance/i-0abc123",
            account_id="999999999999",
            region="us-east-1",
        )
        assert resource.account_id == "999999999999"

    def test_provider_is_always_aws(self) -> None:
        resource = AWSResource(
            tenant_id="t-001",
            resource_type="ec2_instance",
            resource_id="i-001",
            name="web-server",
            arn="arn:aws:ec2:us-east-1:111:instance/i-001",
        )
        assert resource.provider == Provider.AWS

    def test_global_resource_has_no_region(self) -> None:
        resource = AWSResource(
            tenant_id="t-001",
            resource_type="iam_role",
            resource_id="AdminRole",
            name="AdminRole",
            arn="arn:aws:iam::111111111111:role/AdminRole",
        )
        assert resource.region is None
        assert resource.account_id == "111111111111"


@pytest.mark.unit
class TestIdentityModel:
    """Identity covers IAM roles, users, and service accounts."""

    def test_account_id_extracted_from_arn(self) -> None:
        identity = Identity(
            tenant_id="t-001",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_ROLE,
            name="AdminRole",
            arn="arn:aws:iam::111111111111:role/AdminRole",
        )
        assert identity.account_id == "111111111111"

    def test_arango_key_for_role(self) -> None:
        identity = Identity(
            tenant_id="t-001",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_ROLE,
            name="WebServerRole",
            arn="arn:aws:iam::111:role/WebServerRole",
        )
        assert identity.arango_key() == "aws_role_WebServerRole"

    def test_arango_key_for_user(self) -> None:
        identity = Identity(
            tenant_id="t-001",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_USER,
            name="alice",
            arn="arn:aws:iam::111:user/alice",
        )
        assert identity.arango_key() == "aws_user_alice"

    def test_privilege_gap_score_defaults_to_zero(self) -> None:
        identity = Identity(
            tenant_id="t-001",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_ROLE,
            name="ReadOnlyRole",
            arn="arn:aws:iam::111:role/ReadOnlyRole",
        )
        assert identity.privilege_gap_score == 0


@pytest.mark.unit
class TestNetworkEndpointModel:
    """NetworkEndpoint covers security group rules, open ports, and gateways."""

    def test_arango_key_with_port(self) -> None:
        ep = NetworkEndpoint(
            tenant_id="t-001",
            provider=Provider.AWS,
            endpoint_type="security_group_rule",
            resource_id="sg-0abc123",
            port=22,
            protocol="tcp",
            cidr="0.0.0.0/0",
            is_public=True,
        )
        assert ep.arango_key() == "aws_security_group_rule_sg-0abc123_22"

    def test_arango_key_without_port(self) -> None:
        ep = NetworkEndpoint(
            tenant_id="t-001",
            provider=Provider.AWS,
            endpoint_type="internet_gateway",
            resource_id="igw-0abc123",
        )
        assert ep.arango_key() == "aws_internet_gateway_igw-0abc123"


@pytest.mark.unit
class TestDataAssetModel:
    """DataAsset covers S3 buckets, RDS instances, and other data stores."""

    def test_arango_key_format(self) -> None:
        asset = DataAsset(
            tenant_id="t-001",
            provider=Provider.AWS,
            asset_type="s3_bucket",
            name="prod-billing-records",
            arn="arn:aws:s3:::prod-billing-records",
        )
        assert asset.arango_key() == "aws_s3_bucket_prod-billing-records"

    def test_pii_and_pci_default_false(self) -> None:
        asset = DataAsset(
            tenant_id="t-001",
            provider=Provider.AWS,
            asset_type="s3_bucket",
            name="logs-bucket",
            arn="arn:aws:s3:::logs-bucket",
        )
        assert not asset.contains_pii
        assert not asset.contains_pci

    def test_account_id_not_extracted_from_s3_arn(self) -> None:
        """S3 ARNs do not contain an account ID — account_id should remain None."""
        asset = DataAsset(
            tenant_id="t-001",
            provider=Provider.AWS,
            asset_type="s3_bucket",
            name="my-bucket",
            arn="arn:aws:s3:::my-bucket",
        )
        assert asset.account_id is None
