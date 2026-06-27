"""
Unit tests for inventory resource Pydantic models.

No external dependencies — all tests run in-process.
Add real assertions as each model is implemented in app/models/inventory.py.
"""
import pytest

# from pydantic import ValidationError
# from app.models.inventory import ResourceBase, AWSResource, ResourceStatus


@pytest.mark.unit
class TestResourceBaseModel:
    """ResourceBase is the root model for every resource in the graph."""

    def test_resource_requires_tenant_id(self) -> None:
        """tenant_id is mandatory — no orphaned resources allowed."""
        pytest.skip("Implement when ResourceBase is created in app/models/inventory.py")
        # with pytest.raises(ValidationError):
        #     ResourceBase(id="ec2-001", type="EC2Instance")  # missing tenant_id

    def test_status_defaults_to_active(self) -> None:
        """Newly created resources default to status: active."""
        pytest.skip("Implement when ResourceBase is created")
        # resource = ResourceBase(id="ec2-001", type="EC2Instance", tenant_id="t-001")
        # assert resource.status == ResourceStatus.ACTIVE

    def test_deleted_resource_retains_id(self) -> None:
        """Resources are soft-deleted — ID and type are preserved for audit trail."""
        pytest.skip("Implement when ResourceBase is created")

    def test_secret_value_field_not_accepted(self) -> None:
        """
        Resources must not store secret values, only metadata.
        e.g. SecretsManager resource stores name + ARN, never the secret itself.
        """
        pytest.skip("Implement when ResourceBase is created")

    def test_updated_at_auto_set_on_upsert(self) -> None:
        """updated_at must be refreshed automatically on every upsert."""
        pytest.skip("Implement when ResourceBase is created")


@pytest.mark.unit
class TestAWSResourceModel:
    """AWSResource extends ResourceBase with AWS-specific fields."""

    def test_arn_is_required(self) -> None:
        """Every AWS resource must have an ARN."""
        pytest.skip("Implement when AWSResource is created")

    def test_account_id_extracted_from_arn(self) -> None:
        """account_id should be derivable from the ARN without a separate field."""
        pytest.skip("Implement when AWSResource is created")

    def test_region_required_for_regional_resources(self) -> None:
        """EC2, RDS, Lambda etc. require region. IAM and S3 are global."""
        pytest.skip("Implement when AWSResource is created")
