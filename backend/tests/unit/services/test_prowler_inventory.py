"""Unit tests for prowler_inventory — post-scan resource extraction."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.services.prowler_inventory import (
    _collection_for,
    _extract_tags,
    _is_public,
    _normalize_type_name,
    _to_jsonable,
    extract_inventory_from_findings,
    resource_arango_key,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    resource_uid: str = "arn:aws:ec2:us-east-1:123:instance/i-abc",
    resource_name: str = "web-server",
    resource_type: str = "AwsEc2Instance",
    service: str = "ec2",
    region: str = "us-east-1",
    account_uid: str = "123456789012",
    metadata: dict[str, Any] | None = None,
    status: str = "FAIL",
) -> Any:
    check_meta = SimpleNamespace(
        ResourceType=resource_type,
        ServiceName=service,
        CheckID="ec2_instance_imdsv2_enabled",
        CheckTitle="EC2 IMDSv2 enabled",
        Severity="high",
        Description="...",
    )
    return SimpleNamespace(
        resource_uid=resource_uid,
        resource_name=resource_name,
        region=region,
        account_uid=account_uid,
        metadata=check_meta,
        resource_metadata=metadata or {},
        status=status,
    )


# ---------------------------------------------------------------------------
# _normalize_type_name
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNormalizeTypeName:
    def test_aws_instance(self):
        assert _normalize_type_name("AwsEc2Instance", "aws") == "ec2_instance"

    def test_aws_iam_role(self):
        assert _normalize_type_name("AwsIamRole", "aws") == "iam_role"

    def test_aws_s3_bucket(self):
        assert _normalize_type_name("AwsS3Bucket", "aws") == "s3_bucket"

    def test_aws_eks_cluster(self):
        assert _normalize_type_name("AwsEksCluster", "aws") == "eks_cluster"

    def test_azure_vm(self):
        result = _normalize_type_name("microsoft.compute/virtualmachines", "azure")
        assert result.startswith("azure_")
        assert "virtualmachines" in result

    def test_gcp_compute_instance(self):
        result = _normalize_type_name("compute.googleapis.com/Instance", "gcp")
        assert result.startswith("gcp_compute_")

    def test_gcp_gke_cluster(self):
        result = _normalize_type_name("container.googleapis.com/Cluster", "gcp")
        assert result.startswith("gcp_container_")

    def test_k8s_pod(self):
        assert _normalize_type_name("Pod", "kubernetes") == "k8s_pod"

    def test_k8s_daemon_set(self):
        assert _normalize_type_name("DaemonSet", "k8s") == "k8s_daemon_set"

    def test_empty_returns_unknown(self):
        assert _normalize_type_name("", "aws") == "unknown"


# ---------------------------------------------------------------------------
# _collection_for
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCollectionFor:
    def test_iam_role_goes_to_identities(self):
        assert _collection_for("AwsIamRole") == "identities"

    def test_iam_user_goes_to_identities(self):
        assert _collection_for("AwsIamUser") == "identities"

    def test_s3_bucket_goes_to_data_assets(self):
        assert _collection_for("AwsS3Bucket") == "data_assets"

    def test_rds_db_instance_goes_to_data_assets(self):
        assert _collection_for("AwsRdsDbInstance") == "data_assets"

    def test_ec2_instance_goes_to_resources(self):
        assert _collection_for("AwsEc2Instance") == "resources"

    def test_eks_cluster_goes_to_resources(self):
        assert _collection_for("AwsEksCluster") == "resources"

    def test_keyvault_goes_to_data_assets(self):
        assert _collection_for("microsoft.keyvault/vaults") == "data_assets"

    def test_azure_vm_goes_to_resources(self):
        assert _collection_for("microsoft.compute/virtualmachines") == "resources"


# ---------------------------------------------------------------------------
# _extract_tags
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExtractTags:
    def test_aws_tag_list(self):
        tags = _extract_tags({"tags": [{"Key": "Env", "Value": "prod"}, {"Key": "Owner", "Value": "team"}]})
        assert tags == {"Env": "prod", "Owner": "team"}

    def test_gcp_labels_dict(self):
        tags = _extract_tags({"labels": {"env": "prod", "app": "web"}})
        assert tags == {"env": "prod", "app": "web"}

    def test_empty_metadata(self):
        assert _extract_tags({}) == {}


# ---------------------------------------------------------------------------
# _is_public
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestIsPublic:
    def test_detects_public_ip(self):
        assert _is_public({"public_ip": "1.2.3.4"}) is True

    def test_detects_public_ip_address(self):
        assert _is_public({"PublicIpAddress": "1.2.3.4"}) is True

    def test_false_when_no_public_fields(self):
        assert _is_public({"private_ip": "10.0.0.1"}) is False

    def test_false_when_empty(self):
        assert _is_public({}) is False


# ---------------------------------------------------------------------------
# resource_arango_key
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_arango_key_is_deterministic():
    k1 = resource_arango_key("arn:aws:ec2:us-east-1:123:instance/i-abc", "tenant-1")
    k2 = resource_arango_key("arn:aws:ec2:us-east-1:123:instance/i-abc", "tenant-1")
    assert k1 == k2


@pytest.mark.unit
def test_arango_key_differs_by_tenant():
    k1 = resource_arango_key("arn:aws:ec2:us-east-1:123:instance/i-abc", "tenant-1")
    k2 = resource_arango_key("arn:aws:ec2:us-east-1:123:instance/i-abc", "tenant-2")
    assert k1 != k2


@pytest.mark.unit
def test_arango_key_is_hex_64_chars():
    k = resource_arango_key("some-resource", "tenant-1")
    assert len(k) == 64
    assert all(c in "0123456789abcdef" for c in k)


# ---------------------------------------------------------------------------
# extract_inventory_from_findings — AWS
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExtractInventoryAws:
    def test_single_ec2_instance_goes_to_resources(self):
        findings = [_make_finding()]
        inv = extract_inventory_from_findings(findings, "t1", "aws", "123")
        assert len(inv["resources"]) == 1
        assert inv["identities"] == []
        assert inv["data_assets"] == []
        doc = inv["resources"][0]
        assert doc["provider"] == "aws"
        assert doc["resource_type"] == "ec2_instance"
        assert doc["tenant_id"] == "t1"

    def test_iam_role_goes_to_identities(self):
        f = _make_finding(
            resource_uid="arn:aws:iam::123:role/MyRole",
            resource_name="MyRole",
            resource_type="AwsIamRole",
            service="iam",
        )
        inv = extract_inventory_from_findings([f], "t1", "aws", "123")
        assert len(inv["identities"]) == 1
        assert inv["resources"] == []

    def test_s3_bucket_goes_to_data_assets(self):
        f = _make_finding(
            resource_uid="arn:aws:s3:::my-bucket",
            resource_name="my-bucket",
            resource_type="AwsS3Bucket",
            service="s3",
        )
        inv = extract_inventory_from_findings([f], "t1", "aws", "123")
        assert len(inv["data_assets"]) == 1

    def test_deduplication_by_resource_uid(self):
        uid = "arn:aws:ec2:us-east-1:123:instance/i-abc"
        f1 = _make_finding(resource_uid=uid, status="FAIL")
        f2 = _make_finding(resource_uid=uid, status="PASS")
        inv = extract_inventory_from_findings([f1, f2], "t1", "aws", "123")
        assert len(inv["resources"]) == 1

    def test_mixed_resource_types(self):
        ec2 = _make_finding()
        role = _make_finding(
            resource_uid="arn:aws:iam::123:role/R",
            resource_name="R",
            resource_type="AwsIamRole",
        )
        bucket = _make_finding(
            resource_uid="arn:aws:s3:::b",
            resource_name="b",
            resource_type="AwsS3Bucket",
        )
        inv = extract_inventory_from_findings([ec2, role, bucket], "t1", "aws", "123")
        assert len(inv["resources"]) == 1
        assert len(inv["identities"]) == 1
        assert len(inv["data_assets"]) == 1

    def test_arn_extracted_as_arn_field(self):
        findings = [_make_finding()]
        inv = extract_inventory_from_findings(findings, "t1", "aws", "123")
        doc = inv["resources"][0]
        assert doc["arn"] is not None
        assert doc["arn"].startswith("arn:")

    def test_non_arn_uid_has_null_arn(self):
        f = _make_finding(resource_uid="i-abc123", resource_name="i-abc123")
        inv = extract_inventory_from_findings([f], "t1", "aws", "123")
        assert inv["resources"][0]["arn"] is None

    def test_tags_extracted_from_metadata(self):
        f = _make_finding(metadata={"tags": [{"Key": "Env", "Value": "prod"}]})
        inv = extract_inventory_from_findings([f], "t1", "aws", "123")
        assert inv["resources"][0]["tags"] == {"Env": "prod"}

    def test_public_ip_sets_is_public_true(self):
        f = _make_finding(metadata={"public_ip": "54.0.0.1"})
        inv = extract_inventory_from_findings([f], "t1", "aws", "123")
        assert inv["resources"][0]["is_public"] is True

    def test_empty_findings_returns_empty_collections(self):
        inv = extract_inventory_from_findings([], "t1", "aws", "123")
        assert inv == {"resources": [], "identities": [], "data_assets": []}

    def test_finding_with_no_uid_skipped(self):
        f = _make_finding(resource_uid="", resource_name="")
        inv = extract_inventory_from_findings([f], "t1", "aws", "123")
        assert all(len(v) == 0 for v in inv.values())

    def test_status_active_always_set(self):
        findings = [
            _make_finding(status="PASS"),
            _make_finding(
                resource_uid="arn:aws:ec2:us-east-1:123:instance/i-xyz",
                status="FAIL",
            ),
        ]
        inv = extract_inventory_from_findings(findings, "t1", "aws", "123")
        for doc in inv["resources"]:
            assert doc["status"] == "active"


# ---------------------------------------------------------------------------
# extract_inventory_from_findings — Azure
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExtractInventoryAzure:
    def _make_azure_finding(
        self,
        resource_uid: str = "/subscriptions/sub1/virtualMachines/myvm",
        resource_type: str = "microsoft.compute/virtualmachines",
    ):
        check_meta = SimpleNamespace(
            ResourceType=resource_type,
            ServiceName="vm",
            CheckID="vm_backup_enabled",
            CheckTitle="VM Backup Enabled",
            Severity="medium",
            Description="...",
        )
        return SimpleNamespace(
            resource_uid=resource_uid,
            resource_name="myvm",
            region="eastus",
            account_uid="sub1",
            metadata=check_meta,
            resource_metadata={},
            status="FAIL",
        )

    def test_azure_vm_goes_to_resources(self):
        inv = extract_inventory_from_findings([self._make_azure_finding()], "t1", "azure", "sub1")
        assert len(inv["resources"]) == 1
        doc = inv["resources"][0]
        assert doc["provider"] == "azure"
        assert "azure" in doc["resource_type"]

    def test_azure_keyvault_goes_to_data_assets(self):
        inv = extract_inventory_from_findings(
            [self._make_azure_finding(resource_type="microsoft.keyvault/vaults")],
            "t1",
            "azure",
            "sub1",
        )
        assert len(inv["data_assets"]) == 1


# ---------------------------------------------------------------------------
# extract_inventory_from_findings — Kubernetes
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExtractInventoryK8s:
    def _make_k8s_finding(self, resource_type="Pod", resource_uid="kube-system/kube-apiserver"):
        check_meta = SimpleNamespace(
            ResourceType=resource_type,
            ServiceName="apiserver",
            CheckID="apiserver_audit_log_maxage_set",
            CheckTitle="API Server audit log",
            Severity="high",
            Description="...",
        )
        return SimpleNamespace(
            resource_uid=resource_uid,
            resource_name="kube-apiserver",
            region="namespace: kube-system",
            account_uid="my-cluster",
            metadata=check_meta,
            resource_metadata={},
            status="FAIL",
        )

    def test_k8s_pod_goes_to_resources(self):
        inv = extract_inventory_from_findings([self._make_k8s_finding()], "t1", "kubernetes", "my-cluster")
        assert len(inv["resources"]) == 1
        doc = inv["resources"][0]
        assert doc["provider"] == "k8s"
        assert doc["resource_type"] == "k8s_pod"


# ---------------------------------------------------------------------------
# _to_jsonable — Pydantic v1/v2 nested object serialization
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestToJsonable:
    def test_plain_types_pass_through(self):
        assert _to_jsonable("hello") == "hello"
        assert _to_jsonable(42) == 42
        assert _to_jsonable(3.14) == 3.14
        assert _to_jsonable(True) is True
        assert _to_jsonable(None) is None

    def test_dict_is_recursed(self):
        assert _to_jsonable({"a": 1, "b": "x"}) == {"a": 1, "b": "x"}

    def test_list_is_recursed(self):
        assert _to_jsonable([1, "two", None]) == [1, "two", None]

    def test_nested_dict_in_list(self):
        assert _to_jsonable([{"k": 1}]) == [{"k": 1}]

    def test_datetime_becomes_isoformat(self):
        from datetime import datetime, timezone
        dt = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _to_jsonable(dt)
        assert result == "2024-01-15T12:00:00+00:00"

    def test_unknown_object_becomes_str(self):
        class Opaque:
            def __str__(self):
                return "opaque-value"
        assert _to_jsonable(Opaque()) == "opaque-value"

    def test_pydantic_v1_model_serialized(self):
        """Simulate a Prowler v5 Trail-like Pydantic v1 model nested in resource_metadata."""
        try:
            from pydantic.v1 import BaseModel as PydanticV1Base
        except ImportError:
            pytest.skip("pydantic.v1 not available")

        class Trail(PydanticV1Base):
            name: str
            arn: str
            is_multiregion: bool = False

        trail = Trail(name="my-trail", arn="arn:aws:cloudtrail:us-east-1:123:trail/my-trail")
        metadata = {"trail": trail, "region": "us-east-1"}
        result = _to_jsonable(metadata)
        assert isinstance(result, dict)
        assert result["region"] == "us-east-1"
        assert isinstance(result["trail"], dict)
        assert result["trail"]["name"] == "my-trail"
        assert result["trail"]["arn"] == "arn:aws:cloudtrail:us-east-1:123:trail/my-trail"

    def test_resource_metadata_with_nested_model_is_json_serializable(self):
        """End-to-end: resource_metadata containing a Pydantic v1 model must produce a JSON-safe doc."""
        import json

        try:
            from pydantic.v1 import BaseModel as PydanticV1Base
        except ImportError:
            pytest.skip("pydantic.v1 not available")

        class Trail(PydanticV1Base):
            name: str
            home_region: str

        finding = _make_finding(
            resource_uid="arn:aws:cloudtrail:us-east-1:123:trail/my-trail",
            resource_type="AwsCloudTrailTrail",
            metadata={"trail": Trail(name="my-trail", home_region="us-east-1")},
        )
        inv = extract_inventory_from_findings([finding], "dev-tenant", "aws", "123456789012")
        assert len(inv["resources"]) == 1
        doc = inv["resources"][0]
        # Must not raise — this is what python-arango does before sending to ArangoDB
        serialized = json.dumps(doc)
        assert "my-trail" in serialized
