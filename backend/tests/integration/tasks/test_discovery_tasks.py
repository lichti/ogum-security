"""
Integration tests for AWS discovery Celery tasks.

Rules:
- ArangoDB: real instance (provided by db_tenant_a fixture — never mocked)
- boto3: mocked via moto (@mock_aws) or via MagicMock for throttle tests
- Celery: task.apply() runs synchronously — no broker required
- _get_tenant_db is patched to return the fixture DB directly
"""
import pytest
import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.conftest import TEST_TENANT_A
from app.db.init import init_tenant_schema
from app.workers.tasks.discovery import discover_aws_basic


def _populate_aws(region: str = "us-east-1") -> dict:
    """Seed moto with one EC2 instance, one IAM role, and one S3 bucket."""
    ec2 = boto3.resource("ec2", region_name=region)
    instance = ec2.create_instances(
        ImageId="ami-00000001",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [
                {"Key": "Name", "Value": "test-web-server"},
                {"Key": "Environment", "Value": "test"},
            ],
        }],
    )[0]

    iam = boto3.client("iam", region_name=region)
    iam.create_role(
        RoleName="TestWebRole",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )

    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket="test-assets-bucket")

    return {"instance_id": instance.id}


@pytest.mark.integration
class TestAWSDiscoveryTask:
    """discover_aws_basic — moto mocks all boto3 calls, real ArangoDB stores results."""

    def test_ec2_instances_persisted_after_discovery(self, db_tenant_a, mocker) -> None:
        """Discovered EC2 instances must appear as vertices in the tenant graph."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            aws = _populate_aws()
            init_tenant_schema(db_tenant_a)
            result = discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()

        resources = list(db_tenant_a.collection("resources").all())
        assert len(resources) == 1
        assert resources[0]["resource_type"] == "ec2_instance"
        assert resources[0]["resource_id"] == aws["instance_id"]
        assert resources[0]["name"] == "test-web-server"
        assert result["ec2_count"] == 1

    def test_iam_roles_and_policies_discovered(self, db_tenant_a, mocker) -> None:
        """IAM roles must be persisted as identities; policy values are never stored."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            _populate_aws()
            init_tenant_schema(db_tenant_a)
            result = discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()

        identities = list(db_tenant_a.collection("identities").all())
        assert any(i["identity_type"] == "iam_role" and i["name"] == "TestWebRole" for i in identities)
        assert result["iam_count"] >= 1

    def test_s3_buckets_discovered_without_storing_content(self, db_tenant_a, mocker) -> None:
        """S3 buckets: only metadata stored — no object contents, no policy values."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            _populate_aws()
            init_tenant_schema(db_tenant_a)
            discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()

        assets = list(db_tenant_a.collection("data_assets").all())
        assert any(a["name"] == "test-assets-bucket" and a["asset_type"] == "s3_bucket" for a in assets)
        for asset in assets:
            assert "contents" not in asset
            assert "objects" not in asset

    def test_upsert_is_idempotent(self, db_tenant_a, mocker) -> None:
        """Running discovery twice must not duplicate resources."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            _populate_aws()
            init_tenant_schema(db_tenant_a)

            discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()
            count_after_first = db_tenant_a.collection("resources").count()

            discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()
            count_after_second = db_tenant_a.collection("resources").count()

        assert count_after_first == count_after_second, "re-discovery must not duplicate resources"

    def test_removed_resource_marked_deleted(self, db_tenant_a, mocker) -> None:
        """Resource present in run 1 but absent in run 2 must be soft-deleted."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            aws = _populate_aws()
            init_tenant_schema(db_tenant_a)
            discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()

        # Second mock_aws context: fresh environment with no instances
        with mock_aws():
            discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()

        resources = list(db_tenant_a.collection("resources").all())
        deleted = [r for r in resources if r["resource_id"] == aws["instance_id"]]
        assert len(deleted) == 1, "resource must be soft-deleted, not hard-deleted"
        assert deleted[0]["status"] == "deleted"
        assert deleted[0].get("deleted_at") is not None

    def test_rate_limit_triggers_exponential_backoff(self, db_tenant_a, mocker) -> None:
        """
        A Throttling ClientError inside _list_ec2_instances must be caught by
        retry_with_backoff and retried before propagating failure.
        """
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)
        sleep_mock = mocker.patch("app.workers.tasks.discovery.time.sleep")

        throttle = ClientError(
            {"Error": {"Code": "Throttling", "Message": "Rate exceeded"}},
            "DescribeInstances",
        )
        paginate_calls = {"n": 0}

        def flaky_paginate(*args, **kwargs):
            paginate_calls["n"] += 1
            if paginate_calls["n"] == 1:
                raise throttle
            return [{"Reservations": []}]

        mock_paginator = mocker.MagicMock()
        mock_paginator.paginate.side_effect = flaky_paginate

        mock_ec2 = mocker.MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator

        mock_iam_paginator = mocker.MagicMock()
        mock_iam_paginator.paginate.return_value = []
        mock_iam = mocker.MagicMock()
        mock_iam.get_paginator.return_value = mock_iam_paginator

        mock_s3 = mocker.MagicMock()
        mock_s3.list_buckets.return_value = {"Buckets": []}

        def client_factory(service: str, **kwargs):
            return {"ec2": mock_ec2, "iam": mock_iam, "s3": mock_s3}.get(service, mocker.MagicMock())

        mocker.patch("app.workers.tasks.discovery.boto3.client", side_effect=client_factory)

        init_tenant_schema(db_tenant_a)
        result = discover_aws_basic.apply(args=[TEST_TENANT_A, ["us-east-1"]]).get()

        # paginator.paginate() must have been called more than once (initial + at least 1 retry)
        assert paginate_calls["n"] >= 2, "must have retried after throttle"
        assert sleep_mock.called, "must sleep between retries to implement backoff"
        assert result["discovered"] == 0


@pytest.mark.integration
class TestRelationshipEdgeCreation:
    """Edge creation is Sprint 2 scope — stubs kept as explicit blockers."""

    def test_ec2_belongs_to_vpc(self, db_tenant_a) -> None:
        pytest.skip("Implement when BELONGS_TO edge creation is added to discover_aws (Sprint 2)")

    def test_ec2_attached_to_security_group(self, db_tenant_a) -> None:
        pytest.skip("Implement when ATTACHED_TO edge creation is added to discover_aws (Sprint 2)")

    def test_iam_role_assumes_role_edge(self, db_tenant_a) -> None:
        pytest.skip("Implement when ASSUMES_ROLE edge creation is added to discover_aws (Sprint 2)")
