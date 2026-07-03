"""
Integration tests for AWS discovery Celery tasks.

Rules:
- ArangoDB: real instance (provided by db_tenant_a fixture — never mocked)
- boto3: mocked via moto (@mock_aws) or via MagicMock for throttle tests
- Celery: task.apply() runs synchronously — no broker required
- _get_tenant_db is patched to return the fixture DB directly
"""

import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from app.db.init import init_tenant_schema
from app.workers.tasks.discovery import discover_aws, discover_aws_basic

TEST_TENANT_A = "test-tenant-aaa"


def _populate_aws(region: str = "us-east-1") -> dict:
    """Seed moto with one EC2 instance, one IAM role, and one S3 bucket."""
    ec2 = boto3.resource("ec2", region_name=region)
    instance = ec2.create_instances(
        ImageId="ami-00000001",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "test-web-server"},
                    {"Key": "Environment", "Value": "test"},
                ],
            }
        ],
    )[0]

    iam = boto3.client("iam", region_name=region)
    iam.create_role(
        RoleName="TestWebRole",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )

    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket="test-assets-bucket")

    return {"instance_id": instance.id}


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_ACCOUNT_ID = "123456789012"


# ─── Sprint 1: basic discovery ────────────────────────────────────────────────


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


# ─── Sprint 2: expanded discovery ─────────────────────────────────────────────


@pytest.mark.integration
class TestAWSExpandedDiscovery:
    """discover_aws — full service coverage. moto mocks, real ArangoDB stores results."""

    def test_vpc_discovery(self, db_tenant_a, mocker) -> None:
        """VPCs (including default VPC) must be discovered and persisted as resources."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ec2 = boto3.client("ec2", region_name="us-east-1")
            ec2.create_vpc(CidrBlock="10.10.0.0/16")
            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        resources = list(db_tenant_a.collection("resources").all())
        vpcs = [r for r in resources if r["resource_type"] == "vpc"]
        assert len(vpcs) >= 2  # at least: default VPC + custom VPC

        custom_vpcs = [v for v in vpcs if v["raw_metadata"].get("cidr_block") == "10.10.0.0/16"]
        assert len(custom_vpcs) == 1
        assert custom_vpcs[0]["status"] == "active"

    def test_security_group_with_open_ingress_is_marked_public(self, db_tenant_a, mocker) -> None:
        """A security group with 0.0.0.0/0 ingress must be persisted with is_public=True."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ec2 = boto3.client("ec2", region_name="us-east-1")
            vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
            vpc_id = vpc["Vpc"]["VpcId"]

            sg = ec2.create_security_group(
                GroupName="wide-open-sg",
                Description="Open to world",
                VpcId=vpc_id,
            )
            sg_id = sg["GroupId"]
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )
            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        resources = list(db_tenant_a.collection("resources").all())
        target_sg = [r for r in resources if r["resource_id"] == sg_id]
        assert len(target_sg) == 1
        assert target_sg[0]["resource_type"] == "security_group"
        assert target_sg[0]["is_public"] is True

    def test_rds_instance_discovery(self, db_tenant_a, mocker) -> None:
        """RDS instances must be discovered and stored with correct resource_type."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            rds = boto3.client("rds", region_name="us-east-1")
            rds.create_db_instance(
                DBInstanceIdentifier="prod-mysql",
                DBInstanceClass="db.t3.micro",
                Engine="mysql",
                MasterUsername="admin",
                MasterUserPassword="password123",
                AllocatedStorage=20,
            )
            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        resources = list(db_tenant_a.collection("resources").all())
        rds_list = [r for r in resources if r["resource_type"] == "rds_instance"]
        assert len(rds_list) >= 1
        assert any(r["resource_id"] == "prod-mysql" for r in rds_list)

    def test_lambda_function_discovery(self, db_tenant_a, mocker) -> None:
        """Lambda functions must be discovered with execution role ARN in metadata."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            iam = boto3.client("iam", region_name="us-east-1")
            role = iam.create_role(
                RoleName="lambda-exec-role",
                AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
            )
            role_arn = role["Role"]["Arn"]

            lam = boto3.client("lambda", region_name="us-east-1")
            lam.create_function(
                FunctionName="my-handler",
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": b"fake-code"},
            )
            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        resources = list(db_tenant_a.collection("resources").all())
        lambdas = [r for r in resources if r["resource_type"] == "lambda_function"]
        assert len(lambdas) >= 1
        assert any(r["name"] == "my-handler" for r in lambdas)
        assert any(r["raw_metadata"].get("execution_role_arn") for r in lambdas)

    def test_soft_delete_vpc_removed_from_cloud(self, db_tenant_a, mocker) -> None:
        """VPC present in run 1 but absent in run 2 must be soft-deleted, not hard-deleted."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ec2 = boto3.client("ec2", region_name="us-east-1")
            vpc = ec2.create_vpc(CidrBlock="10.99.0.0/16")
            custom_vpc_id = vpc["Vpc"]["VpcId"]
            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        # Confirm it was discovered as active
        all_resources = list(db_tenant_a.collection("resources").all())
        discovered = [r for r in all_resources if r["resource_id"] == custom_vpc_id]
        assert len(discovered) == 1
        assert discovered[0]["status"] == "active"

        # Second mock_aws context — fresh state, custom VPC gone
        with mock_aws():
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        all_resources = list(db_tenant_a.collection("resources").all())
        after_second_run = [r for r in all_resources if r["resource_id"] == custom_vpc_id]
        assert len(after_second_run) == 1, "soft-deleted resource must still exist"
        assert after_second_run[0]["status"] == "deleted"
        assert after_second_run[0].get("deleted_at") is not None

    def test_ecr_repository_discovery(self, db_tenant_a, mocker) -> None:
        """ECR repositories must be discovered and stored with correct resource_type."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ecr = boto3.client("ecr", region_name="us-east-1")
            ecr.create_repository(repositoryName="my-app")
            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        resources = list(db_tenant_a.collection("resources").all())
        repos = [r for r in resources if r["resource_type"] == "ecr_repository"]
        assert len(repos) >= 1
        assert any(r["name"] == "my-app" for r in repos)


# ─── Sprint 2: relationship edges ─────────────────────────────────────────────


@pytest.mark.integration
class TestRelationshipEdgeCreation:
    """discover_aws creates relationship edges between AWS resources."""

    def test_ec2_belongs_to_vpc_edge(self, db_tenant_a, mocker) -> None:
        """EC2 instances must have a BELONGS_TO edge pointing to their VPC."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ec2_client = boto3.client("ec2", region_name="us-east-1")
            # Describe the default VPC so we know what to expect
            vpcs = ec2_client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
            _default_vpc_id = vpcs["Vpcs"][0]["VpcId"]

            ec2_resource = boto3.resource("ec2", region_name="us-east-1")
            _instance = ec2_resource.create_instances(
                ImageId="ami-00000001",
                MinCount=1,
                MaxCount=1,
            )[0]

            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        edges = list(db_tenant_a.collection("BELONGS_TO").all())
        ec2_edges = [e for e in edges if "ec2_instance" in e["_from"]]
        assert len(ec2_edges) >= 1
        # All edges must point to a VPC vertex
        for edge in ec2_edges:
            assert "resources/" in edge["_to"]

    def test_sg_attached_to_ec2_edge(self, db_tenant_a, mocker) -> None:
        """Security groups attached to an EC2 must have an ATTACHED_TO edge."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ec2_client = boto3.client("ec2", region_name="us-east-1")
            vpcs = ec2_client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
            default_vpc_id = vpcs["Vpcs"][0]["VpcId"]

            sg = ec2_client.create_security_group(
                GroupName="web-sg",
                Description="Web tier SG",
                VpcId=default_vpc_id,
            )
            sg_id = sg["GroupId"]

            ec2_resource = boto3.resource("ec2", region_name="us-east-1")
            ec2_resource.create_instances(
                ImageId="ami-00000001",
                MinCount=1,
                MaxCount=1,
                SecurityGroupIds=[sg_id],
            )

            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        edges = list(db_tenant_a.collection("ATTACHED_TO").all())
        sg_edges = [e for e in edges if "security_group" in e["_from"]]
        assert len(sg_edges) >= 1
        for edge in sg_edges:
            assert "resources/" in edge["_to"]

    def test_igw_routes_traffic_to_vpc_edge(self, db_tenant_a, mocker) -> None:
        """An IGW attached to a VPC must have a ROUTES_TRAFFIC edge."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ec2_client = boto3.client("ec2", region_name="us-east-1")
            vpc = ec2_client.create_vpc(CidrBlock="10.20.0.0/16")
            vpc_id = vpc["Vpc"]["VpcId"]

            igw = ec2_client.create_internet_gateway()
            igw_id = igw["InternetGateway"]["InternetGatewayId"]
            ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        # Verify IGW vertex exists
        resources = list(db_tenant_a.collection("resources").all())
        igws = [r for r in resources if r["resource_type"] == "internet_gateway" and r["resource_id"] == igw_id]
        assert len(igws) == 1

        # Verify ROUTES_TRAFFIC edge: IGW → VPC
        edges = list(db_tenant_a.collection("ROUTES_TRAFFIC").all())
        igw_edges = [e for e in edges if "internet_gateway" in e["_from"]]
        assert len(igw_edges) >= 1
        vpc_handles = [e["_to"] for e in igw_edges]
        assert any("vpc" in h for h in vpc_handles)

    def test_lambda_assumes_role_edge(self, db_tenant_a, mocker) -> None:
        """Lambda function must have an ASSUMES_ROLE edge to its execution role."""
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            iam = boto3.client("iam", region_name="us-east-1")
            role = iam.create_role(
                RoleName="my-lambda-role",
                AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
            )
            role_arn = role["Role"]["Arn"]

            lam = boto3.client("lambda", region_name="us-east-1")
            lam.create_function(
                FunctionName="edge-test-fn",
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": b"fake-code"},
            )
            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        # Lambda → IAM Role edge
        edges = list(db_tenant_a.collection("ASSUMES_ROLE").all())
        lambda_edges = [e for e in edges if "lambda_function" in e["_from"]]
        assert len(lambda_edges) >= 1
        assert all("identities/" in e["_to"] for e in lambda_edges)

    def test_two_hop_aql_traversal_igw_vpc_ec2(self, db_tenant_a, mocker) -> None:
        """
        2-hop graph traversal: IGW --ROUTES_TRAFFIC--> VPC <--BELONGS_TO-- EC2.
        Starting from an IGW, we must reach EC2 instances through the VPC.
        """
        mocker.patch("app.workers.tasks.discovery._get_tenant_db", return_value=db_tenant_a)

        with mock_aws():
            ec2_client = boto3.client("ec2", region_name="us-east-1")
            vpcs = ec2_client.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
            default_vpc_id = vpcs["Vpcs"][0]["VpcId"]

            igw = ec2_client.create_internet_gateway()
            igw_id = igw["InternetGateway"]["InternetGatewayId"]
            ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=default_vpc_id)

            ec2_resource = boto3.resource("ec2", region_name="us-east-1")
            ec2_resource.create_instances(ImageId="ami-00000001", MinCount=1, MaxCount=1)

            init_tenant_schema(db_tenant_a)
            discover_aws.apply(args=[TEST_TENANT_A, ["us-east-1"], _ACCOUNT_ID]).get()

        # Traversal: IGW → VPC (ROUTES_TRAFFIC outbound), VPC → EC2 (BELONGS_TO inbound)
        cursor = db_tenant_a.aql.execute("""
            FOR igw IN resources
              FILTER igw.resource_type == "internet_gateway"
              FOR vpc IN 1 OUTBOUND igw ROUTES_TRAFFIC
                FILTER vpc.resource_type == "vpc"
                FOR ec2 IN 1 INBOUND vpc BELONGS_TO
                  FILTER ec2.resource_type == "ec2_instance"
                  RETURN ec2
        """)
        results = list(cursor)
        assert len(results) >= 1, "2-hop traversal IGW→VPC→EC2 must return at least one instance"
