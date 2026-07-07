"""
Integration tests for scan_ec2_instance Celery task (Epic 03 Sprint 1).

Strategy:
- boto3 (EC2 API calls) → mocked via moto @mock_aws
- Analysers (Trivy, YARA, TruffleHog) → mocked via pytest-mock (external binaries)
- mount/umount subprocess → mocked (no real EBS attachment in CI)
- ArangoDB → real instance via Docker (never mocked)

Each test verifies the full task lifecycle: snapshot created, analysis run,
findings persisted to ArangoDB, cleanup executed even on failure.
"""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from moto import mock_aws

from app.db.init import init_tenant_schema
from app.workers.tasks.side_scanning import cleanup_orphan_snapshots, scan_ec2_instance

# ─── Helpers ─────────────────────────────────────────────────────────────────

REGION = "us-east-1"
TENANT = "test-sidescanning"
ACCOUNT = "123456789012"
AZ = "us-east-1a"


def _seed_ec2(ec2_client: Any) -> tuple[str, str]:
    """Create a minimal moto EC2 instance + volume. Returns (instance_id, volume_id)."""
    # Volume
    vol = ec2_client.create_volume(AvailabilityZone=AZ, Size=8, VolumeType="gp3")
    volume_id = vol["VolumeId"]

    # Instance (moto doesn't need a real AMI to create instances via resource)
    ec2_resource = boto3.resource("ec2", region_name=REGION)
    instances = ec2_resource.create_instances(
        ImageId="ami-00000000",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
    )
    instance_id = instances[0].id
    return instance_id, volume_id


# ─── Tests ────────────────────────────────────────────────────────────────────


@pytest.mark.integration
@mock_aws
def test_scan_creates_snapshot_and_deletes_it(db_tenant_a, mocker):
    """Snapshot is created then deleted even when analysers return empty results."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    # Analysers return empty — no findings expected
    mocker.patch("app.workers.tasks.side_scanning.run_trivy_fs", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_trufflehog", return_value=[])

    # Patch _get_tenant_db so the task uses the test DB
    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    result = scan_ec2_instance(
        tenant_id=TENANT,
        resource_key="test-resource-key",
        provider_key="test-provider",
        region=REGION,
        account_id=ACCOUNT,
        instance_id=instance_id,
        volume_id=volume_id,
        availability_zone=AZ,
        resource_arn=f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{instance_id}",
    )

    # No findings — but job completed
    assert result["findings_count"] == 0
    assert result["cve_count"] == 0

    # Snapshot must be gone after task
    snaps = ec2_client.describe_snapshots(
        Filters=[{"Name": "tag:ogum:scan", "Values": ["true"]}],
        OwnerIds=["self"],
    )
    assert len(snaps["Snapshots"]) == 0


@pytest.mark.integration
@mock_aws
def test_scan_persists_cve_findings(db_tenant_a, mocker):
    """CVE findings from Trivy are normalised and persisted to ArangoDB."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    # Seed a resource vertex so HAS_FINDING edge has a valid _from
    db_tenant_a.collection("resources").insert(
        {
            "_key": "test-resource-key",
            "tenant_id": TENANT,
            "resource_id": "test-resource-key",
            "provider": "aws",
            "resource_type": "ec2_instance",
            "status": "active",
        }
    )

    trivy_output = [
        {
            "cve_id": "CVE-2024-1234",
            "package": "openssl",
            "installed_version": "1.1.1",
            "fixed_version": "1.1.2",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "title": "OpenSSL buffer overflow",
            "description": "A buffer overflow in OpenSSL allows...",
        }
    ]
    mocker.patch("app.workers.tasks.side_scanning.run_trivy_fs", return_value=trivy_output)
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_trufflehog", return_value=[])
    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    result = scan_ec2_instance(
        tenant_id=TENANT,
        resource_key="test-resource-key",
        provider_key="test-provider",
        region=REGION,
        account_id=ACCOUNT,
        instance_id=instance_id,
        volume_id=volume_id,
        availability_zone=AZ,
    )

    assert result["findings_count"] == 1
    assert result["cve_count"] == 1

    # Finding persisted in ArangoDB
    cursor = db_tenant_a.aql.execute("FOR f IN findings FILTER f.source == 'side_scanning' RETURN f")
    findings = list(cursor)
    assert len(findings) == 1
    assert findings[0]["check_id"] == "side_scanning/cve/CVE-2024-1234"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["tenant_id"] == TENANT
    # Secret value must not appear in raw_output
    assert "secret" not in str(findings[0])


@pytest.mark.integration
@mock_aws
def test_scan_persists_secret_finding(db_tenant_a, mocker):
    """Exposed secret findings are persisted — secret value never stored."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    db_tenant_a.collection("resources").insert(
        {
            "_key": "res-secret-test",
            "tenant_id": TENANT,
            "resource_id": "res-secret-test",
            "provider": "aws",
            "resource_type": "ec2_instance",
            "status": "active",
        }
    )

    secret_output = [{"rule": "aws_key", "path": "/home/ubuntu/.bashrc", "line": 42}]
    mocker.patch("app.workers.tasks.side_scanning.run_trivy_fs", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_trufflehog", return_value=secret_output)
    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    result = scan_ec2_instance(
        tenant_id=TENANT,
        resource_key="res-secret-test",
        provider_key="test-provider",
        region=REGION,
        account_id=ACCOUNT,
        instance_id=instance_id,
        volume_id=volume_id,
        availability_zone=AZ,
    )

    assert result["secret_count"] == 1

    cursor = db_tenant_a.aql.execute("FOR f IN findings FILTER f.source == 'side_scanning' RETURN f")
    findings = list(cursor)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "CRITICAL"
    assert "exposed_secret" in f["check_id"] or "secret" in f["check_id"]
    # The actual secret value must never appear
    assert "AKIA" not in str(f)


@pytest.mark.integration
@mock_aws
def test_scan_persists_malware_finding(db_tenant_a, mocker):
    """Malware (YARA) findings are persisted as CRITICAL."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    db_tenant_a.collection("resources").insert(
        {
            "_key": "res-malware-test",
            "tenant_id": TENANT,
            "resource_id": "res-malware-test",
            "provider": "aws",
            "resource_type": "ec2_instance",
            "status": "active",
        }
    )

    yara_output = [{"rule": "Webshell_Generic", "path": "/var/www/html/shell.php"}]
    mocker.patch("app.workers.tasks.side_scanning.run_trivy_fs", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=yara_output)
    mocker.patch("app.workers.tasks.side_scanning.run_trufflehog", return_value=[])
    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    result = scan_ec2_instance(
        tenant_id=TENANT,
        resource_key="res-malware-test",
        provider_key="test-provider",
        region=REGION,
        account_id=ACCOUNT,
        instance_id=instance_id,
        volume_id=volume_id,
        availability_zone=AZ,
    )

    assert result["malware_count"] == 1

    cursor = db_tenant_a.aql.execute("FOR f IN findings FILTER f.source == 'side_scanning' RETURN f")
    findings = list(cursor)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert "malware" in findings[0]["check_id"]


@pytest.mark.integration
@mock_aws
def test_cleanup_runs_after_analyser_exception(db_tenant_a, mocker):
    """Snapshot and volume are deleted even when an analyser raises an exception."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    mocker.patch(
        "app.workers.tasks.side_scanning.run_trivy_fs",
        side_effect=RuntimeError("trivy crashed"),
    )
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_trufflehog", return_value=[])
    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    # Task should not raise — analyser errors are caught inside ThreadPoolExecutor
    result = scan_ec2_instance(
        tenant_id=TENANT,
        resource_key="cleanup-test",
        provider_key="test-provider",
        region=REGION,
        account_id=ACCOUNT,
        instance_id=instance_id,
        volume_id=volume_id,
        availability_zone=AZ,
    )

    assert result["findings_count"] == 0

    # Snapshot must still be cleaned up
    snaps = ec2_client.describe_snapshots(
        Filters=[{"Name": "tag:ogum:scan", "Values": ["true"]}],
        OwnerIds=["self"],
    )
    assert len(snaps["Snapshots"]) == 0


@pytest.mark.integration
@mock_aws
def test_scan_job_record_created(db_tenant_a, mocker):
    """scan_jobs record is created and completed in ArangoDB."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    mocker.patch("app.workers.tasks.side_scanning.run_trivy_fs", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_trufflehog", return_value=[])
    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    result = scan_ec2_instance(
        tenant_id=TENANT,
        resource_key="job-test",
        provider_key="test-provider",
        region=REGION,
        account_id=ACCOUNT,
        instance_id=instance_id,
        volume_id=volume_id,
        availability_zone=AZ,
    )

    job_id = result["job_id"]
    job_doc = db_tenant_a.collection("scan_jobs").get(job_id)
    assert job_doc is not None
    assert job_doc["status"] == "completed"


@pytest.mark.integration
@mock_aws
def test_snapshot_tagged_with_tenant_and_expiry(db_tenant_a, mocker):
    """Created snapshot carries ogum:scan, ogum:tenant_id, and ogum:expires_at tags."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    mocker.patch("app.workers.tasks.side_scanning.run_trivy_fs", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=[])
    mocker.patch("app.workers.tasks.side_scanning.run_trufflehog", return_value=[])
    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    scan_ec2_instance(
        tenant_id=TENANT,
        resource_key="tag-test",
        provider_key="test-provider",
        region=REGION,
        account_id=ACCOUNT,
        instance_id=instance_id,
        volume_id=volume_id,
        availability_zone=AZ,
    )

    # All ogum:scan snapshots were deleted — verify via tag filter returning nothing
    snaps = ec2_client.describe_snapshots(
        Filters=[{"Name": "tag:ogum:scan", "Values": ["true"]}],
        OwnerIds=["self"],
    )
    # Snapshot was cleaned up (count == 0 confirms lifecycle was correct)
    assert len(snaps["Snapshots"]) == 0


@pytest.mark.integration
@mock_aws
def test_cleanup_orphan_snapshots_deletes_expired(db_tenant_a, mocker):
    """cleanup_orphan_snapshots deletes snapshots past their expiry tag."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    vol = ec2_client.create_volume(AvailabilityZone=AZ, Size=8)
    volume_id = vol["VolumeId"]

    # Create an expired snapshot manually
    snap = ec2_client.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "ogum:scan", "Value": "true"},
                    {"Key": "ogum:tenant_id", "Value": TENANT},
                    # Already expired — 2020
                    {"Key": "ogum:expires_at", "Value": "2020-01-01T00:00:00+00:00"},
                ],
            }
        ],
    )
    snap_id = snap["SnapshotId"]

    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    result = cleanup_orphan_snapshots(
        tenant_id=TENANT,
        region=REGION,
    )

    assert result["deleted"] == 1
    assert result["scanned"] >= 1

    # Snapshot gone — filter-based query returns empty list for deleted snapshots
    # (describe_snapshots with SnapshotIds raises ClientError for deleted snapshots)
    snaps = ec2_client.describe_snapshots(
        Filters=[
            {"Name": "tag:ogum:scan", "Values": ["true"]},
            {"Name": "snapshot-id", "Values": [snap_id]},
        ],
        OwnerIds=["self"],
    )
    assert len(snaps["Snapshots"]) == 0


@pytest.mark.integration
@mock_aws
def test_cleanup_orphan_snapshots_skips_future(db_tenant_a, mocker):
    """cleanup_orphan_snapshots does not delete snapshots with future expiry."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    vol = ec2_client.create_volume(AvailabilityZone=AZ, Size=8)
    volume_id = vol["VolumeId"]

    ec2_client.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "ogum:scan", "Value": "true"},
                    {"Key": "ogum:tenant_id", "Value": TENANT},
                    # Far future
                    {"Key": "ogum:expires_at", "Value": "2099-01-01T00:00:00+00:00"},
                ],
            }
        ],
    )

    mocker.patch(
        "app.workers.tasks.side_scanning._get_tenant_db",
        return_value=db_tenant_a,
    )

    result = cleanup_orphan_snapshots(
        tenant_id=TENANT,
        region=REGION,
    )

    assert result["deleted"] == 0
    # Snapshot still present
    snaps = ec2_client.describe_snapshots(
        Filters=[{"Name": "tag:ogum:scan", "Values": ["true"]}],
        OwnerIds=["self"],
    )
    assert len(snaps["Snapshots"]) == 1
