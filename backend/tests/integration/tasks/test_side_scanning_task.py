"""
Integration tests for cleanup_orphan_snapshots (Celery Beat hourly task).

Strategy:
- boto3 (EC2 API calls) → mocked via moto @mock_aws
- ArangoDB → real instance via Docker (never mocked)

Note: scan_ec2_instance (Sprint 1, volume/mount pipeline) was removed — EBS Direct
API (scan_ec2_instance_v2, see test_side_scanning_v2.py) covers everything it did,
plus SBOM generation and an optional scoped-mount YARA scan.
"""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from moto import mock_aws

from app.workers.tasks.side_scanning import cleanup_orphan_snapshots

REGION = "us-east-1"
TENANT = "test-sidescanning"
AZ = "us-east-1a"


@pytest.mark.integration
@mock_aws
def test_cleanup_orphan_snapshots_deletes_expired(db_tenant_a: Any, mocker: Any) -> None:
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
def test_cleanup_orphan_snapshots_skips_future(db_tenant_a: Any, mocker: Any) -> None:
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
