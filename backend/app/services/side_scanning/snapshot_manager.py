"""EBS snapshot lifecycle management for side-scanning."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 10  # seconds between snapshot state polls
_SNAPSHOT_MAX_WAIT = 900  # 15 minutes


def create_scan_snapshot(ec2_client: Any, volume_id: str, tenant_id: str) -> str:
    """Create a tagged EBS snapshot for side-scanning. Returns snapshot_id."""
    expires_at = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    resp = ec2_client.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "ogum:scan", "Value": "true"},
                    {"Key": "ogum:tenant_id", "Value": tenant_id},
                    {"Key": "ogum:expires_at", "Value": expires_at},
                ],
            }
        ],
    )
    snapshot_id: str = resp["SnapshotId"]
    logger.info("Created snapshot %s from volume %s (tenant=%s)", snapshot_id, volume_id, tenant_id)
    return snapshot_id


def wait_for_snapshot(ec2_client: Any, snapshot_id: str, timeout: int = _SNAPSHOT_MAX_WAIT) -> None:
    """Poll until snapshot reaches completed state. Raises TimeoutError or RuntimeError on failure."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        resp = ec2_client.describe_snapshots(SnapshotIds=[snapshot_id])
        state = resp["Snapshots"][0]["State"]
        if state == "completed":
            return
        if state == "error":
            raise RuntimeError(f"Snapshot {snapshot_id} entered error state")
        time.sleep(_POLL_INTERVAL)
    raise TimeoutError(f"Snapshot {snapshot_id} not completed within {timeout}s")


def create_volume_from_snapshot(ec2_client: Any, snapshot_id: str, availability_zone: str) -> str:
    """Create a gp3 volume from a snapshot. Returns volume_id."""
    resp = ec2_client.create_volume(
        SnapshotId=snapshot_id,
        AvailabilityZone=availability_zone,
        VolumeType="gp3",
    )
    volume_id: str = resp["VolumeId"]
    logger.info("Created volume %s from snapshot %s", volume_id, snapshot_id)
    return volume_id


def delete_snapshot_safe(ec2_client: Any, snapshot_id: str) -> None:
    """Delete snapshot, logging but not swallowing failures (caller handles DLQ)."""
    try:
        ec2_client.delete_snapshot(SnapshotId=snapshot_id)
        logger.info("Deleted snapshot %s", snapshot_id)
    except Exception:
        logger.exception("Failed to delete snapshot %s — requires manual cleanup", snapshot_id)
        raise


def delete_volume_safe(ec2_client: Any, volume_id: str) -> None:
    """Delete volume, logging but not swallowing failures (caller handles DLQ)."""
    try:
        ec2_client.delete_volume(VolumeId=volume_id)
        logger.info("Deleted volume %s", volume_id)
    except Exception:
        logger.exception("Failed to delete volume %s — requires manual cleanup", volume_id)
        raise


def mount_volume_ro(device: str, mount_path: str) -> None:
    """Mount a block device read-only. Requires appropriate Linux capabilities."""
    os.makedirs(mount_path, exist_ok=True)
    result = subprocess.run(
        ["mount", "-o", "ro", device, mount_path],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"mount failed (device={device}): {result.stderr.strip()}")
    logger.info("Mounted %s at %s (read-only)", device, mount_path)


def umount_volume(mount_path: str) -> None:
    """Unmount a path, best-effort (errors are logged, never raised during cleanup)."""
    try:
        result = subprocess.run(
            ["umount", mount_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning("umount %s returned %d: %s", mount_path, result.returncode, result.stderr.strip())
    except Exception:
        logger.exception("Failed to umount %s", mount_path)


def list_ogum_snapshots(ec2_client: Any) -> list[dict[str, Any]]:
    """List all snapshots tagged ogum:scan=true owned by the current account."""
    resp = ec2_client.describe_snapshots(
        Filters=[{"Name": "tag:ogum:scan", "Values": ["true"]}],
        OwnerIds=["self"],
    )
    snapshots: list[dict[str, Any]] = resp.get("Snapshots", [])
    return snapshots
