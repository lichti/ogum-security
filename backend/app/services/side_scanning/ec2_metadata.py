"""
Resolve EC2 instance metadata that Prowler's inventory does not carry.

Prowler's EC2 `Instance` model (prowler.providers.aws.services.ec2.ec2_service)
has no availability zone or block-device/volume fields, but scan_ec2_instance_v2
needs both — volume_id to create the EBS snapshot in the first place, and
availability_zone to attach a scoped scan volume for the optional YARA step.
One batched describe_instances call per trigger resolves both without
reintroducing a second discovery pipeline.
"""

from __future__ import annotations

from typing import Any


def resolve_ec2_scan_metadata(ec2_client: Any, instance_ids: list[str]) -> dict[str, dict[str, str]]:
    """
    Return {instance_id: {"availability_zone": ..., "volume_id": ...}} for each
    instance found. Instances that no longer exist or have no attached volume
    are omitted from the result rather than raising.
    """
    if not instance_ids:
        return {}

    result: dict[str, dict[str, str]] = {}
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate(InstanceIds=instance_ids):
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId")
                if not instance_id:
                    continue

                availability_zone = instance.get("Placement", {}).get("AvailabilityZone", "")

                volume_id = _root_volume_id(instance)
                if not volume_id:
                    continue

                result[instance_id] = {
                    "availability_zone": availability_zone,
                    "volume_id": volume_id,
                }

    return result


def _root_volume_id(instance: dict[str, Any]) -> str:
    """Prefer the mapping matching RootDeviceName; fall back to the first EBS mapping."""
    mappings = instance.get("BlockDeviceMappings", [])
    if not mappings:
        return ""

    root_device_name = instance.get("RootDeviceName")
    if root_device_name:
        for mapping in mappings:
            if mapping.get("DeviceName") == root_device_name:
                return str(mapping.get("Ebs", {}).get("VolumeId", ""))

    return str(mappings[0].get("Ebs", {}).get("VolumeId", ""))
