"""Unit tests for resolve_ec2_scan_metadata (AZ + root volume lookup via describe_instances)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from app.services.side_scanning.ec2_metadata import resolve_ec2_scan_metadata


def _paginated_client(reservations: list[dict[str, Any]]) -> MagicMock:
    client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Reservations": reservations}]
    client.get_paginator.return_value = paginator
    return client


class TestResolveEc2ScanMetadata:
    def test_returns_empty_dict_for_no_instance_ids(self) -> None:
        client = _paginated_client([])
        assert resolve_ec2_scan_metadata(client, []) == {}
        client.get_paginator.assert_not_called()

    def test_extracts_az_and_root_volume_via_root_device_name(self) -> None:
        reservations = [
            {
                "Instances": [
                    {
                        "InstanceId": "i-0123456789abcdef0",
                        "Placement": {"AvailabilityZone": "us-east-1a"},
                        "RootDeviceName": "/dev/xvda",
                        "BlockDeviceMappings": [
                            {"DeviceName": "/dev/xvdb", "Ebs": {"VolumeId": "vol-secondary"}},
                            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-root"}},
                        ],
                    }
                ]
            }
        ]
        client = _paginated_client(reservations)

        result = resolve_ec2_scan_metadata(client, ["i-0123456789abcdef0"])

        assert result == {"i-0123456789abcdef0": {"availability_zone": "us-east-1a", "volume_id": "vol-root"}}

    def test_falls_back_to_first_mapping_when_root_device_name_missing(self) -> None:
        reservations = [
            {
                "Instances": [
                    {
                        "InstanceId": "i-fallback",
                        "Placement": {"AvailabilityZone": "us-west-2b"},
                        "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"VolumeId": "vol-only"}}],
                    }
                ]
            }
        ]
        client = _paginated_client(reservations)

        result = resolve_ec2_scan_metadata(client, ["i-fallback"])

        assert result["i-fallback"]["volume_id"] == "vol-only"

    def test_omits_instance_with_no_block_device_mappings(self) -> None:
        reservations = [
            {
                "Instances": [
                    {
                        "InstanceId": "i-novolume",
                        "Placement": {"AvailabilityZone": "us-east-1a"},
                        "BlockDeviceMappings": [],
                    }
                ]
            }
        ]
        client = _paginated_client(reservations)

        result = resolve_ec2_scan_metadata(client, ["i-novolume"])

        assert result == {}

    def test_multiple_instances_across_pages(self) -> None:
        pages = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-first",
                                "Placement": {"AvailabilityZone": "us-east-1a"},
                                "RootDeviceName": "/dev/xvda",
                                "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1"}}],
                            }
                        ]
                    }
                ]
            },
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-second",
                                "Placement": {"AvailabilityZone": "us-east-1b"},
                                "RootDeviceName": "/dev/xvda",
                                "BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-2"}}],
                            }
                        ]
                    }
                ]
            },
        ]
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = pages
        client.get_paginator.return_value = paginator

        result = resolve_ec2_scan_metadata(client, ["i-first", "i-second"])

        assert set(result.keys()) == {"i-first", "i-second"}
        assert result["i-first"]["volume_id"] == "vol-1"
        assert result["i-second"]["volume_id"] == "vol-2"
