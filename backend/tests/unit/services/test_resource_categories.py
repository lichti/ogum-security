"""Unit tests for resource_categories.py — parity with frontend/src/lib/inventoryCategories.ts."""

from __future__ import annotations

import pytest

from app.services.resource_categories import category_of, resource_types_for_category


@pytest.mark.unit
class TestCategoryOf:
    @pytest.mark.parametrize(
        ("resource_type", "expected"),
        [
            ("ec2_instance", "compute"),
            ("virtual_machine", "compute"),
            ("lambda_function", "compute"),
            ("eks_cluster", "containers"),
            ("pod", "containers"),
            ("gcs_bucket", "storage"),
            ("storage_account", "storage"),
            ("rds_instance", "database"),
            ("vpc", "networking"),
            ("security_group", "networking"),
            ("kms_key", "security_identity"),
            ("key_vault", "security_identity"),
        ],
    )
    def test_known_types_map_to_expected_category(self, resource_type: str, expected: str) -> None:
        assert category_of(resource_type) == expected

    def test_unknown_type_falls_back_to_other(self) -> None:
        assert category_of("some_future_resource_type") == "other"

    def test_none_falls_back_to_other(self) -> None:
        assert category_of(None) == "other"

    def test_empty_string_falls_back_to_other(self) -> None:
        assert category_of("") == "other"


@pytest.mark.unit
class TestResourceTypesForCategory:
    def test_returns_types_for_known_category(self) -> None:
        types = resource_types_for_category("database")
        assert "rds_instance" in types

    def test_returns_empty_list_for_unknown_category(self) -> None:
        assert resource_types_for_category("not_a_real_category") == []

    def test_every_returned_type_maps_back_to_the_category(self) -> None:
        for rt in resource_types_for_category("networking"):
            assert category_of(rt) == "networking"
