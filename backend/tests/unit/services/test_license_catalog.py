import pytest

from app.services.license_catalog import categorize_license, is_deprecated_license


@pytest.mark.unit
class TestCategorizeLicense:
    @pytest.mark.parametrize(
        "license_id,expected",
        [
            ("MIT", "permissive"),
            ("Apache-2.0", "permissive"),
            ("BSD-3-Clause", "permissive"),
            ("MPL-2.0", "weak_copyleft"),
            ("LGPL-2.1-only", "weak_copyleft"),
            ("GPL-3.0-only", "copyleft"),
            ("AGPL-3.0-or-later", "copyleft"),
            ("SomeMadeUpLicense-1.0", "unknown"),
        ],
    )
    def test_known_ids_map_to_expected_category(self, license_id, expected):
        assert categorize_license(license_id) == expected

    def test_deprecated_bare_gpl_id_still_categorizes(self):
        assert categorize_license("GPL-2.0") == "copyleft"

    def test_deprecated_bare_lgpl_id_still_categorizes(self):
        assert categorize_license("LGPL-2.1") == "weak_copyleft"


@pytest.mark.unit
class TestIsDeprecatedLicense:
    def test_bare_gpl_ids_are_deprecated(self):
        assert is_deprecated_license("GPL-2.0") is True

    def test_suffixed_variant_is_not_deprecated(self):
        assert is_deprecated_license("GPL-2.0-only") is False

    def test_permissive_license_is_not_deprecated(self):
        assert is_deprecated_license("MIT") is False
