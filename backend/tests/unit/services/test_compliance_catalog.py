import pytest

from app.services.compliance_catalog import get_aws_catalog, get_catalog_for_framework


@pytest.mark.unit
class TestGetAwsCatalog:
    def test_loads_the_full_aws_framework_set(self):
        catalog = get_aws_catalog()
        assert len(catalog) >= 40  # 45 at the time of writing; tolerant of Prowler version drift

    def test_known_multi_version_framework_slug_present(self):
        catalog = get_aws_catalog()
        assert "CIS-7.0" in catalog
        assert len(catalog["CIS-7.0"]) > 0

    def test_requirement_control_id_matches_framework_mapping_convention(self):
        catalog = get_aws_catalog()
        cis = catalog["CIS-7.0"]
        first = cis[0]
        assert first.control_id
        assert first.name
        assert first.section_key
        assert first.section_label

    def test_cis_requirement_uses_its_own_section_attribute(self):
        catalog = get_aws_catalog()
        cis = catalog["CIS-7.0"]
        req = next(r for r in cis if r.control_id == "2.1.1")
        # CIS ships an explicit Attributes[0].Section — must not fall back to derive_section's heuristic.
        assert "Identity and Access Management" in req.section_label

    def test_mitre_requirement_without_section_attribute_falls_back_to_derive_section(self):
        catalog = get_aws_catalog()
        mitre = catalog.get("MITRE-ATTACK")
        assert mitre is not None
        req = mitre[0]
        # Mitre_Requirement has no Section/SubSection — must still get a usable (key, label).
        assert req.section_key
        assert req.section_label


@pytest.mark.unit
class TestGetCatalogForFramework:
    def test_known_framework_returns_requirements(self):
        assert get_catalog_for_framework("CIS-7.0") is not None

    def test_unknown_framework_returns_none(self):
        assert get_catalog_for_framework("NOT-A-REAL-FRAMEWORK") is None
