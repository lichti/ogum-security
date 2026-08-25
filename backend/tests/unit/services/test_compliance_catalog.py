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

    def test_cis_requirement_name_falls_back_to_description_not_raw_id(self):
        # Prowler's CIS JSON never populates Requirement.Name — only Description has a
        # human-readable label. Regression: name used to fall back straight to the raw
        # control_id ("2.1.1"), leaving the accordion row unreadable.
        catalog = get_aws_catalog()
        cis = catalog["CIS-7.0"]
        req = next(r for r in cis if r.control_id == "2.1.1")
        assert req.name != req.control_id
        assert req.name == req.description

    def test_asd_essential_eight_requirement_name_falls_back_to_description(self):
        catalog = get_aws_catalog()
        e8 = next((v for k, v in catalog.items() if k.startswith("ASD-Essential-Eight")), None)
        assert e8 is not None
        req = e8[0]
        assert req.name != req.control_id
        assert req.name == req.description

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

    def test_ccc_groups_by_family_name_not_the_near_unique_section_attribute(self):
        # CCC's raw Attributes[0].Section is "CCC.Core.CN01 Implement Digital
        # Signatures..." — one distinct value per *control* (110 of them for 172
        # requirements), producing an almost-flat list if used directly as the section.
        # FamilyName ("Core", "Access Control", ...) is the real category.
        catalog = get_aws_catalog()
        ccc = catalog.get("CCC-v2025.10")
        assert ccc is not None
        distinct_sections = {r.section_key for r in ccc}
        assert len(distinct_sections) < len(ccc) / 2  # real categories, not per-control noise
        req = ccc[0]
        assert req.section_label not in (None, "")
        assert req.section_label != req.control_id
        # The old per-control Section value is still available, one level down.
        assert req.subsection_label

    def test_kisa_groups_by_domain_and_subdomain_not_the_near_unique_section_attribute(self):
        catalog = get_aws_catalog()
        kisa = catalog.get("KISA-ISMS-P-2023")
        assert kisa is not None
        distinct_sections = {r.section_key for r in kisa}
        distinct_subsections = {r.subsection_key for r in kisa}
        # KISA's raw Section is "1.1.1 Executive Participation" — unique per requirement
        # (101 for 101). Domain/Subdomain give a real 2-level hierarchy instead.
        assert len(distinct_sections) < 10
        assert 1 < len(distinct_subsections) < len(kisa)

    def test_pci_4_0_groups_by_id_prefix_not_the_near_unique_section_attribute(self):
        # PCI-4.0's raw Attributes[0].Section is "1.2.5: Network security controls
        # (NSCs) are configured and maintained." — 107 distinct values for 1669
        # requirements, SubSection always empty. Unlike CCC/KISA there's no better
        # native field, so this falls back to the generic ID-based split, which lines
        # up with PCI's 12 official Requirements + 2 Appendix sections (13 groups).
        catalog = get_aws_catalog()
        pci4 = catalog.get("PCI-4.0")
        assert pci4 is not None
        distinct_sections = {r.section_key for r in pci4}
        assert len(distinct_sections) <= 15
        req = next(r for r in pci4 if r.control_id == "1.2.5.1")
        assert req.section_label == "Section 1"
        # The noisy raw Section value isn't discarded — it becomes the subsection.
        assert req.subsection_label and req.subsection_label.startswith("1.2.5")

    def test_pci_3_2_1_keeps_its_own_genuine_section_attribute(self):
        # Regression guard: PCI-3.2.1's Section ("Requirement 1: Install and
        # maintain...") is a real multi-control category — must not be caught by the
        # PCI-4.0-specific fallback.
        catalog = get_aws_catalog()
        pci3 = catalog.get("PCI-3.2.1")
        assert pci3 is not None
        req = next(r for r in pci3 if r.control_id == "1.1")
        assert req.section_label.startswith("Requirement 1")


@pytest.mark.unit
class TestGetCatalogForFramework:
    def test_known_framework_returns_requirements(self):
        assert get_catalog_for_framework("CIS-7.0") is not None

    def test_unknown_framework_returns_none(self):
        assert get_catalog_for_framework("NOT-A-REAL-FRAMEWORK") is None
