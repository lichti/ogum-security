import pytest

from app.services.compliance_frameworks import derive_section, resolve_family


@pytest.mark.unit
class TestResolveFamily:
    def test_known_multi_version_framework_resolves_to_shared_family(self):
        f1 = resolve_family("CIS-1.4")
        f2 = resolve_family("CIS-7.0")
        assert f1[0] == f2[0] == "cis-aws"
        assert f1[1] == f2[1] == "CIS AWS Foundations Benchmark"
        assert f1[2] == "1.4"
        assert f2[2] == "7.0"

    def test_nist_800_53_revisions_share_a_family(self):
        rev4 = resolve_family("NIST-800-53-Revision-4")
        rev5 = resolve_family("NIST-800-53-Revision-5")
        assert rev4[0] == rev5[0] == "nist-800-53"
        assert rev4[2] == "Revision 4"
        assert rev5[2] == "Revision 5"

    def test_kisa_english_and_korean_share_a_family(self):
        en = resolve_family("KISA-ISMS-P-2023")
        ko = resolve_family("KISA-ISMS-P-2023-korean")
        assert en[0] == ko[0] == "kisa-isms-p"

    def test_unmapped_single_version_framework_falls_back_gracefully(self):
        family_key, label, version = resolve_family("SOC2")
        assert family_key == "SOC2"
        assert label == "SOC 2"
        assert version == ""

    def test_completely_unknown_slug_is_humanized_not_dropped(self):
        family_key, label, version = resolve_family("SOME-FUTURE-FRAMEWORK-9.0")
        assert family_key == "SOME-FUTURE-FRAMEWORK-9.0"
        assert label == "SOME FUTURE FRAMEWORK 9.0"
        assert version == ""


@pytest.mark.unit
class TestDeriveSection:
    def test_nist_800_53_control_maps_to_known_family_code(self):
        key, label = derive_section("ac_3_3_b_4", "nist-800-53")
        assert key == "ac"
        assert "Access Control" in label

    def test_dot_separated_control_groups_by_first_segment(self):
        key, label = derive_section("1.1", "cis-aws")
        assert key == "1"
        assert label == "Section 1"

    def test_iso27001_annex_control_groups_by_annex_letter(self):
        key, label = derive_section("A.8.22", "iso27001")
        assert key == "a"
        assert label == "Section A"

    def test_missing_control_id_falls_back_to_general(self):
        key, label = derive_section(None, "soc2")
        assert key == "general"
        assert label == "General"

    def test_unrecognized_nist_family_code_falls_back_to_generic_split(self):
        key, label = derive_section("zz_1_2", "nist-800-53")
        assert key == "zz"
        assert label == "Section ZZ"
