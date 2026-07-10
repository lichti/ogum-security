"""Framework identity resolution for the Compliance page.

Prowler tags every check with `{framework_slug}/{control_id}` for every
compliance framework it happens to satisfy (regardless of which framework
the user selected when triggering the scan) — a single AWS account scan
routinely touches 40+ raw framework slugs. Several of those slugs are just
different *versions* of the same underlying framework (CIS AWS Foundations
Benchmark ships 8 separate version slugs, NIST 800-53 has two, etc.).

This module resolves a raw slug to a stable (family, label, version) tuple
so the UI can show one navigable entry per real-world framework, with a
version switcher instead of N near-duplicate top-level cards.
"""

from __future__ import annotations

# raw Prowler slug -> (family key, family display label, version label)
FRAMEWORK_FAMILIES: dict[str, tuple[str, str, str]] = {
    # CIS AWS Foundations Benchmark — 8 versions
    "CIS-1.4": ("cis-aws", "CIS AWS Foundations Benchmark", "1.4"),
    "CIS-1.5": ("cis-aws", "CIS AWS Foundations Benchmark", "1.5"),
    "CIS-2.0": ("cis-aws", "CIS AWS Foundations Benchmark", "2.0"),
    "CIS-3.0": ("cis-aws", "CIS AWS Foundations Benchmark", "3.0"),
    "CIS-4.0.1": ("cis-aws", "CIS AWS Foundations Benchmark", "4.0.1"),
    "CIS-5.0": ("cis-aws", "CIS AWS Foundations Benchmark", "5.0"),
    "CIS-6.0": ("cis-aws", "CIS AWS Foundations Benchmark", "6.0"),
    "CIS-7.0": ("cis-aws", "CIS AWS Foundations Benchmark", "7.0"),
    # CIS other providers (not seen in AWS-only data yet, mapped defensively)
    "CIS-AZURE-2.0": ("cis-azure", "CIS Microsoft Azure Foundations Benchmark", "2.0"),
    "CIS-AZURE-3.0": ("cis-azure", "CIS Microsoft Azure Foundations Benchmark", "3.0"),
    "CIS-AZURE-4.0": ("cis-azure", "CIS Microsoft Azure Foundations Benchmark", "4.0"),
    "CIS-GCP-2.0": ("cis-gcp", "CIS Google Cloud Platform Foundation Benchmark", "2.0"),
    "CIS-GCP-3.0": ("cis-gcp", "CIS Google Cloud Platform Foundation Benchmark", "3.0"),
    "CIS-GCP-4.0": ("cis-gcp", "CIS Google Cloud Platform Foundation Benchmark", "4.0"),
    "CIS-K8S-1.10": ("cis-k8s", "CIS Kubernetes Benchmark", "1.10"),
    "CIS-K8S-1.12": ("cis-k8s", "CIS Kubernetes Benchmark", "1.12"),
    "CIS-K8S-2.0": ("cis-k8s", "CIS Kubernetes Benchmark", "2.0"),
    # NIST 800-53 — 2 revisions
    "NIST-800-53-Revision-4": ("nist-800-53", "NIST 800-53", "Revision 4"),
    "NIST-800-53-Revision-5": ("nist-800-53", "NIST 800-53", "Revision 5"),
    # NIST Cybersecurity Framework — 2 versions
    "NIST-CSF-1.1": ("nist-csf", "NIST Cybersecurity Framework", "1.1"),
    "NIST-CSF-2.0": ("nist-csf", "NIST Cybersecurity Framework", "2.0"),
    "NIST-800-171-Revision-2": ("nist-800-171", "NIST 800-171", "Revision 2"),
    # ISO/IEC 27001 — 2 editions
    "ISO27001-2013": ("iso27001", "ISO/IEC 27001", "2013"),
    "ISO27001-2022": ("iso27001", "ISO/IEC 27001", "2022"),
    # PCI DSS — 2 versions
    "PCI-3.2.1": ("pci-dss", "PCI DSS", "3.2.1"),
    "PCI-4.0": ("pci-dss", "PCI DSS", "4.0"),
    # KISA ISMS-P — same content, English + Korean-labelled slugs
    "KISA-ISMS-P-2023": ("kisa-isms-p", "KISA ISMS-P", "2023"),
    "KISA-ISMS-P-2023-korean": ("kisa-isms-p", "KISA ISMS-P", "2023 (한국어)"),
    # FedRAMP family — 3 profiles
    "FedRAMP-Low-Revision-4": ("fedramp", "FedRAMP", "Low, Rev 4"),
    "FedRamp-Moderate-Revision-4": ("fedramp", "FedRAMP", "Moderate, Rev 4"),
    "FedRAMP-20x-KSI-Low-25.05C": ("fedramp", "FedRAMP", "20x KSI Low, 25.05C"),
}

# Curated display labels for single-version frameworks whose raw slug isn't
# already readable. Anything not listed here falls back to a humanized
# version of the slug (hyphens -> spaces, title case).
_SINGLE_VERSION_LABELS: dict[str, str] = {
    "SOC2": "SOC 2",
    "HIPAA": "HIPAA",
    "GDPR": "GDPR",
    "NIS2": "NIS2 Directive",
    "FFIEC": "FFIEC",
    "CISA": "CISA Cyber Essentials",
    "C5-2025": "BSI Cloud Computing Compliance Criteria Catalogue (C5)",
    "CCC-v2025.10": "Cloud Controls Catalogue (CCC)",
    "MITRE-ATTACK": "MITRE ATT&CK",
    "ENS-RD2022": "ENS — Esquema Nacional de Seguridad",
    "SecNumCloud-3.2": "SecNumCloud",
    "GxP-21-CFR-Part-11": "GxP 21 CFR Part 11",
    "GxP-EU-Annex-11": "GxP EU Annex 11",
    "ProwlerThreatScore-1.0": "Prowler ThreatScore",
    "RBI-Cyber-Security-Framework": "RBI Cyber Security Framework",
    "ASD-Essential-Eight-Nov 2023": "ASD Essential Eight",
    "AWS-Well-Architected-Framework-Security-Pillar": "AWS Well-Architected — Security Pillar",
    "AWS-Well-Architected-Framework-Reliability-Pillar": "AWS Well-Architected — Reliability Pillar",
    "AWS-AI-Security-Framework-1.0": "AWS AI Security Framework",
    "AWS-Foundational-Security-Best-Practices": "AWS Foundational Security Best Practices",
    "AWS-Foundational-Technical-Review": "AWS Foundational Technical Review",
    "AWS-Account-Security-Onboarding": "AWS Account Security Onboarding",
    "AWS-Audit-Manager-Control-Tower-Guardrails": "AWS Audit Manager — Control Tower Guardrails",
}


def _humanize(slug: str) -> str:
    return slug.replace("-", " ").replace("_", " ").strip()


def resolve_family(prefix: str) -> tuple[str, str, str]:
    """Return (family_key, family_label, version_label) for a raw framework slug."""
    if prefix in FRAMEWORK_FAMILIES:
        return FRAMEWORK_FAMILIES[prefix]
    label = _SINGLE_VERSION_LABELS.get(prefix, _humanize(prefix))
    return prefix, label, ""


# NIST 800-53 control family codes (standard, both Rev 4 and Rev 5)
_NIST_800_53_FAMILIES: dict[str, str] = {
    "ac": "Access Control",
    "at": "Awareness and Training",
    "au": "Audit and Accountability",
    "ca": "Assessment, Authorization, and Monitoring",
    "cm": "Configuration Management",
    "cp": "Contingency Planning",
    "ia": "Identification and Authentication",
    "ir": "Incident Response",
    "ma": "Maintenance",
    "mp": "Media Protection",
    "pe": "Physical and Environmental Protection",
    "pl": "Planning",
    "pm": "Program Management",
    "ps": "Personnel Security",
    "pt": "PII Processing and Transparency",
    "ra": "Risk Assessment",
    "sa": "System and Services Acquisition",
    "sc": "System and Communications Protection",
    "si": "System and Information Integrity",
    "sr": "Supply Chain Risk Management",
}


def derive_section(control_id: str | None, family_key: str) -> tuple[str, str]:
    """Return (section_key, section_label) grouping controls within a framework version.

    Best-effort, generic heuristic since we only store the flat control id string:
    - NIST 800-53 controls (e.g. "ac_3_3_b_4") use the standard 2-letter family code.
    - Dot-separated hierarchical numbering (CIS "1.1", ISO27001 "A.8.22") groups by
      the first segment.
    - Underscore/dash-separated ids group by their first segment.
    - No control id (bare framework findings, e.g. Checkov IaC mappings) -> "General".
    """
    if not control_id:
        return "general", "General"

    if family_key == "nist-800-53" and "_" in control_id:
        code = control_id.split("_")[0].lower()
        if code in _NIST_800_53_FAMILIES:
            return code, f"{code.upper()} — {_NIST_800_53_FAMILIES[code]}"

    for sep in (".", "_", "-"):
        if sep in control_id:
            head = control_id.split(sep)[0]
            key = head.lower()
            label = f"Section {head.upper()}" if not head.isdigit() else f"Section {head}"
            return key, label

    return "general", "General"
