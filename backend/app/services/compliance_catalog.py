"""AWS compliance framework catalog, sourced from the `prowler` package.

Prowler ships one JSON file per compliance framework (`prowler/compliance/aws/*.json`)
listing every requirement it defines, independent of whether any of them have ever
produced a finding for a given tenant. This module loads that catalog through
Prowler's own `Compliance.get_bulk()` API rather than parsing the JSON files directly
or vendoring copies of them — Prowler stays the single source of truth for AWS
compliance data (see decision #14), and any Prowler version bump picks up catalog
changes automatically.

The slug computed here (`f"{Framework}-{Version}"` or just `Framework`) is the exact
same value Prowler embeds as the framework prefix in `Finding.framework_mapping`
(`"{slug}/{control_id}"`) — verified against `prowler/lib/outputs/compliance/
compliance_check.py::get_check_compliance`, which builds `framework_mapping` from this
same `Framework`/`Version` pair. `resolve_family()` in `compliance_frameworks.py`
already resolves this slug for every framework family the UI knows about.

Scope: AWS only. Azure/GCP/Kubernetes use their own discovery pipelines, not Prowler
(decision #14 is AWS-specific) — the catalog (and therefore the `Unscored` control
state) is unavailable for non-AWS frameworks. Callers must treat a `None` return from
`get_catalog_for_framework()` as "catalog not available", not "framework has zero
controls".
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from app.services.compliance_frameworks import derive_section, resolve_family


@dataclass(frozen=True)
class CatalogRequirement:
    control_id: str
    name: str
    description: str
    section_key: str
    section_label: str
    subsection_key: str | None
    subsection_label: str | None


def _slugify(label: str) -> str:
    return label.strip().lower().replace(" ", "-")


# Framework slugs where `Attributes[0].Section` is verified (by direct inspection of
# the loaded catalog) to be a near-unique per-*control* sentence rather than a real
# category, with `SubSection` always empty — using it as-is produces a huge, flat,
# effectively un-navigable top-level list. PCI-4.0: 107 distinct Section values for
# 1669 requirements (e.g. "1.2.5: Network security controls (NSCs) are configured and
# maintained."). Not a generic count/ratio threshold: AWS FSBP has 50 distinct Section
# values too, but they're genuine short categories ("ACM", "API Gateway", ...) — a
# blanket heuristic would wrongly reclassify it. Reassess this list if a future Prowler
# release restructures one of these frameworks' Section field.
_DEGENERATE_SECTION_SLUGS = frozenset({"PCI-4.0"})


def _section_and_subsection(
    attrs: object, req_id: str, family_key: str, slug: str
) -> tuple[str, str, str | None, str | None]:
    """(section_key, section_label, subsection_key, subsection_label) for one requirement.

    Most frameworks' `Attributes[0].Section` is a genuine multi-control category (CIS's
    "2 Identity and Access Management" covers dozens of controls) and is used as-is.
    A few frameworks abuse the same field for a per-*control* label instead — CCC's
    `Section` is literally "CCC.Core.CN01 Implement Digital Signatures..." (one distinct
    value per control, 110 of them for 172 requirements) and KISA's is
    "1.1.1 Executive Participation" (101 distinct values for 101 requirements) — using
    it directly as the grouping key produces an almost-flat, one-bucket-per-control list
    instead of a real hierarchy. Both frameworks carry a proper category elsewhere in
    their Attributes (`FamilyName` / `Domain`+`Subdomain`); prefer those when available.
    PCI-4.0 (`_DEGENERATE_SECTION_SLUGS`) has the same shape of problem but no better
    native field — its ID structure ("1.2.5.1") already encodes PCI's 12 official
    Requirements as the first dot-segment, so it falls back to the generic ID-based
    split, with the noisy raw Section demoted to subsection instead of discarded.
    """
    from prowler.lib.check.compliance_models import (  # noqa: PLC0415 — heavy import, load on first use only
        CCC_Requirement_Attribute,
        KISA_ISMSP_Requirement_Attribute,
    )

    if isinstance(attrs, CCC_Requirement_Attribute) and attrs.FamilyName:
        subsection_attr = getattr(attrs, "Section", None)
        return (
            _slugify(attrs.FamilyName),
            attrs.FamilyName,
            _slugify(subsection_attr) if subsection_attr else None,
            subsection_attr,
        )

    if isinstance(attrs, KISA_ISMSP_Requirement_Attribute) and attrs.Domain:
        subsection_attr = getattr(attrs, "Subdomain", None)
        return (
            _slugify(attrs.Domain),
            attrs.Domain,
            _slugify(subsection_attr) if subsection_attr else None,
            subsection_attr,
        )

    section_attr = getattr(attrs, "Section", None) if attrs else None
    subsection_attr = getattr(attrs, "SubSection", None) if attrs else None

    if section_attr and slug not in _DEGENERATE_SECTION_SLUGS:
        sub_key = _slugify(subsection_attr) if subsection_attr else None
        return _slugify(section_attr), section_attr, sub_key, subsection_attr

    section_key, section_label = derive_section(req_id, family_key)
    if section_attr and not subsection_attr:
        subsection_attr = section_attr
    return section_key, section_label, _slugify(subsection_attr) if subsection_attr else None, subsection_attr


@lru_cache(maxsize=1)
def get_aws_catalog() -> dict[str, list[CatalogRequirement]]:
    """Raw Prowler framework slug -> full list of catalog requirements.

    Cached for the lifetime of the process: `Compliance.get_bulk()` reads and
    validates ~45 JSON files (measured ~1.7s) and the catalog only changes on a
    Prowler version bump, i.e. on deploy — a process restart already invalidates it.
    """
    from prowler.lib.check.compliance_models import Compliance  # noqa: PLC0415 — heavy import, load on first use only

    bulk = Compliance.get_bulk(provider="aws")

    catalog: dict[str, list[CatalogRequirement]] = {}
    for compliance in bulk.values():
        slug = f"{compliance.Framework}-{compliance.Version}" if compliance.Version else compliance.Framework
        family_key, _, _ = resolve_family(slug)

        requirements: list[CatalogRequirement] = []
        for req in compliance.Requirements:
            attrs = req.Attributes[0] if getattr(req, "Attributes", None) else None
            section_key, section_label, subsection_key, subsection_label = _section_and_subsection(
                attrs, req.Id, family_key, slug
            )

            requirements.append(
                CatalogRequirement(
                    control_id=req.Id,
                    # Several Prowler frameworks (CIS, ASD Essential Eight, C5, CCC,
                    # ENS, NIS2, ThreatScore, ...) never populate `Name` — only
                    # `Description` carries a human-readable label there. Falling back
                    # straight to `req.Id` made the accordion show "2.1.1" or "E8-1.1"
                    # as the row's name with the real text buried in the hover tooltip.
                    name=getattr(req, "Name", None) or req.Description or req.Id,
                    description=req.Description or "",
                    section_key=section_key,
                    section_label=section_label,
                    subsection_key=subsection_key,
                    subsection_label=subsection_label,
                )
            )

        catalog[slug] = requirements

    return catalog


def get_catalog_for_framework(raw_slug: str) -> list[CatalogRequirement] | None:
    """Catalog requirements for one framework slug, or None if unavailable (non-AWS)."""
    return get_aws_catalog().get(raw_slug)
