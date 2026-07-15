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
            section_attr = getattr(attrs, "Section", None) if attrs else None
            subsection_attr = getattr(attrs, "SubSection", None) if attrs else None

            if section_attr:
                section_key, section_label = _slugify(section_attr), section_attr
            else:
                section_key, section_label = derive_section(req.Id, family_key)

            requirements.append(
                CatalogRequirement(
                    control_id=req.Id,
                    name=getattr(req, "Name", None) or req.Id,
                    description=req.Description or "",
                    section_key=section_key,
                    section_label=section_label,
                    subsection_key=_slugify(subsection_attr) if subsection_attr else None,
                    subsection_label=subsection_attr,
                )
            )

        catalog[slug] = requirements

    return catalog


def get_catalog_for_framework(raw_slug: str) -> list[CatalogRequirement] | None:
    """Catalog requirements for one framework slug, or None if unavailable (non-AWS)."""
    return get_aws_catalog().get(raw_slug)
