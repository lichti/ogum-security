from __future__ import annotations

from typing import Any

from arango.database import StandardDatabase

from app.models.api_responses import ResourceDetail
from app.models.software_inventory import SoftwareInventoryResponse, SoftwareLicense, SoftwarePackage
from app.services.license_catalog import categorize_license, is_deprecated_license

_TRIVY_FILEPATH_PROPERTY = "aquasecurity:trivy:FilePath"


def _get_sbom(db: StandardDatabase, resource_key: str) -> dict[str, Any] | None:
    if not db.has_collection("HAS_SBOM") or not db.has_collection("sboms"):
        return None
    cursor = db.aql.execute(
        "FOR v IN 1 OUTBOUND @from HAS_SBOM RETURN v",
        bind_vars={"from": f"resources/{resource_key}"},
    )
    return next(iter(cursor), None)


def _cves_by_package(db: StandardDatabase, tenant_id: str, resource_id: str) -> dict[str, list[str]]:
    if not db.has_collection("findings"):
        return {}
    cursor = db.aql.execute(
        "FOR f IN findings "
        "FILTER f.tenant_id == @tenant_id AND f.resource_id == @resource_id "
        'FILTER f.source == "side_scanning" AND f.status == "FAIL" '
        'FILTER STARTS_WITH(f.check_id, "side_scanning/cve/") '
        "COLLECT package = f.raw_output.package INTO cve_ids = f.check_id "
        "RETURN {package, cve_ids}",
        bind_vars={"tenant_id": tenant_id, "resource_id": resource_id},
    )
    return {row["package"]: [cve.rsplit("/", 1)[-1] for cve in row["cve_ids"]] for row in cursor if row["package"]}


def _extract_filesystem_path(component: dict[str, Any]) -> str | None:
    for prop in component.get("properties", []) or []:
        if prop.get("name") == _TRIVY_FILEPATH_PROPERTY:
            value = prop.get("value")
            return str(value) if value is not None else None
    return None


def _extract_license_ids(component: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for entry in component.get("licenses", []) or []:
        license_obj = entry.get("license")
        if license_obj:
            license_id = license_obj.get("id") or license_obj.get("name")
            if license_id:
                ids.append(license_id)
        elif entry.get("expression"):
            # Best-effort: "MIT OR Apache-2.0" -> ["MIT", "Apache-2.0"] (compound SPDX
            # expressions aren't parsed for AND/WITH operators, just split on the common case).
            ids.extend(part.strip() for part in entry["expression"].replace(" AND ", " OR ").split(" OR "))
    return ids


def get_software_inventory(db: StandardDatabase, tenant_id: str, resource: ResourceDetail) -> SoftwareInventoryResponse:
    sbom = _get_sbom(db, resource.key)
    if not sbom:
        return SoftwareInventoryResponse(resource_key=resource.key)

    cve_by_package = _cves_by_package(db, tenant_id, resource.resource_id)
    components = sbom.get("content", {}).get("components", []) or []

    packages: list[SoftwarePackage] = []
    license_counts: dict[str, int] = {}
    for component in components:
        if component.get("type") != "library":
            continue
        name = component.get("name", "")
        packages.append(
            SoftwarePackage(
                name=name,
                version=component.get("version", ""),
                cve_ids=cve_by_package.get(name, []),
                filesystem_path=_extract_filesystem_path(component),
            )
        )
        for license_id in _extract_license_ids(component):
            license_counts[license_id] = license_counts.get(license_id, 0) + 1

    licenses = [
        SoftwareLicense(
            license_id=license_id,
            category=categorize_license(license_id),
            deprecated=is_deprecated_license(license_id),
            package_count=count,
        )
        for license_id, count in sorted(license_counts.items())
    ]

    return SoftwareInventoryResponse(
        resource_key=resource.key,
        sbom_generated_at=sbom.get("generated_at"),
        installed_packages=packages,
        licenses=licenses,
    )
