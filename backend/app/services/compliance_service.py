from __future__ import annotations

from typing import Any

from arango.database import StandardDatabase

from app.services.compliance_frameworks import derive_section, resolve_family

_SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def _score(pass_count: int, fail_count: int) -> float:
    total = pass_count + fail_count
    return round(pass_count / total * 100, 1) if total else 0.0


def _build_families(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group raw (prefix, control, status, count) rows into family -> versions -> sections.

    A single Prowler slug is `{framework_slug}/{control_id}` (or a bare slug with no
    control id for Checkov/IaC mappings). Grouping directly on the raw string — as the
    previous implementation did — treats every individual control as its own top-level
    "framework", producing thousands of near-duplicate entries instead of a few dozen
    real frameworks. This resolves each raw slug to its framework family + version, and
    each control id to a section within that version, before aggregating counts.
    """
    # raw[prefix][control_or_None] = {"PASS": n, "FAIL": n}
    raw: dict[str, dict[str | None, dict[str, int]]] = {}
    for row in rows:
        prefix = row["prefix"]
        control = row["control"]
        counts = raw.setdefault(prefix, {}).setdefault(control, {"PASS": 0, "FAIL": 0})
        counts[row["status"]] = row["cnt"]

    families: dict[str, dict[str, Any]] = {}

    for prefix, controls in raw.items():
        family_key, family_label, version_label = resolve_family(prefix)

        sections: dict[str, dict[str, Any]] = {}
        version_pass = version_fail = 0

        for control, counts in controls.items():
            p, fa = counts["PASS"], counts["FAIL"]
            version_pass += p
            version_fail += fa

            sec_key, sec_label = derive_section(control, family_key)
            section = sections.setdefault(sec_key, {"key": sec_key, "label": sec_label, "pass": 0, "fail": 0})
            section["pass"] += p
            section["fail"] += fa

        section_list = [
            {**sec, "total": sec["pass"] + sec["fail"], "score": _score(sec["pass"], sec["fail"])}
            for sec in sorted(sections.values(), key=lambda s: s["key"])
        ]

        version_entry = {
            "id": prefix,
            "version_label": version_label,
            "pass": version_pass,
            "fail": version_fail,
            "total": version_pass + version_fail,
            "score": _score(version_pass, version_fail),
            "sections": section_list,
        }

        family = families.setdefault(family_key, {"family": family_key, "label": family_label, "versions": []})
        family["versions"].append(version_entry)

    family_list = list(families.values())
    for family in family_list:
        # Best-effort "latest first": version ids sort lexicographically close enough
        # to semver ordering for the single/double-digit version numbers Prowler ships
        # (Revision-5 > Revision-4, 2.0 > 1.1, 7.0 > 1.4, ...).
        family["versions"].sort(key=lambda v: v["id"], reverse=True)

    family_list.sort(key=lambda f: f["label"])
    return family_list


def get_compliance_summary(db: StandardDatabase, tenant_id: str, framework: str | None = None) -> dict[str, Any]:
    """Framework family scores + a top-failing-controls list.

    `framework` (a raw slug, e.g. "CIS-7.0") scopes `top_failing` to that framework
    version — the family/version/section tree itself is always computed in full so the
    sidebar and version switcher stay populated regardless of the current selection.
    """
    aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status IN ["FAIL", "PASS"]
        FOR fw IN f.framework_mapping
            LET parts = SPLIT(fw, "/", 2)
            COLLECT prefix = parts[0], control = (LENGTH(parts) > 1 ? parts[1] : null), status = f.status
            WITH COUNT INTO cnt
            RETURN {prefix, control, status, cnt}
    """
    rows = list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id}))
    families = _build_families(rows)

    # ThreatScore: weighted by severity of FAIL findings (0–100, inverted) — always global.
    weight_aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status == "FAIL"
        COLLECT severity = f.severity WITH COUNT INTO cnt
        RETURN {severity, cnt}
    """
    sev_rows = list(db.aql.execute(weight_aql, bind_vars={"tenant_id": tenant_id}))
    weighted = sum(_SEVERITY_WEIGHT.get(r["severity"], 0) * r["cnt"] for r in sev_rows)
    # Cap at 200 for normalisation → threat_score in [0, 100]
    threat_score = max(0, 100 - min(weighted, 200) // 2)

    # Top 10 failing checks by count, optionally scoped to one framework version.
    top_filters = ["f.tenant_id == @tenant_id", 'f.status == "FAIL"']
    top_bind: dict[str, Any] = {"tenant_id": tenant_id}
    if framework:
        top_filters.append(
            "LENGTH(FOR fw IN f.framework_mapping "
            'FILTER fw == @framework OR STARTS_WITH(fw, CONCAT(@framework, "/")) '
            "RETURN 1) > 0"
        )
        top_bind["framework"] = framework
    top_filter_str = "\n        ".join(f"FILTER {c}" for c in top_filters)

    top_aql = f"""
    FOR f IN findings
        {top_filter_str}
        COLLECT check_id = f.check_id, title = f.title, severity = f.severity
            WITH COUNT INTO cnt
        SORT cnt DESC
        LIMIT 10
        RETURN {{check_id, title, severity, count: cnt}}
    """
    top_failing = list(db.aql.execute(top_aql, bind_vars=top_bind))

    return {
        "families": families,
        "threat_score": threat_score,
        "top_failing": top_failing,
    }
