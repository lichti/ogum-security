from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from arango.database import StandardDatabase

from app.services.compliance_catalog import get_catalog_for_framework
from app.services.compliance_frameworks import derive_section, is_known_framework_slug, resolve_family

_SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

_TREND_PERIOD_DAYS = {"7d": 7, "14d": 14, "1m": 30}


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


def _raw_prefix_control_status_rows(db: StandardDatabase, tenant_id: str) -> list[dict[str, Any]]:
    """(prefix, control, status) -> count, across every framework the tenant has findings for.

    Shared by `get_compliance_summary` (asset-level family/version/section tree) and
    `get_all_framework_control_scores` (control-level score, used by the snapshot
    writer) so both read the same single AQL pass over `findings`.
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
    return list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id}))


def get_compliance_summary(db: StandardDatabase, tenant_id: str, framework: str | None = None) -> dict[str, Any]:
    """Framework family scores + a top-failing-controls list.

    `framework` (a raw slug, e.g. "CIS-7.0") scopes `top_failing` to that framework
    version — the family/version/section tree itself is always computed in full so the
    sidebar and version switcher stay populated regardless of the current selection.
    """
    rows = _raw_prefix_control_status_rows(db, tenant_id)
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


def _score_by_control(
    control_status: dict[str, tuple[int, int]],
    catalog_control_ids: set[str] | None,
) -> tuple[float, int, int, int]:
    """Control-level score: a control is Fail if any asset fails it, Pass if only
    passing assets touched it, Unscored if the catalog knows about it but no asset
    has evaluated it yet. Unlike `_score()` (asset/finding-count based), Unscored
    controls are excluded from the denominator — they're neither a pass nor a fail.

    `catalog_control_ids=None` means the catalog is unavailable for this framework
    (non-AWS) — every control is judged solely by whether it has findings.

    Returns (score_by_control, pass_count, fail_count, unscored_count).
    """
    all_ids = set(control_status) | (catalog_control_ids or set())
    pass_count = fail_count = 0
    for control_id in all_ids:
        p, f = control_status.get(control_id, (0, 0))
        if f > 0:
            fail_count += 1
        elif p > 0:
            pass_count += 1
    unscored_count = len(all_ids) - pass_count - fail_count
    denom = pass_count + fail_count
    score = round(pass_count / denom * 100, 1) if denom else 0.0
    return score, pass_count, fail_count, unscored_count


def get_all_framework_control_scores(db: StandardDatabase, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Control-level score for every framework the tenant has findings for.

    One AQL pass total (shared with `get_compliance_summary` via
    `_raw_prefix_control_status_rows`), not one query per framework — this is what
    `snapshot_compliance_scores` calls once per scan.
    """
    rows = _raw_prefix_control_status_rows(db, tenant_id)

    by_prefix: dict[str, dict[str, list[int]]] = {}
    for row in rows:
        control = row["control"]
        if control is None:
            continue  # bare framework findings (e.g. Checkov/IaC) have no control granularity
        counts = by_prefix.setdefault(row["prefix"], {}).setdefault(control, [0, 0])
        counts[0 if row["status"] == "PASS" else 1] += row["cnt"]

    result: dict[str, dict[str, Any]] = {}
    for prefix, control_counts in by_prefix.items():
        control_status = {cid: (c[0], c[1]) for cid, c in control_counts.items()}
        catalog = get_catalog_for_framework(prefix)
        catalog_ids = {r.control_id for r in catalog} if catalog is not None else None
        score, pass_count, fail_count, unscored_count = _score_by_control(control_status, catalog_ids)
        result[prefix] = {
            "score_by_control": score,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "unscored_count": unscored_count,
            "catalog_available": catalog is not None,
        }
    return result


def get_framework_detail(db: StandardDatabase, tenant_id: str, raw_slug: str) -> dict[str, Any] | None:
    """Full detail for one framework version: score duality, Unscored count, and the
    section -> sub-section -> requirement tree (US-14.14/US-14.15/US-14.16).

    Returns None only when `raw_slug` is a genuinely unknown slug — no findings, no
    AWS catalog entry, and no curated label. A real framework with zero findings so
    far (e.g. GDPR before any relevant check has run) still returns a full tree with
    every control Unscored, not a 404.
    """
    aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status IN ["FAIL", "PASS"]
        FOR fw IN f.framework_mapping
            FILTER fw == @raw_slug OR STARTS_WITH(fw, CONCAT(@raw_slug, "/"))
            LET parts = SPLIT(fw, "/", 2)
            RETURN {
                control: (LENGTH(parts) > 1 ? parts[1] : null),
                status: f.status,
                finding_key: f._key,
                severity: f.severity,
            }
    """
    rows = list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id, "raw_slug": raw_slug}))

    catalog = get_catalog_for_framework(raw_slug)
    catalog_available = catalog is not None
    if not rows and not catalog_available and not is_known_framework_slug(raw_slug):
        return None

    family_key, family_label, version_label = resolve_family(raw_slug)

    per_control: dict[str, dict[str, Any]] = {}
    bare_pass = bare_fail = 0
    for row in rows:
        control = row["control"]
        if control is None:
            if row["status"] == "PASS":
                bare_pass += 1
            else:
                bare_fail += 1
            continue
        entry = per_control.setdefault(
            control, {"pass": 0, "fail": 0, "fail_key": None, "fail_weight": -1, "pass_key": None}
        )
        if row["status"] == "FAIL":
            entry["fail"] += 1
            weight = _SEVERITY_WEIGHT.get(row["severity"], 0)
            if weight > entry["fail_weight"]:
                entry["fail_weight"] = weight
                entry["fail_key"] = row["finding_key"]
        else:
            entry["pass"] += 1
            if entry["pass_key"] is None:
                entry["pass_key"] = row["finding_key"]

    catalog_by_id = {r.control_id: r for r in (catalog or [])}
    all_control_ids = set(per_control) | set(catalog_by_id)

    control_status = {
        cid: (per_control.get(cid, {}).get("pass", 0), per_control.get(cid, {}).get("fail", 0))
        for cid in all_control_ids
    }
    catalog_ids = set(catalog_by_id) if catalog_available else None
    score_by_control, pass_count, fail_count, unscored_count = _score_by_control(control_status, catalog_ids)

    asset_pass = sum(e["pass"] for e in per_control.values()) + bare_pass
    asset_fail = sum(e["fail"] for e in per_control.values()) + bare_fail
    score_by_asset = _score(asset_pass, asset_fail)

    # section_key -> {label, requirements: [...], subsections: {sub_key -> {label, requirements: [...]}}}
    sections: dict[str, dict[str, Any]] = {}
    for control_id in all_control_ids:
        found = per_control.get(control_id)
        cat = catalog_by_id.get(control_id)
        if cat is not None:
            sec_key, sec_label = cat.section_key, cat.section_label
            sub_key, sub_label = cat.subsection_key, cat.subsection_label
            name, description = cat.name, cat.description
        else:
            sec_key, sec_label = derive_section(control_id, family_key)
            sub_key, sub_label = None, None
            name, description = control_id, None

        if found and found["fail"] > 0:
            status, finding_key = "FAIL", found["fail_key"]
        elif found and found["pass"] > 0:
            status, finding_key = "PASS", found["pass_key"]
        else:
            status, finding_key = "UNSCORED", None

        requirement = {
            "control_id": control_id,
            "name": name,
            "description": description,
            "status": status,
            "finding_key": finding_key,
            "pass_count": found["pass"] if found else 0,
            "fail_count": found["fail"] if found else 0,
        }

        section = sections.setdefault(sec_key, {"label": sec_label, "requirements": [], "subsections": {}})
        if sub_key:
            subsection = section["subsections"].setdefault(sub_key, {"label": sub_label, "requirements": []})
            subsection["requirements"].append(requirement)
        else:
            section["requirements"].append(requirement)

    def _rollup(requirements: list[dict[str, Any]]) -> tuple[int, int, int, int, float]:
        p = sum(1 for r in requirements if r["status"] == "PASS")
        f = sum(1 for r in requirements if r["status"] == "FAIL")
        u = sum(1 for r in requirements if r["status"] == "UNSCORED")
        total = len(requirements)
        return p, f, u, total, _score(p, f)

    section_list = []
    for sec_key, sec in sorted(sections.items()):
        subsection_list = []
        all_requirements = list(sec["requirements"])
        for sub_key, sub in sorted(sec["subsections"].items()):
            p, f, u, total, score = _rollup(sub["requirements"])
            subsection_list.append(
                {
                    "key": sub_key,
                    "label": sub["label"],
                    "pass_count": p,
                    "fail_count": f,
                    "unscored_count": u,
                    "total": total,
                    "score_by_control": score,
                    "subsections": [],
                    "requirements": sub["requirements"],
                }
            )
            all_requirements.extend(sub["requirements"])
        p, f, u, total, score = _rollup(all_requirements)
        section_list.append(
            {
                "key": sec_key,
                "label": sec["label"],
                "pass_count": p,
                "fail_count": f,
                "unscored_count": u,
                "total": total,
                "score_by_control": score,
                "subsections": subsection_list,
                "requirements": sec["requirements"],
            }
        )

    return {
        "id": raw_slug,
        "family": family_key,
        "family_label": family_label,
        "version_label": version_label,
        "score_by_control": score_by_control,
        "score_by_asset": score_by_asset,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "unscored_count": unscored_count,
        "total_controls": len(all_control_ids),
        "catalog_available": catalog_available,
        "sections": section_list,
    }


def snapshot_compliance_scores(db: StandardDatabase, tenant_id: str) -> int:
    """Upsert one score snapshot per framework the tenant has findings for, keyed by
    (tenant, framework, day) — running this twice on the same day overwrites, not
    duplicates. Called at the end of every CSPM scan (`run_cspm_scan`); there is no
    backfill, so `/trend` starts empty and grows one point per scan day.

    Returns the number of framework snapshots written.
    """
    control_scores = get_all_framework_control_scores(db, tenant_id)
    summary = get_compliance_summary(db, tenant_id)
    asset_versions = {version["id"]: version for family in summary["families"] for version in family["versions"]}

    snapshot_date = datetime.now(UTC).date().isoformat()
    now = datetime.now(UTC).isoformat()
    collection = db.collection("compliance_score_snapshots")

    count = 0
    for prefix in set(control_scores) | set(asset_versions):
        ctrl = control_scores.get(prefix)
        asset = asset_versions.get(prefix)
        score_by_asset = asset["score"] if asset else 0.0
        doc = {
            "_key": hashlib.sha256(f"{tenant_id}|{prefix}|{snapshot_date}".encode()).hexdigest(),
            "tenant_id": tenant_id,
            "framework_id": prefix,
            "snapshot_date": snapshot_date,
            "score_by_control": ctrl["score_by_control"] if ctrl else score_by_asset,
            "score_by_asset": score_by_asset,
            "pass_count": ctrl["pass_count"] if ctrl else (asset["pass"] if asset else 0),
            "fail_count": ctrl["fail_count"] if ctrl else (asset["fail"] if asset else 0),
            "unscored_count": ctrl["unscored_count"] if ctrl else 0,
            "created_at": now,
        }
        collection.insert(doc, overwrite=True)
        count += 1
    return count


def get_score_trend(db: StandardDatabase, tenant_id: str, raw_slug: str, period: str) -> list[dict[str, Any]]:
    """Daily score history for one framework, from `compliance_score_snapshots`."""
    days = _TREND_PERIOD_DAYS[period]
    since = (datetime.now(UTC) - timedelta(days=days)).date().isoformat()
    aql = """
    FOR s IN compliance_score_snapshots
        FILTER s.tenant_id == @tenant_id AND s.framework_id == @framework_id AND s.snapshot_date >= @since
        SORT s.snapshot_date ASC
        RETURN {
            date: s.snapshot_date,
            score_by_control: s.score_by_control,
            score_by_asset: s.score_by_asset,
            pass_count: s.pass_count,
            fail_count: s.fail_count,
            unscored_count: s.unscored_count,
        }
    """
    return list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id, "framework_id": raw_slug, "since": since}))
