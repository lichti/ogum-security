from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from arango.database import StandardDatabase

from app.models.settings import ComplianceFamilySettings
from app.services.compliance_catalog import get_catalog_for_framework
from app.services.compliance_frameworks import derive_section, is_known_framework_slug, natural_sort_key, resolve_family
from app.services.settings_service import get_all_compliance_family_settings

_SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

_TREND_PERIOD_DAYS = {"7d": 7, "14d": 14, "1m": 30}


def _score(pass_count: int, fail_count: int) -> float:
    """Plain Pass/(Pass+Fail) ratio — used where there's no Unscored bucket to fold in
    (the numerator already includes it where relevant, e.g. `_rollup`'s
    `score_by_control` call passes `control_pass + control_unscored` as `pass_count`)."""
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

    `pass`/`fail`/`total`/`score` here are a plain finding tally (ACCEPTED folded into
    Pass, MUTED ignored) — a last-resort fallback used only for bare-mapping
    frameworks with no control granularity at all (e.g. some Checkov/IaC slugs).
    `get_compliance_summary` overwrites every other version's score with the real By
    Control score right after calling this function.
    """
    # raw[prefix][control_or_None] = {"PASS": n, "FAIL": n, "ACCEPTED": n}
    raw: dict[str, dict[str | None, dict[str, int]]] = {}
    for row in rows:
        if row["status"] not in ("PASS", "FAIL", "ACCEPTED"):
            continue
        prefix = row["prefix"]
        control = row["control"]
        counts = raw.setdefault(prefix, {}).setdefault(control, {"PASS": 0, "FAIL": 0, "ACCEPTED": 0})
        counts[row["status"]] = row["cnt"]

    families: dict[str, dict[str, Any]] = {}

    for prefix, controls in raw.items():
        family_key, family_label, version_label = resolve_family(prefix)

        sections: dict[str, dict[str, Any]] = {}
        version_pass = version_fail = 0

        for control, counts in controls.items():
            p, fa = counts["PASS"] + counts["ACCEPTED"], counts["FAIL"]
            version_pass += p
            version_fail += fa

            sec_key, sec_label = derive_section(control, family_key)
            section = sections.setdefault(sec_key, {"key": sec_key, "label": sec_label, "pass": 0, "fail": 0})
            section["pass"] += p
            section["fail"] += fa

        section_list = [
            {
                "key": sec["key"],
                "label": sec["label"],
                "pass": sec["pass"],
                "fail": sec["fail"],
                "total": sec["pass"] + sec["fail"],
                "score": _score(sec["pass"], sec["fail"]),
            }
            for sec in sorted(sections.values(), key=lambda s: natural_sort_key(s["key"]))
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

    Covers all 4 real finding statuses (PASS/FAIL/MUTED/ACCEPTED) — `_build_families`
    (family/version/section tree, `/summary`) aggregates PASS/FAIL/ACCEPTED and
    ignores MUTED, while `get_all_framework_control_scores` (control-level score,
    used by the snapshot writer) folds MUTED/ACCEPTED into UNSCORED/PASS. Both share
    this single AQL pass over `findings` rather than querying twice.
    """
    aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status IN ["FAIL", "PASS", "MUTED", "ACCEPTED"]
        FOR fw IN f.framework_mapping
            LET parts = SPLIT(fw, "/", 2)
            COLLECT prefix = parts[0], control = (LENGTH(parts) > 1 ? parts[1] : null), status = f.status
            WITH COUNT INTO cnt
            RETURN {prefix, control, status, cnt}
    """
    return list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id}))


def get_compliance_summary(
    db: StandardDatabase, tenant_id: str, framework: str | None = None, severities: list[str] | None = None
) -> dict[str, Any]:
    """Framework family scores plus two top-10 risk lists (US-14.20/21):

    - `top_failing`: grouped by check (check_id/title/severity), sorted by how many
      resources fail it — "which policy gap, fixed once, helps the most".
    - `top_assets`: grouped by resource, sorted by FAIL finding count — "which single
      resource concentrates the most risk".

    `framework` (a raw slug, e.g. "CIS-7.0") scopes both lists to that framework
    version — the family/version/section tree itself is always computed in full so the
    sidebar and version switcher stay populated regardless of the current selection.
    The frontend also calls this with `framework=None` for the "Global" cross-framework
    tab, fetched in parallel with the scoped call rather than swapped on toggle.

    `severities` restricts `top_failing` only — the Top 10 Findings severity toggle
    (US-14.21) — `top_assets` always reflects every severity regardless. `None` means
    no restriction (the default, all 5 toggles on); the frontend sends a value that
    matches no real severity when the user has switched every toggle off, so `IN`
    naturally yields zero rows instead of the backend needing to special-case "filter
    to nothing" vs "no filter" (indistinguishable once serialized as an empty query
    param — see Top10Findings.tsx).

    A family disabled in Compliance Settings (US-14.19) is dropped from the family
    tree AND from both lists — a finding survives the aggregate cut only if at
    least one of its OTHER framework_mapping entries is still enabled (a CIS+NIST
    finding with only CIS disabled still counts, via NIST).
    """
    all_rows = _raw_prefix_control_status_rows(db, tenant_id)
    family_settings = get_all_compliance_family_settings(db)
    disabled_keys = {key for key, settings in family_settings.items() if not settings.enabled}
    disabled_prefixes = (
        {row["prefix"] for row in all_rows if resolve_family(row["prefix"])[0] in disabled_keys}
        if disabled_keys
        else set()
    )
    rows = [row for row in all_rows if row["prefix"] not in disabled_prefixes] if disabled_prefixes else all_rows
    families = _build_families(rows)
    control_scores = _control_scores_by_prefix(rows)
    for family in families:
        targets = family_settings.get(family["family"], ComplianceFamilySettings())
        family["target_by_control"] = targets.target_by_control
        for version in family["versions"]:
            # The headline score shown in the sidebar and the framework detail header
            # is always By Control. Bare-mapping frameworks with no control
            # granularity at all (e.g. some Checkov/IaC slugs) have no entry here and
            # keep `_build_families`'s finding-tally fallback as the only score available.
            ctrl = control_scores.get(version["id"])
            if ctrl is not None:
                version["score"] = ctrl["score_by_control"]
                version["pass"] = ctrl["pass_count"]
                version["fail"] = ctrl["fail_count"]
                version["total"] = ctrl["pass_count"] + ctrl["fail_count"] + ctrl["unscored_count"]

    # A finding with framework_mapping entries only in disabled families is excluded
    # from both aggregate queries below — empty when no framework is disabled (the
    # common case), so this never adds a clause to the AQL for a fresh tenant.
    disabled_condition = (
        'LENGTH(FOR fw IN f.framework_mapping FILTER SPLIT(fw, "/", 2)[0] NOT IN @disabled_prefixes RETURN 1) > 0'
        if disabled_prefixes
        else ""
    )
    agg_bind: dict[str, Any] = {"tenant_id": tenant_id}
    if disabled_condition:
        agg_bind["disabled_prefixes"] = list(disabled_prefixes)

    # ThreatScore: weighted by severity of FAIL findings (0–100, inverted) — tenant-wide
    # across every *enabled* framework, not scoped to the currently-open one.
    weight_filter = f"FILTER {disabled_condition}" if disabled_condition else ""
    weight_aql = f"""
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status == "FAIL"
        {weight_filter}
        COLLECT severity = f.severity WITH COUNT INTO cnt
        RETURN {{severity, cnt}}
    """
    sev_rows = list(db.aql.execute(weight_aql, bind_vars=agg_bind))
    weighted = sum(_SEVERITY_WEIGHT.get(r["severity"], 0) * r["cnt"] for r in sev_rows)
    # Cap at 200 for normalisation → threat_score in [0, 100]
    threat_score = max(0, 100 - min(weighted, 200) // 2)

    # Top 10 failing checks by count, optionally scoped to one framework version.
    top_filters = ["f.tenant_id == @tenant_id", 'f.status == "FAIL"']
    top_bind: dict[str, Any] = dict(agg_bind)
    if disabled_condition:
        top_filters.append(disabled_condition)
    if framework:
        top_filters.append(
            "LENGTH(FOR fw IN f.framework_mapping "
            'FILTER fw == @framework OR STARTS_WITH(fw, CONCAT(@framework, "/")) '
            "RETURN 1) > 0"
        )
        top_bind["framework"] = framework
    top_filter_str = "\n        ".join(f"FILTER {c}" for c in top_filters)

    # Severity toggle (US-14.21) applies only to top_failing, not top_assets — its own
    # filter list/bind built from the shared base above so assets_aql below stays
    # unaffected.
    findings_filters = list(top_filters)
    findings_bind: dict[str, Any] = dict(top_bind)
    if severities is not None:
        findings_filters.append("f.severity IN @severities")
        findings_bind["severities"] = severities
    findings_filter_str = "\n        ".join(f"FILTER {c}" for c in findings_filters)

    top_aql = f"""
    FOR f IN findings
        {findings_filter_str}
        COLLECT check_id = f.check_id, title = f.title, severity = f.severity
            WITH COUNT INTO cnt
        SORT cnt DESC
        LIMIT 10
        RETURN {{check_id, title, severity, count: cnt}}
    """
    top_failing = list(db.aql.execute(top_aql, bind_vars=findings_bind))

    # Top 10 assets by count of FAIL findings — simple count, not severity-weighted
    # (a resource with many LOW findings still ranks above one with a single CRITICAL;
    # ThreatScore is where severity weighting already lives). Same filters as top_failing:
    # tenant, FAIL-only, disabled-framework exclusion, optional framework scope.
    # Grouped by resource_id alone, not the full (resource_id, resource_type, ...)
    # tuple: account-level checks (IAM password policy, CloudTrail config, ...) tag
    # resource_id with the bare account ID, and different account-level checks can
    # carry different resource_type labels ("AwsCloudWatchAlarm" vs "Other") for that
    # same pseudo-resource — grouping by the full tuple split one asset into several
    # rows with duplicate resource_id. `sample` picks one representative finding per
    # resource_id for the display fields, preferring one whose resource_type isn't
    # "unknown" (prowler_service._normalize's own fallback for a finding whose check
    # result carried no metadata) when a more specific one is available in the group.
    assets_aql = f"""
    FOR f IN findings
        {top_filter_str}
        COLLECT resource_id = f.resource_id INTO grouped
        LET sample = FIRST(
            FOR g IN grouped
                SORT g.f.resource_type == "unknown" ASC
                RETURN g.f
        )
        LET cnt = LENGTH(grouped)
        SORT cnt DESC
        LIMIT 10
        RETURN {{
            resource_id,
            resource_type: sample.resource_type,
            provider: sample.provider,
            region: sample.region,
            account_id: sample.account_id,
            count: cnt,
        }}
    """
    top_assets = list(db.aql.execute(assets_aql, bind_vars=top_bind))

    return {
        "families": families,
        "threat_score": threat_score,
        "top_failing": top_failing,
        "top_assets": top_assets,
    }


def list_compliance_family_settings(db: StandardDatabase, tenant_id: str) -> list[dict[str, Any]]:
    """Every framework family the tenant currently has findings for, merged with its
    Compliance Settings (enabled + per-metric targets) — powers the Compliance
    Settings page (US-14.19). Deliberately unfiltered by `enabled`: a disabled family
    must still show up here so it can be re-enabled, unlike `get_compliance_summary`
    which drops it.
    """
    rows = _raw_prefix_control_status_rows(db, tenant_id)
    families = _build_families(rows)
    settings = get_all_compliance_family_settings(db)

    result = [
        {
            "family_key": family["family"],
            "family_label": family["label"],
            **settings.get(family["family"], ComplianceFamilySettings()).model_dump(),
        }
        for family in families
    ]
    result.sort(key=lambda item: item["family_label"])
    return result


# Index into the 4-tuples used throughout this module for per-control/per-finding
# status counts: (pass, fail, accepted, muted).
_PASS, _FAIL, _ACCEPTED, _MUTED = 0, 1, 2, 3
_STATUS_INDEX = {"PASS": _PASS, "FAIL": _FAIL, "ACCEPTED": _ACCEPTED, "MUTED": _MUTED}


def _score_by_control(
    control_status: dict[str, tuple[int, int, int, int]],
    catalog_control_ids: set[str] | None,
) -> tuple[float, int, int, int]:
    """Control-level score, folding ACCEPTED/MUTED into the binary Pass/Fail/Unscored
    view (confirmed design — see Epic 14 Sprint 4 Grupo D follow-up):

    - Any FAIL finding on the control -> the control is Fail. FAIL always wins.
    - No FAIL, but any PASS or ACCEPTED finding -> the control is Pass. An explicit
      risk acceptance is treated as satisfying the control for this view.
    - Otherwise (only MUTED findings, or no findings at all) -> Unscored. A muted
      finding is suppressed noise, not a decision about the control's status — it
      collapses into the same "not really evaluated" bucket as a control the
      catalog knows about but that has never produced a finding.

    Unscored counts toward the compliant side of the ratio (confirmed design,
    revisiting the earlier "excluded from the denominator" rule): score =
    (Pass + Unscored) / Total. A control nobody has evaluated yet is treated as not
    (yet) failing, same spirit as "innocent until proven guilty" — accepted tradeoff
    is that a framework with zero scans shows 100%, not 0%. `catalog_control_ids=None`
    means the catalog is unavailable for this framework (non-AWS) — every control is
    judged solely by whether it has findings.

    Returns (score_by_control, pass_count, fail_count, unscored_count).
    """
    all_ids = set(control_status) | (catalog_control_ids or set())
    pass_count = fail_count = 0
    for control_id in all_ids:
        p, f, a, _m = control_status.get(control_id, (0, 0, 0, 0))
        if f > 0:
            fail_count += 1
        elif p > 0 or a > 0:
            pass_count += 1
    total = len(all_ids)
    unscored_count = total - pass_count - fail_count
    score = round((pass_count + unscored_count) / total * 100, 1) if total else 0.0
    return score, pass_count, fail_count, unscored_count


def _control_scores_by_prefix(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Control-level score per framework version (`prefix`), from raw
    (prefix, control, status, count) rows — shared by `get_all_framework_control_scores`
    (fresh AQL fetch, one row per framework, used by the snapshot writer) and
    `get_compliance_summary` (reuses rows it already fetched for `_build_families`,
    avoiding a second AQL pass over the same data).
    """
    by_prefix: dict[str, dict[str, list[int]]] = {}
    for row in rows:
        control = row["control"]
        if control is None:
            continue  # bare framework findings (e.g. Checkov/IaC) have no control granularity
        counts = by_prefix.setdefault(row["prefix"], {}).setdefault(control, [0, 0, 0, 0])
        counts[_STATUS_INDEX[row["status"]]] += row["cnt"]

    result: dict[str, dict[str, Any]] = {}
    for prefix, control_counts in by_prefix.items():
        control_status = {cid: (c[0], c[1], c[2], c[3]) for cid, c in control_counts.items()}
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


def get_all_framework_control_scores(db: StandardDatabase, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Control-level score for every framework the tenant has findings for.

    One AQL pass total (shared with `get_compliance_summary` via
    `_raw_prefix_control_status_rows`), not one query per framework — this is what
    `snapshot_compliance_scores` calls once per scan.
    """
    return _control_scores_by_prefix(_raw_prefix_control_status_rows(db, tenant_id))


def get_framework_detail(db: StandardDatabase, tenant_id: str, raw_slug: str) -> dict[str, Any] | None:
    """Full detail for one framework version, By Control (US-14.14/15/16): Pass/Fail/
    Unscored per *control* — ACCEPTED folds into Pass, MUTED folds into Unscored, any
    FAIL wins regardless of how many assets pass. Plus the section -> sub-section ->
    requirement tree that backs it, folded the same way at every level.

    Returns None only when `raw_slug` is a genuinely unknown slug — no findings, no
    AWS catalog entry, and no curated label. A real framework with zero findings so
    far (e.g. GDPR before any relevant check has run) still returns a full tree with
    every control Unscored, not a 404.
    """
    aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status IN ["FAIL", "PASS", "MUTED", "ACCEPTED"]
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
    family_targets = get_all_compliance_family_settings(db).get(family_key, ComplianceFamilySettings())

    per_control: dict[str, dict[str, Any]] = {}
    for row in rows:
        control = row["control"]
        status = row["status"]
        if control is None:
            continue  # bare (control-less) findings have no section to attribute to
        entry = per_control.setdefault(
            control,
            {
                "pass": 0,
                "fail": 0,
                "accepted": 0,
                "muted": 0,
                "fail_key": None,
                "fail_weight": -1,
                "pass_key": None,
                "accepted_key": None,
                "muted_key": None,
            },
        )
        if status == "FAIL":
            entry["fail"] += 1
            weight = _SEVERITY_WEIGHT.get(row["severity"], 0)
            if weight > entry["fail_weight"]:
                entry["fail_weight"] = weight
                entry["fail_key"] = row["finding_key"]
        elif status == "PASS":
            entry["pass"] += 1
            if entry["pass_key"] is None:
                entry["pass_key"] = row["finding_key"]
        elif status == "ACCEPTED":
            entry["accepted"] += 1
            if entry["accepted_key"] is None:
                entry["accepted_key"] = row["finding_key"]
        else:  # MUTED
            entry["muted"] += 1
            if entry["muted_key"] is None:
                entry["muted_key"] = row["finding_key"]

    catalog_by_id = {r.control_id: r for r in (catalog or [])}
    all_control_ids = set(per_control) | set(catalog_by_id)

    control_status = {
        cid: (
            per_control.get(cid, {}).get("pass", 0),
            per_control.get(cid, {}).get("fail", 0),
            per_control.get(cid, {}).get("accepted", 0),
            per_control.get(cid, {}).get("muted", 0),
        )
        for cid in all_control_ids
    }
    catalog_ids = set(catalog_by_id) if catalog_available else None
    score_by_control, control_pass_count, control_fail_count, control_unscored_count = _score_by_control(
        control_status, catalog_ids
    )

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

        # FAIL always wins; PASS covers real passes and accepted risk; everything else
        # (muted-only or never evaluated) is Unscored — same fold rule as `_score_by_control`.
        if found and found["fail"] > 0:
            status, finding_key = "FAIL", found["fail_key"]
        elif found and (found["pass"] > 0 or found["accepted"] > 0):
            status = "PASS"
            finding_key = found["pass_key"] or found["accepted_key"]
        else:
            status = "UNSCORED"
            # Still link to a muted finding if one exists — excluded from scoring,
            # not from the drill-down.
            finding_key = found["muted_key"] if found else None

        requirement = {
            "control_id": control_id,
            "name": name,
            "description": description,
            "status": status,
            "finding_key": finding_key,
            "pass_count": found["pass"] if found else 0,
            "fail_count": found["fail"] if found else 0,
            "accepted_count": found["accepted"] if found else 0,
            "muted_count": found["muted"] if found else 0,
        }

        section = sections.setdefault(sec_key, {"label": sec_label, "requirements": [], "subsections": {}})
        if sub_key:
            subsection = section["subsections"].setdefault(sub_key, {"label": sub_label, "requirements": []})
            subsection["requirements"].append(requirement)
        else:
            section["requirements"].append(requirement)

    def _rollup(requirements: list[dict[str, Any]]) -> dict[str, Any]:
        control_pass = sum(1 for r in requirements if r["status"] == "PASS")
        control_fail = sum(1 for r in requirements if r["status"] == "FAIL")
        control_unscored = sum(1 for r in requirements if r["status"] == "UNSCORED")
        return {
            "control_pass_count": control_pass,
            "control_fail_count": control_fail,
            "control_unscored_count": control_unscored,
            "control_total": len(requirements),
            # Unscored counts toward Pass — same rule as `_score_by_control` (see its
            # docstring); passing `control_pass + control_unscored` as the numerator to
            # the plain Pass/(Pass+Fail) helper produces (Pass+Unscored)/Total exactly.
            "score_by_control": _score(control_pass + control_unscored, control_fail),
        }

    section_list = []
    for sec_key, sec in sorted(sections.items(), key=lambda item: natural_sort_key(item[0])):
        subsection_list = []
        sec_requirements = sorted(sec["requirements"], key=lambda r: natural_sort_key(r["control_id"]))
        all_requirements = list(sec_requirements)
        for sub_key, sub in sorted(sec["subsections"].items(), key=lambda item: natural_sort_key(item[0])):
            sub_requirements = sorted(sub["requirements"], key=lambda r: natural_sort_key(r["control_id"]))
            rollup = _rollup(sub_requirements)
            subsection_list.append(
                {
                    "key": sub_key,
                    "label": sub["label"],
                    **rollup,
                    "subsections": [],
                    "requirements": sub_requirements,
                }
            )
            all_requirements.extend(sub_requirements)
        rollup = _rollup(all_requirements)
        section_list.append(
            {
                "key": sec_key,
                "label": sec["label"],
                **rollup,
                "subsections": subsection_list,
                "requirements": sec_requirements,
            }
        )

    return {
        "id": raw_slug,
        "family": family_key,
        "family_label": family_label,
        "version_label": version_label,
        "score_by_control": score_by_control,
        "control_pass_count": control_pass_count,
        "control_fail_count": control_fail_count,
        "control_unscored_count": control_unscored_count,
        "control_total": len(all_control_ids),
        "target_by_control": family_targets.target_by_control,
        "catalog_available": catalog_available,
        "sections": section_list,
    }


def snapshot_compliance_scores(db: StandardDatabase, tenant_id: str) -> int:
    """Upsert one By Control score snapshot per framework the tenant has findings
    for, keyed by (tenant, framework, day) — running this twice on the same day
    overwrites, not duplicates. Called at the end of every CSPM scan
    (`run_cspm_scan`); there is no backfill, so `/trend` starts empty and grows one
    point per scan day.

    Returns the number of framework snapshots written.
    """
    control_scores = get_all_framework_control_scores(db, tenant_id)

    snapshot_date = datetime.now(UTC).date().isoformat()
    now = datetime.now(UTC).isoformat()
    collection = db.collection("compliance_score_snapshots")

    count = 0
    for prefix, ctrl in control_scores.items():
        doc = {
            "_key": hashlib.sha256(f"{tenant_id}|{prefix}|{snapshot_date}".encode()).hexdigest(),
            "tenant_id": tenant_id,
            "framework_id": prefix,
            "snapshot_date": snapshot_date,
            "score_by_control": ctrl["score_by_control"],
            "pass_count": ctrl["pass_count"],
            "fail_count": ctrl["fail_count"],
            "unscored_count": ctrl["unscored_count"],
            "created_at": now,
        }
        collection.insert(doc, overwrite=True)
        count += 1
    return count


def get_score_trend(db: StandardDatabase, tenant_id: str, raw_slug: str, period: str) -> list[dict[str, Any]]:
    """Daily By Control score history for one framework, from `compliance_score_snapshots`."""
    days = _TREND_PERIOD_DAYS[period]
    since = (datetime.now(UTC) - timedelta(days=days)).date().isoformat()
    aql = """
    FOR s IN compliance_score_snapshots
        FILTER s.tenant_id == @tenant_id AND s.framework_id == @framework_id AND s.snapshot_date >= @since
        SORT s.snapshot_date ASC
        RETURN {
            date: s.snapshot_date,
            score_by_control: s.score_by_control,
            pass_count: s.pass_count,
            fail_count: s.fail_count,
            unscored_count: s.unscored_count,
        }
    """
    return list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id, "framework_id": raw_slug, "since": since}))


def get_control_assets(db: StandardDatabase, tenant_id: str, raw_slug: str, control_id: str) -> list[dict[str, Any]]:
    """Per-asset Pass/Fail tally for one control (US-14.22: the compliance page's
    control drill-down panel, Assets tab). `raw_slug` + `control_id` reconstruct the
    exact `framework_mapping` entry (`"{raw_slug}/{control_id}"`) `get_framework_detail`
    derived `control_id` from in the first place — an exact match, not the prefix
    match `get_framework_detail` uses for the whole tree, since this always targets
    one leaf control.

    ACCEPTED folds into `pass_count`, same fold rule as everywhere else in this
    module; MUTED findings are counted in neither bucket (they surface in the panel's
    "All" filter, not "Pass" or "Fail").

    `resource_type` "unknown" is `prowler_service._normalize`'s own fallback for a
    finding whose Prowler check result carried no metadata — not every check on the
    same resource_id hits that gap, so a later row with a real type overwrites an
    earlier "unknown" pick instead of the display field getting stuck on whichever
    row AQL happened to return first (folded in Python, not AQL's arbitrary
    `COLLECT ... INTO` order, precisely so this preference is possible).
    """
    full_slug = f"{raw_slug}/{control_id}"
    aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER @full_slug IN f.framework_mapping
        RETURN {
            resource_id: f.resource_id,
            status: f.status,
            resource_type: f.resource_type,
            provider: f.provider,
            region: f.region,
            account_id: f.account_id,
        }
    """
    rows = list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id, "full_slug": full_slug}))

    per_resource: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = per_resource.setdefault(
            row["resource_id"],
            {
                "resource_id": row["resource_id"],
                "resource_type": row["resource_type"],
                "provider": row["provider"],
                "region": row["region"],
                "account_id": row["account_id"],
                "pass_count": 0,
                "fail_count": 0,
            },
        )
        if entry["resource_type"] == "unknown" and row["resource_type"] != "unknown":
            entry["resource_type"] = row["resource_type"]
            entry["provider"] = row["provider"]
            entry["region"] = row["region"]
            entry["account_id"] = row["account_id"]
        if row["status"] in ("PASS", "ACCEPTED"):
            entry["pass_count"] += 1
        elif row["status"] == "FAIL":
            entry["fail_count"] += 1

    assets = list(per_resource.values())
    assets.sort(key=lambda a: (-a["fail_count"], -a["pass_count"], a["resource_id"]))
    return assets
