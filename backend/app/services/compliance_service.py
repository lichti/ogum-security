from __future__ import annotations

from arango.database import StandardDatabase

_SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def get_compliance_summary(db: StandardDatabase, tenant_id: str) -> dict:
    aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status IN ["FAIL", "PASS"]
        FOR fw IN f.framework_mapping
            COLLECT framework = fw, status = f.status WITH COUNT INTO cnt
            RETURN {framework, status, cnt}
    """
    rows = list(db.aql.execute(aql, bind_vars={"tenant_id": tenant_id}))

    raw: dict[str, dict[str, int]] = {}
    for r in rows:
        fw = r["framework"]
        if fw not in raw:
            raw[fw] = {"PASS": 0, "FAIL": 0}
        raw[fw][r["status"]] = r["cnt"]

    frameworks = []
    for fw_id, counts in sorted(raw.items()):
        total = counts["PASS"] + counts["FAIL"]
        score = round(counts["PASS"] / total * 100, 1) if total else 0.0
        frameworks.append(
            {
                "id": fw_id,
                "pass": counts["PASS"],
                "fail": counts["FAIL"],
                "total": total,
                "score": score,
            }
        )

    # ThreatScore: weighted by severity of FAIL findings (0–100, inverted)
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

    # Top 10 failing checks by count
    top_aql = """
    FOR f IN findings
        FILTER f.tenant_id == @tenant_id
        FILTER f.status == "FAIL"
        COLLECT check_id = f.check_id, title = f.title, severity = f.severity
            WITH COUNT INTO cnt
        SORT cnt DESC
        LIMIT 10
        RETURN {check_id, title, severity, count: cnt}
    """
    top_failing = list(db.aql.execute(top_aql, bind_vars={"tenant_id": tenant_id}))

    return {
        "frameworks": frameworks,
        "threat_score": threat_score,
        "top_failing": top_failing,
    }
