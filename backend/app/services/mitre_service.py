"""MITRE ATT&CK service — technique lookups, TC chain mapping, and finding enrichment."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Hardcoded MITRE chains for the four built-in Toxic Combination rules.
# Keys match the `rule` field stored on attack_path documents.
MITRE_CHAINS: dict[str, list[str]] = {
    "TC-01": ["T1190", "T1078.004", "T1537"],  # Internet-facing EC2 → IAM → S3
    "TC-02": ["T1530", "T1552.005"],  # Public S3 with credentials
    "TC-03": ["T1078", "T1213"],  # Overpermissioned identity → DB
    "TC-04": ["T1611", "T1552.005"],  # K8s host network → metadata
}


def build_mitre_chain_for_tc(tc_rule_id: str) -> list[str]:
    """Return the list of MITRE technique IDs for a built-in TC rule.

    Returns an empty list for unknown rules so callers need not special-case None.
    """
    return list(MITRE_CHAINS.get(tc_rule_id, []))


def get_techniques_for_path(path_doc: dict[str, Any], admin_db: Any) -> dict[str, Any]:
    """Look up full MITRE technique, tactic and APT group data for an attack path.

    Reads ``mitre_ttps`` and ``mitre_chain`` from *path_doc* and queries the
    global admin database.  Returns gracefully if the admin DB is unavailable or
    the MITRE collections have not been imported yet.

    Return schema::

        {
            "techniques": [{"technique_id": "T1190", "name": "...", "tactic_ids": [...], ...}],
            "tactics":    [{"tactic_id": "TA0001", "name": "...", "shortname": "..."}],
            "apt_groups": [{"group_id": "G0073", "name": "...", "aliases": [...], "country": "..."}],
            "mitre_chain": ["T1190", "T1078.004", "T1537"],
        }
    """
    empty: dict[str, Any] = {"techniques": [], "tactics": [], "apt_groups": [], "mitre_chain": []}

    mitre_ttps: list[str] = list(path_doc.get("mitre_ttps") or [])
    mitre_chain: list[str] = list(path_doc.get("mitre_chain") or [])
    all_ttp_ids = list(dict.fromkeys(mitre_chain + [t for t in mitre_ttps if t not in mitre_chain]))

    if not all_ttp_ids:
        return {**empty, "mitre_chain": mitre_chain}

    try:
        if not admin_db.has_collection("mitre_techniques"):
            return {**empty, "mitre_chain": mitre_chain}
    except Exception:
        return {**empty, "mitre_chain": mitre_chain}

    techniques: list[dict[str, Any]] = []
    tactic_ids_seen: set[str] = set()
    apt_group_ids_seen: set[str] = set()
    apt_groups: list[dict[str, Any]] = []

    try:
        for ttp_id in all_ttp_ids:
            cursor = admin_db.aql.execute(
                "FOR t IN mitre_techniques FILTER t.technique_id == @tid LIMIT 1 RETURN t",
                bind_vars={"tid": ttp_id},
            )
            rows = list(cursor)
            if not rows:
                continue
            tech = rows[0]
            techniques.append(tech)
            for tid in tech.get("tactic_ids") or []:
                tactic_ids_seen.add(tid)

            # Fetch APT groups that use this technique via APT_USES edges
            apt_cursor = admin_db.aql.execute(
                """
                FOR g, e IN 1..1 INBOUND @tech_id APT_USES
                    LIMIT 10
                    RETURN DISTINCT g
                """,
                bind_vars={"tech_id": tech["_id"]},
            )
            for grp in apt_cursor:
                gid = grp.get("group_id", "")
                if gid and gid not in apt_group_ids_seen:
                    apt_group_ids_seen.add(gid)
                    apt_groups.append(grp)

        # Fetch tactic documents
        tactics: list[dict[str, Any]] = []
        if tactic_ids_seen:
            tactic_cursor = admin_db.aql.execute(
                "FOR t IN mitre_tactics FILTER t.tactic_id IN @ids RETURN t",
                bind_vars={"ids": list(tactic_ids_seen)},
            )
            tactics = list(tactic_cursor)

    except Exception:
        logger.exception("MITRE lookup failed; returning partial results")

    return {
        "techniques": techniques,
        "tactics": tactics,
        "apt_groups": apt_groups,
        "mitre_chain": mitre_chain,
    }


def enrich_finding_with_mitre(
    finding_key: str,
    mitre_ttps: list[str],
    db: Any,
    tenant_id: str,  # noqa: ARG001  # kept for future row-level audit
) -> int:
    """Create MAPPED_TO edges from a finding to MITRE techniques in the admin DB.

    Cross-database references are not supported by ArangoDB graph traversals, so
    edges are stored in the tenant DB pointing to technique IDs by string key only.
    Returns the number of edges created.
    """
    if not mitre_ttps:
        return 0

    created = 0
    for ttp_id in mitre_ttps:
        edge_key = f"{finding_key.replace('/', '_')}__{ttp_id.replace('.', '_')}"
        edge_doc = {
            "_key": edge_key,
            "_from": f"findings/{finding_key}",
            "_to": f"mitre_techniques/{ttp_id}",
            "technique_id": ttp_id,
        }
        try:
            db.collection("MAPPED_TO").insert(edge_doc, overwrite=True)
            created += 1
        except Exception:
            logger.debug("Could not create MAPPED_TO edge for finding=%s ttp=%s", finding_key, ttp_id)

    return created
