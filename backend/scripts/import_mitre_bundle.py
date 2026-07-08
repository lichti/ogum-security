#!/usr/bin/env python3
"""
Import MITRE ATT&CK Enterprise bundle (STIX 2.0) into ArangoDB global database.

The MITRE collections live in ogum_admin (shared across all tenants):
  mitre_techniques  — attack-pattern objects  (T-codes)
  mitre_tactics     — x-mitre-tactic objects  (TA-codes)
  mitre_groups      — intrusion-set objects    (G-codes)
  APT_USES          — relationship edges       (group uses technique)

Usage:
    python scripts/import_mitre_bundle.py [--bundle-url URL] [--db-host HOST] \\
                                           [--db-port PORT] [--db-password PASSWORD]

The script is idempotent — safe to run multiple times.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import urllib.request
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_DEFAULT_BUNDLE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


# ---------------------------------------------------------------------------
# STIX parsing helpers
# ---------------------------------------------------------------------------


def _extract_technique_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _extract_tactic_shortname(obj: dict[str, Any]) -> str:
    return obj.get("x_mitre_shortname", "")


def _parse_bundle(
    bundle: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    """Return (techniques, tactics, groups, apt_uses_edges) parsed from STIX bundle."""
    techniques: list[dict[str, Any]] = []
    tactics: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    apt_uses: list[dict[str, Any]] = []

    # Index for resolving STIX IDs → external IDs
    stix_to_ext: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        obj_type = obj.get("type", "")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        if obj_type == "attack-pattern":
            tid = _extract_technique_id(obj)
            if not tid:
                continue
            stix_to_ext[obj["id"]] = tid
            tactic_ids = [
                p.get("phase_name", "")
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            techniques.append(
                {
                    "_key": tid.replace(".", "_"),
                    "technique_id": tid,
                    "stix_id": obj["id"],
                    "name": obj.get("name", ""),
                    "description": (obj.get("description", "") or "")[:500],
                    "tactic_ids": tactic_ids,
                    "platforms": obj.get("x_mitre_platforms", []),
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                }
            )

        elif obj_type == "x-mitre-tactic":
            tid = _extract_technique_id(obj)
            shortname = _extract_tactic_shortname(obj)
            if not tid:
                continue
            stix_to_ext[obj["id"]] = tid
            tactics.append(
                {
                    "_key": tid,
                    "tactic_id": tid,
                    "stix_id": obj["id"],
                    "name": obj.get("name", ""),
                    "shortname": shortname,
                    "description": (obj.get("description", "") or "")[:500],
                }
            )

        elif obj_type == "intrusion-set":
            gid = _extract_technique_id(obj)
            if not gid:
                continue
            stix_to_ext[obj["id"]] = gid
            aliases = obj.get("aliases", [])
            if obj.get("name") in aliases:
                aliases = [a for a in aliases if a != obj["name"]]
            groups.append(
                {
                    "_key": gid,
                    "group_id": gid,
                    "stix_id": obj["id"],
                    "name": obj.get("name", ""),
                    "aliases": aliases,
                    "description": (obj.get("description", "") or "")[:500],
                    "country": "",  # STIX 2.0 doesn't include country directly
                }
            )

        elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
            source_stix = obj.get("source_ref", "")
            target_stix = obj.get("target_ref", "")
            if "intrusion-set" in source_stix and "attack-pattern" in target_stix:
                apt_uses.append({"source_stix": source_stix, "target_stix": target_stix})

    # Resolve STIX IDs to external IDs for the APT_USES edges
    resolved_edges: list[dict[str, Any]] = []
    for rel in apt_uses:
        gid = stix_to_ext.get(rel["source_stix"])
        tid = stix_to_ext.get(rel["target_stix"])
        if gid and tid:
            edge_key = f"{gid}__{tid.replace('.', '_')}"
            resolved_edges.append(
                {
                    "_key": edge_key,
                    "_from": f"mitre_groups/{gid}",
                    "_to": f"mitre_techniques/{tid.replace('.', '_')}",
                    "group_id": gid,
                    "technique_id": tid,
                }
            )

    return techniques, tactics, groups, resolved_edges


def _upsert_all(db: Any, collection: str, docs: list[dict[str, Any]], *, edge: bool = False) -> int:
    col = db.collection(collection)
    count = 0
    for doc in docs:
        try:
            col.insert(doc, overwrite=True)
            count += 1
        except Exception as exc:
            logger.debug("Skipped %s/%s: %s", collection, doc.get("_key"), exc)
    return count


# ---------------------------------------------------------------------------
# Schema bootstrap (standalone — no dependency on app package)
# ---------------------------------------------------------------------------

_MITRE_VERTEX_COLLECTIONS = ["mitre_techniques", "mitre_tactics", "mitre_groups"]
_MITRE_EDGE_COLLECTIONS = ["APT_USES"]
_MITRE_INDEXES = [
    ("mitre_techniques", "technique_id", True),
    ("mitre_groups", "group_id", True),
    ("mitre_tactics", "tactic_id", True),
]


def _ensure_admin_schema(db: Any) -> None:
    for name in _MITRE_VERTEX_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name)
    for name in _MITRE_EDGE_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name, edge=True)
    for col_name, field, unique in _MITRE_INDEXES:
        col = db.collection(col_name)
        existing = col.indexes()
        already = any(
            idx.get("fields") == [field] and idx.get("type") == "persistent"
            for idx in existing
        )
        if not already:
            col.add_index({"type": "persistent", "fields": [field], "unique": unique})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import MITRE ATT&CK bundle into ArangoDB")
    parser.add_argument("--bundle-url", default=_DEFAULT_BUNDLE_URL, help="URL of enterprise-attack.json")
    parser.add_argument("--db-host", default=os.environ.get("ARANGO_HOST", "localhost"))
    parser.add_argument("--db-port", type=int, default=int(os.environ.get("ARANGO_PORT", "8529")))
    parser.add_argument("--db-user", default=os.environ.get("ARANGO_USER", "root"))
    parser.add_argument("--db-password", default=os.environ.get("ARANGO_PASSWORD", "changeme"))
    parser.add_argument("--local-file", default=None, help="Use a local STIX bundle file instead of downloading")
    args = parser.parse_args(argv)

    # ── Load bundle ──────────────────────────────────────────────────────────
    if args.local_file:
        logger.info("Loading bundle from local file: %s", args.local_file)
        with open(args.local_file) as fh:
            bundle = json.load(fh)
    else:
        logger.info("Downloading MITRE ATT&CK bundle from %s ...", args.bundle_url)
        try:
            with urllib.request.urlopen(args.bundle_url, timeout=60) as resp:  # noqa: S310
                bundle = json.loads(resp.read())
            logger.info("Download complete.")
        except Exception as exc:
            logger.error("Failed to download bundle: %s", exc)
            logger.error("Use --local-file to import from a local copy.")
            return 1

    # ── Parse ────────────────────────────────────────────────────────────────
    techniques, tactics, groups, edges = _parse_bundle(bundle)
    logger.info(
        "Parsed: %d techniques, %d tactics, %d groups, %d APT_USES edges",
        len(techniques),
        len(tactics),
        len(groups),
        len(edges),
    )

    # ── Connect ──────────────────────────────────────────────────────────────
    try:
        from arango import ArangoClient

        client = ArangoClient(hosts=f"http://{args.db_host}:{args.db_port}")
        sys_db = client.db("_system", username=args.db_user, password=args.db_password)
        if not sys_db.has_database("ogum_admin"):
            sys_db.create_database("ogum_admin")
        db = client.db("ogum_admin", username=args.db_user, password=args.db_password)

        _ensure_admin_schema(db)
    except Exception as exc:
        logger.error("Failed to connect to ArangoDB: %s", exc)
        return 1

    # ── Upsert ───────────────────────────────────────────────────────────────
    t_count = _upsert_all(db, "mitre_techniques", techniques)
    ta_count = _upsert_all(db, "mitre_tactics", tactics)
    g_count = _upsert_all(db, "mitre_groups", groups)
    e_count = _upsert_all(db, "APT_USES", edges, edge=True)

    print(f"Imported: {t_count} techniques, {ta_count} tactics, {g_count} groups, {e_count} edges")
    return 0


if __name__ == "__main__":
    sys.exit(main())
