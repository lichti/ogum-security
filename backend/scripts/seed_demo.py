#!/usr/bin/env python3
"""
Seed realistic demo findings into an Ogum tenant database.

Usage:
    python scripts/seed_demo.py                          # uses dev-tenant, localhost ArangoDB
    python scripts/seed_demo.py --tenant my-tenant
    python scripts/seed_demo.py --tenant my-tenant --clear
    ARANGO_URL=http://arango:8529 python scripts/seed_demo.py

Environment variables (override defaults):
    ARANGO_URL       ArangoDB URL (default: http://localhost:8529)
    ARANGO_USER      ArangoDB user (default: root)
    ARANGO_PASSWORD  ArangoDB password (default: changeme)
    TENANT_ID        Tenant to seed (default: dev-tenant)
"""

from __future__ import annotations

import argparse
import os
import sys

# Allow running from repo root or from backend/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arango import ArangoClient

from app.api.v1.dev import seed_findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Ogum demo data")
    parser.add_argument("--tenant", default=os.getenv("TENANT_ID", "dev-tenant"), help="Tenant ID to seed")
    parser.add_argument("--clear", action="store_true", help="Clear findings and scan_jobs before seeding")
    parser.add_argument("--arango-url", default=os.getenv("ARANGO_URL", "http://localhost:8529"))
    parser.add_argument("--arango-user", default=os.getenv("ARANGO_USER", "root"))
    parser.add_argument("--arango-password", default=os.getenv("ARANGO_PASSWORD", "changeme"))
    args = parser.parse_args()

    tenant_id = args.tenant
    db_name = f"ogum_{tenant_id}"

    client = ArangoClient(hosts=args.arango_url)
    sys_db = client.db("_system", username=args.arango_user, password=args.arango_password)

    if not sys_db.has_database(db_name):
        sys_db.create_database(db_name)
        print(f"Created database: {db_name}")

    db = client.db(db_name, username=args.arango_user, password=args.arango_password)

    if args.clear:
        try:
            deleted = sum(
                1
                for _ in db.aql.execute(
                    "FOR f IN findings FILTER f.tenant_id == @tid REMOVE f IN findings RETURN 1",
                    bind_vars={"tid": tenant_id},
                )
            )
            print(f"Cleared {deleted} findings")
        except Exception as e:
            print(f"Clear failed (collection may not exist): {e}")

    result = seed_findings(db, tenant_id)

    print(f"\n✓ Seeded tenant '{tenant_id}':")
    print(f"  Database:        {db_name} ({args.arango_url})")
    print(f"  Findings:        {result['findings_inserted']} total")
    print(f"    FAIL:          {result['findings_fail']}")
    print(f"    PASS:          {result['findings_pass']}")
    print(f"    MUTED:         {result['findings_muted']}")
    print(f"  Scan job:        {result['scan_job_id']}")
    print(f"  Account ID:      {result['account_id']}")
    print("\n  Open http://localhost:3000 — findings and compliance should now have data.\n")


if __name__ == "__main__":
    main()
