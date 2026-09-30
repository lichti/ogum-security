#!/usr/bin/env python3
"""Executa as migrações de schema em todos os tenants registrados (US-00.12).

Itera `_system.tenants` (allowlist do resolver estrito) e aplica as migrações
pendentes em cada `ogum_{tenant_id}`. Idempotente.

    # Local (repo root)
    python backend/scripts/run_migrations.py

    # Dentro do container do backend
    docker compose exec -T backend python scripts/run_migrations.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arango import ArangoClient  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.migrations import run_migrations  # noqa: E402


def main() -> int:
    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    sys_db = client.db("_system", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)

    if not sys_db.has_collection("tenants"):
        print("Nenhum tenant registrado (_system.tenants vazia).")
        return 0

    tenants = [doc["tenant_id"] for doc in sys_db.collection("tenants").all()]
    if not tenants:
        print("Nenhum tenant registrado.")
        return 0

    failed = 0
    for tenant_id in sorted(tenants):
        db_name = f"ogum_{tenant_id}"
        if not sys_db.has_database(db_name):
            print(f"[{db_name}] database não provisionado — pulando (provisionamento via register_tenant)")
            continue
        db = client.db(db_name, username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
        try:
            ran = run_migrations(db, tenant_id)
            print(f"[{db_name}] {'aplicadas: ' + ', '.join(ran) if ran else 'sem pendências'}")
        except Exception as exc:
            failed += 1
            print(f"[{db_name}] FALHOU: {exc}")

    print(f"\nConcluído: {len(tenants)} tenant(s), {failed} falha(s).")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
