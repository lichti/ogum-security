#!/usr/bin/env python3
"""Migração única: credenciais plaintext de tenant_config → Vault (US-06.11).

Para cada database `ogum_*` do ArangoDB, varre `tenant_config` em busca dos
campos de segredo em plaintext; para cada documento com segredos:
grava o lote no Vault (`tenants/{tenant_id}/{provider_key}`), grava as
referências (`credentials_vault_path`/`_version`) e faz **purge** dos campos
planos (passam a `None`). Idempotente: documentos já migrados são ignorados.

    # Local (repo root)
    python backend/scripts/migrate_credentials_to_vault.py

    # Dentro do container do backend
    docker compose exec -T backend python scripts/migrate_credentials_to_vault.py

Requer Vault no ar (compose: `docker compose up -d vault`). Rode em janela de
manutenção: um scan agendado em execução durante a migração ainda lê o formato
legado (get_provider_credentials tolera), mas o fluxo novo já grava só no Vault.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arango import ArangoClient  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.services import vault_client  # noqa: E402
from app.services.provider_service import _SECRET_FIELDS  # noqa: E402


def main() -> int:
    client = ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
    sys_db = client.db("_system", username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)

    tenant_dbs = [name for name in sys_db.databases() if name.startswith("ogum_")]
    if not tenant_dbs:
        print("Nenhum database de tenant encontrado.")
        return 0

    migrated = skipped = 0
    for db_name in sorted(tenant_dbs):
        tenant_id = db_name.removeprefix("ogum_")
        db = client.db(db_name, username=settings.ARANGO_USER, password=settings.ARANGO_PASSWORD)
        if not db.has_collection("tenant_config"):
            continue
        for doc in db.collection("tenant_config"):
            plaintext = {f: doc[f] for f in _SECRET_FIELDS if doc.get(f)}
            if not plaintext:
                skipped += 1
                continue
            key = doc["_key"]
            ref = vault_client.store_credentials(tenant_id, key, plaintext)
            db.collection("tenant_config").update(
                {
                    "_key": key,
                    "credentials_vault_path": ref["path"],
                    "credentials_vault_version": ref["version"],
                    **{f: None for f in _SECRET_FIELDS},
                }
            )
            migrated += 1
            print(f"[{db_name}] {key}: {len(plaintext)} segredo(s) → Vault {ref['path']} v{ref['version']}")

    print(f"\nConcluído: {migrated} provider(s) migrado(s), {skipped} já sem plaintext.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
