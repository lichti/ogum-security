"""001 — baseline: materializa o schema atual (init_tenant_schema).

Ponto de partida do controle versionado: tenants criados antes do framework
de migrações (US-00.12) registram esta migração como aplicada, e o bootstrap
create-only de `db/init.py` permanece como base — migrações seguintes (002+)
partem daqui e nunca recriam o que o bootstrap já cria.
"""

from __future__ import annotations

from typing import Any


def up(db: Any) -> None:
    from app.db.init import init_tenant_schema

    init_tenant_schema(db)
