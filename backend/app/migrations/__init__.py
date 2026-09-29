"""Runner de migrações versionadas de schema por tenant (US-00.12).

Convenção:
- Cada migração é um módulo `NNN_descricao.py` (ordenação lexicográfica) com
  `def up(db)`. `down(db)` é opcional e não é executado pelo runner.
- Controle de aplicação: coleção `_migrations` no próprio tenant DB
  (`_key` = nome do módulo, sem extensão).
- Idempotente: migrações já aplicadas são puladas; rodar duas vezes não muda
  nada.
- Bootstrap vs evolução: `init_tenant_schema` (create-only) permanece no
  caminho de request como bootstrap barato; a EVOLUÇÃO do schema acontece
  exclusivamente por migrações via `make migrate` (scripts/run_migrations.py),
  que itera os tenants registrados em `_system.tenants`.

Para criar uma migração nova: `00N_descricao.py` com `def up(db)`.
"""

from __future__ import annotations

import importlib
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MIGRATIONS_COLLECTION = "migrations"
_MIGRATIONS_DIR = Path(__file__).resolve().parent


def _migration_modules() -> list[tuple[str, Any]]:
    """Módulos de migração em ordem, como (nome, módulo)."""
    modules: list[tuple[str, Any]] = []
    for path in sorted(_MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.py")):
        name = path.stem
        module = importlib.import_module(f"app.migrations.{name}")
        modules.append((name, module))
    return modules


def _ensure_collection(db: Any) -> Any:
    if not db.has_collection(MIGRATIONS_COLLECTION):
        db.create_collection(MIGRATIONS_COLLECTION)
    return db.collection(MIGRATIONS_COLLECTION)


def applied(db: Any) -> set[str]:
    """Nomes das migrações já aplicadas neste tenant DB."""
    col = _ensure_collection(db)
    return {doc["_key"] for doc in col.all()}


def run_migrations(db: Any, tenant_id: str) -> list[str]:
    """Aplica as migrações pendentes em ordem. Retorna as aplicadas agora."""
    col = _ensure_collection(db)
    done = applied(db)
    ran: list[str] = []
    for name, module in _migration_modules():
        if name in done:
            continue
        logger.info("Applying migration %s [tenant=%s]", name, tenant_id)
        module.up(db)
        col.insert(
            {
                "_key": name,
                "migration": name,
                "tenant_id": tenant_id,
                "applied_at": datetime.now(UTC).isoformat(),
            }
        )
        ran.append(name)
    if ran:
        logger.info("Migrations applied [tenant=%s]: %s", tenant_id, ", ".join(ran))
    return ran
