#!/usr/bin/env python3
"""Bootstrap do token API interim por tenant (US-06.09).

Rode no servidor (ou no container do backend) para emitir o primeiro token de
um tenant sem depender de HTTP — resolve o ovo-e-galinha do gate: as rotas
admin exigem PlatformAdmin, e este script emite o primeiro token diretamente
via registro. O valor impresso vale uma única vez; emitir de novo revoga o
anterior.

    # Local (repo root)
    python backend/scripts/mint_tenant_token.py --tenant-id dev

    # Dentro do container do backend
    docker compose exec -T backend python scripts/mint_tenant_token.py \
        --tenant-id dev --platform-admin
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services import tenant_registry  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True, help="ID do tenant (ex.: dev)")
    parser.add_argument(
        "--platform-admin",
        action="store_true",
        help="Token com role PlatformAdmin (acesso às rotas /api/v1/admin/*)",
    )
    args = parser.parse_args()

    issued = tenant_registry.mint_api_token(args.tenant_id, platform_admin=args.platform_admin)
    print(f"tenant_id:      {issued.tenant_id}")
    print(f"platform_admin: {issued.platform_admin}")
    print(f"expires_at:     {issued.expires_at}")
    print()
    print("Guarde este valor agora — ele NÃO será exibido novamente:")
    print(issued.api_token)  # codeql[py/clear-text-logging-sensitive-data]: exibição única é o propósito do CLI
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
