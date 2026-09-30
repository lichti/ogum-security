"""Boot seguro em produção (US-06.10).

Executado no lifespan quando `APP_ENV=production`: configurações perigosas
**impedem o boot** — defaults de segredo, Vault não configurado ou não
autenticado são condições de parada, nunca avisos.
"""

from __future__ import annotations

import logging

from app.core.config import settings

logger = logging.getLogger(__name__)

_INSECURE_DEFAULTS = {
    "APP_SECRET_KEY": "change-me-in-production",
    "ARANGO_PASSWORD": "changeme",
}


class ProductionConfigError(RuntimeError):
    pass


def validate_production_config() -> None:
    problems: list[str] = []
    for field, default in _INSECURE_DEFAULTS.items():
        if getattr(settings, field) == default:
            problems.append(f"{field} is still the insecure default")
    if settings.JWT_ALGORITHM.startswith("HS") and not settings.JWT_SECRET_KEY:
        problems.append("JWT_SECRET_KEY is empty (HS256 falls back to APP_SECRET_KEY)")
    if not settings.VAULT_ENABLED or not settings.VAULT_ADDR or not settings.VAULT_TOKEN:
        problems.append("Vault is not configured (VAULT_ENABLED/VAULT_ADDR/VAULT_TOKEN)")
    if not settings.CORS_ORIGINS or "*" in settings.CORS_ORIGINS:
        problems.append("CORS_ORIGINS must be an explicit origin list in production")

    if problems:
        raise ProductionConfigError("Insecure production configuration: " + "; ".join(problems))

    # Reachability: falha o boot se o Vault não autentica (credencial store é
    # dependência de disponibilidade desde a US-06.11/ADR-015).
    from app.services import vault_client

    try:
        vault_client._client().is_authenticated()
    except Exception as exc:
        raise ProductionConfigError(f"Vault is not reachable/authenticated: {exc}") from exc

    logger.info("Production configuration validated (secrets defaults, Vault, CORS)")
