"""RBAC — roles, permissões e gate declarativo (Epic 06 Sprint 1).

Módulo puro: nenhuma importação de FastAPI no nível de módulo, para poder ser
consumido por workers e testes sem o app. O gate `require_permission` importa
`get_current_user` de forma lazy para evitar dependência circular.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.deps import CurrentUser

# Permissão curinga: PlatformAdmin não precisa estar listada em cada conjunto.
WILDCARD_PERMISSION = "*"


class Role(StrEnum):
    PlatformAdmin = "PlatformAdmin"
    SecOps = "SecOps"
    DevOps = "DevOps"
    Auditor = "Auditor"


ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.PlatformAdmin: {WILDCARD_PERMISSION},
    Role.SecOps: {
        "findings:read",
        "findings:mute",
        "findings:accept",
        "inventory:read",
        "scans:trigger",
        "scans:read",
        "incidents:read",
        "incidents:approve_tier2",
        "incidents:resolve",
        "attack_paths:read",
        "remediation:generate",
        "remediation:open_pr",
        "chat:use",
    },
    Role.DevOps: {
        "findings:read",
        "inventory:read",
        "scans:read",
        "attack_paths:read",
        "chat:use",
    },
    Role.Auditor: {
        "findings:read",
        "inventory:read",
        "compliance:read",
        "audit_log:read",
        "scans:read",
        "attack_paths:read",
    },
}


def has_permission(role: Role, permission: str) -> bool:
    granted = ROLE_PERMISSIONS.get(role, set())
    return WILDCARD_PERMISSION in granted or permission in granted


def require_permission(permission: str) -> Callable[..., CurrentUser]:
    """Fábrica de dependência FastAPI: 403 se a role não tem a permissão.

    Uso: `user: CurrentUser = Depends(require_permission("scans:trigger"))`.
    Import preguiçoso de `get_current_user` — `deps.py` importa este módulo.
    """

    def dependency(user: CurrentUser) -> CurrentUser:
        from fastapi import HTTPException, status

        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' does not grant '{permission}'",
            )
        return user

    return dependency
