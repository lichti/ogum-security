"""Fixtures exclusivas da suíte unitária.

Vault desabilitado por padrão: testes unitários não tocam infraestrutura —
o fluxo de credenciais com Vault real é coberto em tests/integration e
tests/security (ArangoDB/Redis/Vault reais via Docker/CI).
"""

import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _vault_disabled(monkeypatch):
    monkeypatch.setattr(settings, "VAULT_ENABLED", False)
