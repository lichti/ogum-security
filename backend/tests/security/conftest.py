"""Perfil da suíte de segurança.

AUTH_ENABLED pina em False por default; os testes que validam o gate de auth
(test_rbac) ligam o flag explicitamente por classe. Registro dos tenants de
teste em sessão (allowlist do resolver estrito, US-06.10).
"""

import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _security_auth_profile(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_ENABLED", False)


# `_registered_test_tenants` (session, tests/conftest.py) é herdada pela
# cadeia de conftests; os testes desta pasta precisam dela registrada porque
# o resolver estrito (US-06.10) exige allowlist — sempre.


@pytest.fixture(scope="session", autouse=True)
def _ensure_registered_test_tenants(_registered_test_tenants):
    yield _registered_test_tenants
