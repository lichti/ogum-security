"""Perfil da suíte de integração: tenants de teste registrados (US-06.10 —
o resolver estrito exige allowlist em `_system.tenants`)."""

import pytest


@pytest.fixture(scope="session", autouse=True)
def _ensure_registered_test_tenants(_registered_test_tenants):
    yield _registered_test_tenants
