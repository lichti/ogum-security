"""Perfil da suíte de API de integração.

AUTH_ENABLED é pinado em False aqui (perfil dev): a suíte de API valida os
handlers, não o gate de auth — esse é coberto ponta a ponta por
tests/security/test_rbac.py (que liga o flag explicitamente). O default de
produção é True (ADR-016); conversão da suíte inteira para tokens é o
follow-up registrado no épico.
"""

import pytest

from app.core.config import settings


@pytest.fixture(autouse=True)
def _dev_auth_profile(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_ENABLED", False)
