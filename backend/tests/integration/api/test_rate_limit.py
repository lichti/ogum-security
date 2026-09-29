"""US-06.13 — rate limiting por tenant.

Fixed-window no Redis; estourou → 429 com `Retry-After` e `X-RateLimit-*`.
Isento: `/health` e webhooks de scanner. Redis indisponível → fail-open.
"""

import pytest
from fastapi.testclient import TestClient

from app.core import middleware as mw
from app.core.config import settings
from app.main import app

pytestmark = pytest.mark.integration

TENANT = "rl-tenant"


@pytest.fixture(autouse=True)
def _low_limit(monkeypatch, _registered_test_tenants):
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_SECOND", 3)
    # Janela longa: determinístico — requests de inventory custam ~300ms cada
    # e atravessariam janelas de 1s (o sweep do teste limpa a janela antes).
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_SECONDS", 3600)
    monkeypatch.setattr(settings, "AUTH_ENABLED", False)
    _flush_window()
    from app.services import tenant_registry

    tenant_registry.register_tenant(TENANT)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _flush_window():
    try:
        redis = mw._rl_redis()
        for key in redis.scan_iter("ogum:rl:*"):
            redis.delete(key)
    except Exception:
        pass


def test_rate_limit_headers_on_success(client):
    _flush_window()
    response = client.get("/api/v1/inventory", headers={"X-Tenant-ID": TENANT})
    assert response.status_code == 200
    assert response.headers["x-ratelimit-limit"] == "3"
    assert response.headers["x-ratelimit-remaining"] == "2"


def test_health_is_exempt(client):
    _flush_window()
    for _ in range(6):
        assert client.get("/health").status_code == 200


def test_redis_unavailable_fails_open(client, monkeypatch):
    _flush_window()

    class _Broken:
        def incr(self, *a, **kw):
            raise ConnectionError("redis down")

    monkeypatch.setattr(mw, "_rl_redis", lambda: _Broken())
    for _ in range(6):
        response = client.get("/api/v1/inventory", headers={"X-Tenant-ID": TENANT})
        assert response.status_code == 200
