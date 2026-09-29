"""Cliente ArangoDB compartilhado (US-00.11).

Um único `ArangoClient` por processo (FastAPI + workers importam o mesmo
singleton) — substitui as instâncias espalhadas que criavam pools concorrentes
de conexão a cada chamada.
"""

from __future__ import annotations

from functools import lru_cache

from arango import ArangoClient

from app.core.config import settings


@lru_cache(maxsize=1)
def get_arango_client() -> ArangoClient:
    """Singleton do driver python-arango (thread-safe; o driver gerencia o
    pool HTTP interno por host)."""
    return ArangoClient(hosts=f"http://{settings.ARANGO_HOST}:{settings.ARANGO_PORT}")
