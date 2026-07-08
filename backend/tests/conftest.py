"""
Global test fixtures for Ogum Security backend.

Rules enforced here:
- ArangoDB: always real instance, never mocked (test env via Docker)
- Redis: always real instance, never mocked
- Cloud provider APIs (boto3, azure-sdk, gcp): mocked at SDK level in each test
- Celery: EAGER mode in unit/security tests; real worker in integration/tasks
"""

import os

import pytest
from arango import ArangoClient

# ─── Constants ────────────────────────────────────────────────────────────────

_arango_host = os.getenv("ARANGO_HOST", "localhost")
_arango_port = os.getenv("ARANGO_PORT", "8529")
ARANGO_URL = os.getenv("ARANGO_URL", f"http://{_arango_host}:{_arango_port}")
# Use ARANGO_PASSWORD to match app/core/config.py — docker-compose maps ARANGO_ROOT_PASSWORD to this
ARANGO_PASSWORD = os.getenv("ARANGO_PASSWORD", "changeme")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")

TEST_TENANT_A = "test-tenant-aaa"
TEST_TENANT_B = "test-tenant-bbb"

_DB_NAME_A = f"ogum_{TEST_TENANT_A}"
_DB_NAME_B = f"ogum_{TEST_TENANT_B}"


# ─── ArangoDB fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def arango_client() -> ArangoClient:
    """Single ArangoDB client shared across the test session."""
    return ArangoClient(hosts=ARANGO_URL)


@pytest.fixture(scope="session")
def sys_db(arango_client: ArangoClient):
    """System database for tenant provisioning/teardown."""
    return arango_client.db("_system", username="root", password=ARANGO_PASSWORD)


def _provision_tenant_db(sys_db, arango_client: ArangoClient, db_name: str):
    """Create a clean tenant database and return it."""
    if sys_db.has_database(db_name):
        sys_db.delete_database(db_name)
    sys_db.create_database(db_name)
    return arango_client.db(db_name, username="root", password=ARANGO_PASSWORD)


@pytest.fixture
def db_tenant_a(sys_db, arango_client: ArangoClient):
    """Clean ArangoDB database for Tenant A. Dropped after each test."""
    db = _provision_tenant_db(sys_db, arango_client, _DB_NAME_A)
    yield db
    if sys_db.has_database(_DB_NAME_A):
        sys_db.delete_database(_DB_NAME_A)


@pytest.fixture
def db_tenant_b(sys_db, arango_client: ArangoClient):
    """Clean ArangoDB database for Tenant B. Dropped after each test."""
    db = _provision_tenant_db(sys_db, arango_client, _DB_NAME_B)
    yield db
    if sys_db.has_database(_DB_NAME_B):
        sys_db.delete_database(_DB_NAME_B)


# ─── FastAPI client fixture ───────────────────────────────────────────────────
# Uncomment and adapt once app.main exists.
#
# from app.main import app
# from app.core.security import create_access_token
#
# @pytest.fixture
# def api_client() -> TestClient:
#     return TestClient(app)
#
# @pytest.fixture
# def auth_headers_secops() -> dict:
#     token = create_access_token(
#         subject="user-001",
#         tenant_id=TEST_TENANT_A,
#         role="SecOps",
#     )
#     return {"Authorization": f"Bearer {token}"}
#
# @pytest.fixture
# def auth_headers_devops() -> dict:
#     token = create_access_token(
#         subject="user-002",
#         tenant_id=TEST_TENANT_A,
#         role="DevOps",
#     )
#     return {"Authorization": f"Bearer {token}"}


# ─── Celery EAGER mode ────────────────────────────────────────────────────────
# Import celery_app once app/celery.py exists:
#
# from app.worker import celery_app
#
# @pytest.fixture(autouse=True)
# def celery_eager(monkeypatch):
#     """Force synchronous task execution in unit and security tests."""
#     monkeypatch.setattr(celery_app.conf, "task_always_eager", True)
#     monkeypatch.setattr(celery_app.conf, "task_eager_propagates", True)
