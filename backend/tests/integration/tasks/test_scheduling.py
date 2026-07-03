"""
Integration tests for the distributed Redis lock in scheduling.py.

Redis: real instance via Docker — never mocked (per CLAUDE.md).
"""

import os

import pytest
from redis import Redis

from app.workers.tasks.scheduling import acquire_lock, release_lock, trigger_all_discoveries

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")


@pytest.fixture
def redis_client() -> Redis:
    r: Redis = Redis.from_url(REDIS_URL)
    r.flushdb()
    yield r
    r.flushdb()


@pytest.mark.integration
class TestDistributedLock:
    """acquire_lock / release_lock — real Redis, no mocks."""

    def test_acquire_lock_succeeds_when_key_is_free(self, redis_client: Redis) -> None:
        assert acquire_lock(redis_client, "tenant-x", "azure") is True

    def test_acquire_lock_fails_when_key_is_already_held(self, redis_client: Redis) -> None:
        acquire_lock(redis_client, "tenant-x", "azure")
        assert acquire_lock(redis_client, "tenant-x", "azure") is False

    def test_release_lock_allows_re_acquisition(self, redis_client: Redis) -> None:
        acquire_lock(redis_client, "tenant-x", "azure")
        release_lock(redis_client, "tenant-x", "azure")
        assert acquire_lock(redis_client, "tenant-x", "azure") is True

    def test_lock_key_is_provider_specific(self, redis_client: Redis) -> None:
        acquire_lock(redis_client, "tenant-x", "azure")
        # Different provider → independent lock
        assert acquire_lock(redis_client, "tenant-x", "gcp") is True

    def test_lock_key_is_tenant_specific(self, redis_client: Redis) -> None:
        acquire_lock(redis_client, "tenant-a", "aws")
        # Different tenant → independent lock
        assert acquire_lock(redis_client, "tenant-b", "aws") is True


@pytest.mark.integration
class TestTriggerAllDiscoveries:
    """trigger_all_discoveries — dispatches the right task per provider."""

    def test_dispatches_aws_discovery(self, mocker) -> None:
        # trigger_all_discoveries imports tasks lazily — patch apply_async directly.
        mock_apply_async = mocker.patch("app.workers.tasks.discovery.discover_aws.apply_async")

        result = trigger_all_discoveries.apply(
            kwargs={"tenant_id": "t1", "provider": "aws", "regions": ["eu-west-1"]}
        ).get()

        assert result["dispatched"] is True
        assert result["provider"] == "aws"
        mock_apply_async.assert_called_once()

    def test_returns_error_for_unknown_provider(self) -> None:
        result = trigger_all_discoveries.apply(kwargs={"tenant_id": "t1", "provider": "unknown"}).get()

        assert result["dispatched"] is False
        assert "unknown_provider" in result["reason"]
