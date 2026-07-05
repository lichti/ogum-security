"""
Integration tests for the distributed Redis lock in scheduling.py.

Redis: real instance via Docker — never mocked (per CLAUDE.md).
"""

import os

import pytest
from redis import Redis

from app.workers.tasks.scheduling import acquire_lock, release_lock, trigger_all_cspm_scans, trigger_all_discoveries

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


@pytest.mark.integration
class TestTriggerAllCspmScans:
    """trigger_all_cspm_scans — iterates tenants and dispatches run_cspm_scan.

    Lazy imports inside the task function mean patches must target source modules,
    not app.workers.tasks.scheduling.* (those bindings don't exist at module level).
    """

    def _mock_arango(self, mocker, db_names: list[str]):
        """Return a mock ArangoClient whose sys_db.databases() yields db_names."""
        mock_client = mocker.MagicMock()
        mock_sys_db = mocker.MagicMock()
        mock_sys_db.databases.return_value = db_names
        mock_client.db.return_value = mock_sys_db
        mocker.patch("arango.ArangoClient", return_value=mock_client)
        return mock_client

    def test_dispatches_cspm_for_enabled_aws_provider(self, mocker) -> None:
        """One enabled AWS provider → one run_cspm_scan dispatched with CIS-AWS-2.0."""
        from app.models.provider import ProviderConfig

        provider = ProviderConfig(
            key="aws-123456789",
            provider="aws",
            display_name="Dev AWS",
            account_id="123456789",
            regions=["us-east-1"],
            enabled=True,
            status="active",
            credential_type="role",
        )
        self._mock_arango(mocker, ["_system", "ogum_test-tenant"])
        mocker.patch("app.services.provider_service.list_providers", return_value=[provider])
        mocker.patch(
            "app.services.provider_service.get_provider_credentials",
            return_value={"role_arn": "arn:aws:iam::123:role/OgumRole"},
        )
        mock_apply = mocker.patch("app.workers.tasks.cspm_scan.run_cspm_scan.apply_async")

        result = trigger_all_cspm_scans.apply().get()

        assert result["dispatched"] == 1
        assert result["skipped"] == 0
        mock_apply.assert_called_once()
        kwargs = mock_apply.call_args.kwargs["kwargs"]
        assert kwargs["provider"] == "aws"
        assert kwargs["frameworks"] == ["CIS-AWS-2.0"]
        assert kwargs["tenant_id"] == "test-tenant"

    def test_skips_disabled_provider(self, mocker) -> None:
        """Disabled provider → zero tasks dispatched."""
        from app.models.provider import ProviderConfig

        provider = ProviderConfig(
            key="aws-disabled",
            provider="aws",
            display_name="Disabled",
            account_id="999",
            enabled=False,
            status="disabled",
            credential_type="role",
        )
        self._mock_arango(mocker, ["ogum_test-tenant"])
        mocker.patch("app.services.provider_service.list_providers", return_value=[provider])
        mocker.patch("app.services.provider_service.get_provider_credentials", return_value={})
        mock_apply = mocker.patch("app.workers.tasks.cspm_scan.run_cspm_scan.apply_async")

        result = trigger_all_cspm_scans.apply().get()

        assert result["dispatched"] == 0
        assert result["skipped"] == 1
        mock_apply.assert_not_called()

    def test_skips_k8s_provider(self, mocker) -> None:
        """k8s has no supported CSPM framework → skipped."""
        from app.models.provider import ProviderConfig

        provider = ProviderConfig(
            key="k8s-cluster",
            provider="k8s",
            display_name="Dev cluster",
            cluster_name="dev",
            enabled=True,
            status="active",
            credential_type="incluster",
        )
        self._mock_arango(mocker, ["ogum_test-tenant"])
        mocker.patch("app.services.provider_service.list_providers", return_value=[provider])
        mocker.patch("app.services.provider_service.get_provider_credentials", return_value={})
        mock_apply = mocker.patch("app.workers.tasks.cspm_scan.run_cspm_scan.apply_async")

        result = trigger_all_cspm_scans.apply().get()

        assert result["dispatched"] == 0
        assert result["skipped"] == 1
        mock_apply.assert_not_called()

    def test_ignores_non_tenant_databases(self, mocker) -> None:
        """System databases (_system, ogum_admin) are not treated as tenants."""
        self._mock_arango(mocker, ["_system", "ogum_admin", "_graphs"])
        mocker.patch("app.services.provider_service.list_providers", return_value=[])
        mocker.patch("app.services.provider_service.get_provider_credentials", return_value={})
        mock_apply = mocker.patch("app.workers.tasks.cspm_scan.run_cspm_scan.apply_async")

        result = trigger_all_cspm_scans.apply().get()

        assert result["dispatched"] == 0
        mock_apply.assert_not_called()
