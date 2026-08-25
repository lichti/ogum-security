"""Unit tests for provider health evaluation and live probe orchestration."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from app.models.provider import ProviderConfig
from app.services.provider_health import (
    STALE_AFTER_HOURS,
    evaluate_cached_health,
    run_connection_test,
)


def make_config(**overrides) -> ProviderConfig:
    defaults = {
        "key": "aws-111111111111",
        "provider": "aws",
        "display_name": "Test AWS",
        "account_id": "111111111111",
        "status": "active",
        "enabled": True,
        "credential_type": "role",
        "role_arn": "arn:aws:iam::111111111111:role/ogum",
        "external_id": "ext-123",
        "last_discovery_at": datetime.now(UTC).isoformat(),
    }
    defaults.update(overrides)
    return ProviderConfig(**defaults)


@pytest.mark.unit
class TestEvaluateCachedHealth:
    def test_active_with_recent_discovery_is_healthy(self):
        result = evaluate_cached_health(make_config())
        assert result.health == "healthy"
        assert result.live is False

    def test_disabled_provider_is_degraded(self):
        result = evaluate_cached_health(make_config(enabled=False))
        assert result.health == "degraded"
        assert "disabled" in (result.reason or "")

    def test_error_status_is_failed(self):
        result = evaluate_cached_health(
            make_config(status="error", last_health_result="AssumeRole denied")
        )
        assert result.health == "failed"
        assert result.reason == "AssumeRole denied"

    def test_pending_without_discovery_is_degraded(self):
        result = evaluate_cached_health(make_config(status="pending", last_discovery_at=None))
        assert result.health == "degraded"
        assert "no successful discovery" in (result.reason or "")

    def test_stale_discovery_is_degraded(self):
        stale = (datetime.now(UTC) - timedelta(hours=STALE_AFTER_HOURS + 5)).isoformat()
        result = evaluate_cached_health(make_config(last_discovery_at=stale))
        assert result.health == "degraded"
        assert "stale" in (result.reason or "") or f"> {STALE_AFTER_HOURS}h" in (result.reason or "")


@pytest.mark.unit
class TestRunConnectionTest:
    def _db(self):
        return MagicMock()

    @patch("app.services.provider_health.get_provider_credentials", return_value={})
    def test_successful_probe_persists_active_and_returns_healthy(self, creds_mock):
        probe_mock = MagicMock(return_value="AWS account 111111111111 reachable via sts:GetCallerIdentity")
        db = self._db()
        with patch.dict("app.services.provider_health._PROBES", {"aws": probe_mock}):
            result = run_connection_test(db, make_config())

        assert result.health == "healthy"
        assert result.live is True
        assert result.status == "active"
        assert "111111111111" in (result.detail or "")
        assert result.latency_ms is not None
        db.collection.assert_called_once_with("tenant_config")

    @patch("app.services.provider_health.get_provider_credentials", return_value={})
    def test_failed_probe_persists_error_and_returns_failed(self, creds_mock):
        probe_mock = MagicMock(side_effect=Exception("The security token included in the request is invalid"))
        db = self._db()
        with patch.dict("app.services.provider_health._PROBES", {"aws": probe_mock}):
            result = run_connection_test(db, make_config())

        assert result.health == "failed"
        assert result.live is True
        assert result.status == "error"
        assert "security token" in (result.detail or "")
        update_doc = db.collection.return_value.update.call_args[0][0]
        assert update_doc["status"] == "error"

    @patch("app.services.provider_health.get_provider_credentials")
    def test_probe_receives_stored_credentials(self, creds_mock):
        creds_mock.return_value = {"aws_access_key_id": "AKIA...", "aws_secret_access_key": "secret"}
        probe_mock = MagicMock(return_value="ok")
        db = self._db()
        with patch.dict("app.services.provider_health._PROBES", {"aws": probe_mock}):
            run_connection_test(db, make_config())
        stored_arg = probe_mock.call_args[0][1]
        assert stored_arg["aws_access_key_id"] == "AKIA..."

    def test_unknown_provider_fails_without_probe(self):
        config = make_config(key="unknown-x", provider="k8s")  # k8s has a probe; use a fake one
        config = config.model_copy(update={"provider": "oci"})
        with patch.dict("app.services.provider_health._PROBES", {}, clear=True):
            result = run_connection_test(self._db(), config)
        assert result.health == "failed"
        assert "no probe implemented" in (result.reason or "")

    @patch("app.services.provider_health.get_provider_credentials", return_value={"kubeconfig": {"apiVersion": "v1"}})
    def test_k8s_probe_dispatches_to_k8s_handler(self, creds_mock):
        k8s_probe = MagicMock(return_value="Kubernetes cluster 'dev' reachable (3 namespace(s) visible)")
        config = make_config(key="k8s-dev-cluster", provider="k8s", cluster_name="dev")
        with patch.dict("app.services.provider_health._PROBES", {"k8s": k8s_probe}):
            result = run_connection_test(self._db(), config)
        assert result.health == "healthy"
        assert "namespace" in (result.detail or "")
