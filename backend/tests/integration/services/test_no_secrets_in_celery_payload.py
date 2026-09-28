"""US-06.12 — nenhum segredo no payload Celery.

Os pontos de despacho devem carregar apenas identificadores (provider_id,
tenant_id); os segredos são resolvidos no worker via Vault. Este teste
captura os kwargs publicados e falha se qualquer valor de segredo vazar.
"""

from typing import Any

import pytest

from app.models.provider import ProviderRegisterRequest
from app.services import provider_service
from app.services.side_scanning import trigger

pytestmark = pytest.mark.integration

SECRET = "supersecret-do-not-ship"
TENANT = "payload-tenant"


def _register(db) -> str:
    return provider_service.register_provider(
        db,
        TENANT,
        ProviderRegisterRequest(
            provider="aws",
            display_name="Payload IT",
            account_id="123456789012",
            regions=["us-east-1"],
            aws_secret_access_key=SECRET,
            validate_connection=False,
        ),
    ).key


def test_enqueue_side_scan_payload_has_no_secrets(db_tenant_a, mocker, monkeypatch):
    provider_key = _register(db_tenant_a)
    resource = {
        "_key": "ec2_instance/i-123",
        "resource_type": "ec2_instance",
        "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
        "region": "us-east-1",
        "account_id": "123456789012",
    }

    captured: dict[str, Any] = {}

    class _FakeTask:
        def delay(self, **kwargs):
            captured.update(kwargs)
            return None

    monkeypatch.setattr(trigger, "scan_ec2_instance_v2", _FakeTask())
    mocker.patch.object(
        trigger,
        "resolve_ec2_scan_metadata",
        return_value={"i-123": {"volume_id": "vol-123", "availability_zone": "us-east-1a"}},
    )

    job_id = trigger.enqueue_side_scan(db_tenant_a, TENANT, resource, provider_key)
    assert job_id

    assert captured.get("provider_id") == provider_key
    dumped = repr(captured)
    assert SECRET not in dumped
    for forbidden in ("aws_secret_access_key", "gcp_service_account_json", "kubeconfig"):
        assert forbidden not in dumped


def test_register_then_doc_never_holds_secret(db_tenant_a):
    provider_key = _register(db_tenant_a)
    doc = db_tenant_a.collection("tenant_config").get(provider_key)
    assert doc["credentials_vault_path"] is None or "tenants/" in doc["credentials_vault_path"]
    assert doc.get("aws_secret_access_key") is None
