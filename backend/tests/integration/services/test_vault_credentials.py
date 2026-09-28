"""Vault credential flow (US-06.11) — Vault e ArangoDB reais.

Cobre o caminho US-06.11/ADR-015: segredos vão exclusivamente para o Vault,
o documento em `tenant_config` guarda apenas a referência, a resolução no
worker não tem fallback para banco, e nenhuma query sobre `tenant_config`
materializa credencial (security).
"""

import pytest

from app.models.provider import ProviderRegisterRequest, ProviderUpdateRequest
from app.services import provider_service, vault_client
from tests.conftest import _provision_tenant_db

pytestmark = pytest.mark.integration

TENANT = "vault-it"
SECRET_KEY = "aws-123456789012"
SECRET_VALUE = "wJalrXUtnFEMI/test-secret-value"


@pytest.fixture
def vault_db(sys_db, arango_client):
    db = _provision_tenant_db(sys_db, arango_client, f"ogum_{TENANT}")
    yield db
    provider_doc = db.collection("tenant_config").get(SECRET_KEY) if db.has_collection("tenant_config") else None
    if provider_doc and provider_doc.get("credentials_vault_path"):
        try:
            vault_client.destroy_credentials(provider_doc["credentials_vault_path"])
        except vault_client.VaultError:
            pass
    if sys_db.has_database(f"ogum_{TENANT}"):
        sys_db.delete_database(f"ogum_{TENANT}")


def _register_request() -> ProviderRegisterRequest:
    return ProviderRegisterRequest(
        provider="aws",
        display_name="Vault IT",
        account_id="123456789012",
        regions=["us-east-1"],
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key=SECRET_VALUE,
        validate_connection=False,
    )


@pytest.mark.integration
def test_register_stores_secrets_only_in_vault(vault_db):
    config = provider_service.register_provider(vault_db, TENANT, _register_request())

    doc = vault_db.collection("tenant_config").get(config.key)
    assert doc["credentials_vault_path"] == f"tenants/{TENANT}/{SECRET_KEY}"
    assert doc["credentials_vault_version"] == 1
    for field in provider_service._SECRET_FIELDS:
        assert doc.get(field) is None

    stored = vault_client.load_credentials(doc["credentials_vault_path"])
    assert stored["aws_secret_access_key"] == SECRET_VALUE


@pytest.mark.integration
def test_resolve_returns_secrets_and_role_fields(vault_db):
    provider_service.register_provider(vault_db, TENANT, _register_request())
    resolved = provider_service.resolve_provider_credentials(vault_db, SECRET_KEY)
    assert resolved["aws_secret_access_key"] == SECRET_VALUE
    assert resolved["external_id"]  # campo não-secreto vindo do documento


@pytest.mark.integration
def test_update_rotates_secret_in_vault(vault_db):
    provider_service.register_provider(vault_db, TENANT, _register_request())
    new_secret = "rotated-secret-value"
    provider_service.update_provider(
        vault_db,
        SECRET_KEY,
        ProviderUpdateRequest(aws_secret_access_key=new_secret),
        tenant_id=TENANT,
    )
    resolved = provider_service.resolve_provider_credentials(vault_db, SECRET_KEY)
    assert resolved["aws_secret_access_key"] == new_secret
    doc = vault_db.collection("tenant_config").get(SECRET_KEY)
    assert doc["credentials_vault_version"] == 2


@pytest.mark.integration
def test_delete_destroys_vault_secret(vault_db):
    provider_service.register_provider(vault_db, TENANT, _register_request())
    doc = vault_db.collection("tenant_config").get(SECRET_KEY)
    path = doc["credentials_vault_path"]
    provider_service.delete_provider(vault_db, SECRET_KEY)
    with pytest.raises(vault_client.CredentialNotFoundError):
        vault_client.load_credentials(path)


@pytest.mark.security
def test_aql_over_tenant_config_never_materializes_credential(vault_db):
    provider_service.register_provider(vault_db, TENANT, _register_request())
    rows = list(vault_db.aql.execute("FOR c IN tenant_config RETURN c"))
    assert rows
    for doc in rows:
        for field in provider_service._SECRET_FIELDS:
            assert not doc.get(field), f"plaintext {field} em tenant_config!"
    dump = repr(rows)
    assert SECRET_VALUE not in dump


@pytest.mark.integration
def test_vault_unavailable_resolves_without_secrets_and_get_returns_empty(vault_db, monkeypatch):
    provider_service.register_provider(vault_db, TENANT, _register_request())
    monkeypatch.setattr(vault_client, "is_configured", lambda: False)

    # Resolução no worker: sem segredos (modo ambient), sem crash — e NUNCA
    # lê plaintext do banco (não há mais plaintext no documento).
    resolved = provider_service.resolve_provider_credentials(vault_db, SECRET_KEY)
    assert resolved.get("aws_secret_access_key") is None
    assert resolved["external_id"]

    # Probe server-side: credencial indisponível → {} (não exceção)
    assert provider_service.get_provider_credentials(vault_db, SECRET_KEY) == {}
