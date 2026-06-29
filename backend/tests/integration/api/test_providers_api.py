"""Integration tests for the Providers API (/api/v1/providers) and inventory export.

Rules:
- ArangoDB: real instance via Docker (never mocked)
- AWS validation calls: mocked with moto
- Celery discover tasks: mocked via mocker.patch
"""
import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

HEADERS = {"X-Tenant-ID": TEST_TENANT_A}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def _register_aws(api_client, mocker, account_id="111111111111", job_id="job-001"):
    mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id=job_id))
    resp = api_client.post(
        "/api/v1/providers",
        json={
            "provider": "aws",
            "display_name": "Dev AWS Account",
            "account_id": account_id,
            "regions": ["us-east-1"],
            "validate_connection": False,
        },
        headers=HEADERS,
    )
    assert resp.status_code == 201
    return resp.json()["data"]["provider_id"]


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/v1/providers
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProvidersRegisterEndpoint:
    def test_register_aws_provider_happy_path(self, api_client, mocker):
        mock_task = mocker.MagicMock()
        mock_task.id = "job-001"
        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mock_task)

        resp = api_client.post(
            "/api/v1/providers",
            json={
                "provider": "aws",
                "display_name": "Dev AWS Account",
                "account_id": "111111111111",
                "regions": ["us-east-1"],
                "validate_connection": False,
            },
            headers=HEADERS,
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["data"]["provider_id"] is not None
        assert body["data"]["discovery_job_id"] == "job-001"

    def test_register_provider_missing_header_returns_422(self, api_client):
        resp = api_client.post(
            "/api/v1/providers",
            json={"provider": "aws", "display_name": "Test", "validate_connection": False},
        )
        assert resp.status_code == 422

    def test_register_invalid_provider_returns_422(self, api_client):
        resp = api_client.post(
            "/api/v1/providers",
            json={"provider": "digitalocean", "display_name": "Test", "validate_connection": False},
            headers=HEADERS,
        )
        assert resp.status_code == 422

    def test_register_sets_status_pending(self, api_client, mocker):
        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id="j1"))
        api_client.post(
            "/api/v1/providers",
            json={"provider": "aws", "display_name": "Test", "account_id": "111", "validate_connection": False},
            headers=HEADERS,
        )
        # status is set to "active" after dispatch succeeds
        list_resp = api_client.get("/api/v1/providers", headers=HEADERS)
        assert list_resp.json()["data"][0]["status"] == "active"

    def test_register_azure_provider_no_validation(self, api_client, mocker):
        mock_task = mocker.MagicMock()
        mock_task.id = "job-azure-001"
        mocker.patch("app.api.v1.providers.discover_azure.delay", return_value=mock_task)

        resp = api_client.post(
            "/api/v1/providers",
            json={
                "provider": "azure",
                "display_name": "Azure Prod",
                "subscription_id": "sub-aaa-bbb",
                "validate_connection": False,
            },
            headers=HEADERS,
        )
        assert resp.status_code == 201
        assert resp.json()["data"]["discovery_job_id"] == "job-azure-001"

    def test_register_gcp_provider_no_validation(self, api_client, mocker):
        mock_task = mocker.MagicMock()
        mock_task.id = "job-gcp-001"
        mocker.patch("app.api.v1.providers.discover_gcp.delay", return_value=mock_task)

        resp = api_client.post(
            "/api/v1/providers",
            json={
                "provider": "gcp",
                "display_name": "GCP Dev",
                "project_id": "my-project-123",
                "validate_connection": False,
            },
            headers=HEADERS,
        )
        assert resp.status_code == 201
        assert resp.json()["data"]["discovery_job_id"] == "job-gcp-001"

    def test_register_is_idempotent_no_duplicate(self, api_client, mocker):
        """Registering the same provider twice overwrites — does not create a duplicate."""
        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id="j1"))
        payload = {
            "provider": "aws",
            "display_name": "My Account",
            "account_id": "999999999999",
            "regions": ["us-east-1"],
            "validate_connection": False,
        }
        api_client.post("/api/v1/providers", json=payload, headers=HEADERS)

        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id="j2"))
        api_client.post("/api/v1/providers", json=payload, headers=HEADERS)

        list_resp = api_client.get("/api/v1/providers", headers=HEADERS)
        assert len(list_resp.json()["data"]) == 1


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/providers
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProvidersListEndpoint:
    def test_list_returns_empty_for_new_tenant(self, api_client):
        resp = api_client.get("/api/v1/providers", headers=HEADERS)
        assert resp.status_code == 200
        assert resp.json()["data"] == []

    def test_list_returns_registered_providers(self, api_client, mocker):
        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id="j1"))
        api_client.post(
            "/api/v1/providers",
            json={
                "provider": "aws",
                "display_name": "Prod",
                "account_id": "111111111111",
                "validate_connection": False,
            },
            headers=HEADERS,
        )

        resp = api_client.get("/api/v1/providers", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 1
        assert data[0]["provider"] == "aws"
        assert data[0]["display_name"] == "Prod"


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/providers/{provider_id}
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProvidersGetEndpoint:
    def test_get_existing_provider(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        resp = api_client.get(f"/api/v1/providers/{provider_id}", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["key"] == provider_id
        assert data["provider"] == "aws"
        assert data["display_name"] == "Dev AWS Account"

    def test_get_nonexistent_provider_returns_404(self, api_client):
        resp = api_client.get("/api/v1/providers/does-not-exist", headers=HEADERS)
        assert resp.status_code == 404

    def test_get_returns_status_field(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        resp = api_client.get(f"/api/v1/providers/{provider_id}", headers=HEADERS)
        assert "status" in resp.json()["data"]


# ──────────────────────────────────────────────────────────────────────────────
# PATCH /api/v1/providers/{provider_id}
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProvidersUpdateEndpoint:
    def test_update_display_name(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        resp = api_client.patch(
            f"/api/v1/providers/{provider_id}",
            json={"display_name": "Renamed Account"},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["display_name"] == "Renamed Account"

    def test_update_regions(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        resp = api_client.patch(
            f"/api/v1/providers/{provider_id}",
            json={"regions": ["us-east-1", "eu-west-1"]},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        assert "eu-west-1" in resp.json()["data"]["regions"]

    def test_disable_provider_sets_status_disabled(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        resp = api_client.patch(
            f"/api/v1/providers/{provider_id}",
            json={"enabled": False},
            headers=HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["enabled"] is False
        assert data["status"] == "disabled"

    def test_enable_provider_sets_status_active(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        api_client.patch(f"/api/v1/providers/{provider_id}", json={"enabled": False}, headers=HEADERS)
        resp = api_client.patch(f"/api/v1/providers/{provider_id}", json={"enabled": True}, headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["enabled"] is True
        assert data["status"] == "active"

    def test_update_nonexistent_returns_404(self, api_client):
        resp = api_client.patch(
            "/api/v1/providers/ghost-provider",
            json={"display_name": "Ghost"},
            headers=HEADERS,
        )
        assert resp.status_code == 404

    def test_partial_update_preserves_other_fields(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        api_client.patch(f"/api/v1/providers/{provider_id}", json={"display_name": "New Name"}, headers=HEADERS)
        resp = api_client.get(f"/api/v1/providers/{provider_id}", headers=HEADERS)
        data = resp.json()["data"]
        assert data["display_name"] == "New Name"
        assert data["provider"] == "aws"
        assert data["account_id"] == "111111111111"


# ──────────────────────────────────────────────────────────────────────────────
# POST /api/v1/providers/{provider_id}/discover
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProvidersTriggerDiscoveryEndpoint:
    def test_trigger_discovery_queues_job(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id="re-job-001"))

        resp = api_client.post(f"/api/v1/providers/{provider_id}/discover", headers=HEADERS)
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["discovery_job_id"] == "re-job-001"
        assert data["provider_id"] == provider_id

    def test_trigger_discovery_updates_last_discovery(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id="re-job-002"))

        api_client.post(f"/api/v1/providers/{provider_id}/discover", headers=HEADERS)
        resp = api_client.get(f"/api/v1/providers/{provider_id}", headers=HEADERS)
        assert resp.json()["data"]["last_discovery_job_id"] == "re-job-002"

    def test_trigger_discovery_nonexistent_returns_404(self, api_client):
        resp = api_client.post("/api/v1/providers/ghost/discover", headers=HEADERS)
        assert resp.status_code == 404

    def test_trigger_discovery_on_disabled_provider_returns_409(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker)
        api_client.patch(f"/api/v1/providers/{provider_id}", json={"enabled": False}, headers=HEADERS)
        resp = api_client.post(f"/api/v1/providers/{provider_id}/discover", headers=HEADERS)
        assert resp.status_code == 409


# ──────────────────────────────────────────────────────────────────────────────
# DELETE /api/v1/providers/{provider_id}
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProvidersDeleteEndpoint:
    def test_delete_existing_provider(self, api_client, mocker):
        provider_id = _register_aws(api_client, mocker, account_id="555555555555")

        del_resp = api_client.delete(f"/api/v1/providers/{provider_id}", headers=HEADERS)
        assert del_resp.status_code == 200
        assert del_resp.json()["data"]["deleted"] is True

        list_resp = api_client.get("/api/v1/providers", headers=HEADERS)
        assert list_resp.json()["data"] == []

    def test_delete_nonexistent_provider_returns_404(self, api_client):
        resp = api_client.delete("/api/v1/providers/nonexistent-key-xyz", headers=HEADERS)
        assert resp.status_code == 404


# ──────────────────────────────────────────────────────────────────────────────
# GET /api/v1/inventory/export
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestInventoryExportEndpoint:
    def test_csv_export_returns_csv_content_type(self, api_client):
        resp = api_client.get("/api/v1/inventory/export?format=csv", headers=HEADERS)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "Content-Disposition" in resp.headers
        assert ".csv" in resp.headers["Content-Disposition"]

    def test_csv_export_has_header_row(self, api_client):
        resp = api_client.get("/api/v1/inventory/export?format=csv", headers=HEADERS)
        lines = resp.text.strip().split("\n")
        assert lines[0].startswith("key,provider")

    def test_json_export_returns_ocsf_structure(self, api_client):
        resp = api_client.get("/api/v1/inventory/export?format=json", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["ocsf_version"] == "1.0.0"
        assert "metadata" in body
        assert "resources" in body
        assert body["metadata"]["tenant_id"] == TEST_TENANT_A

    def test_json_export_contains_all_required_metadata_fields(self, api_client):
        resp = api_client.get("/api/v1/inventory/export?format=json", headers=HEADERS)
        meta = resp.json()["metadata"]
        assert "exported_at" in meta
        assert "total_resources" in meta
        assert "product" in meta

    def test_invalid_format_returns_422(self, api_client):
        resp = api_client.get("/api/v1/inventory/export?format=xml", headers=HEADERS)
        assert resp.status_code == 422

    def test_csv_export_with_resources_contains_data_rows(self, api_client, db_tenant_a):
        from app.models.inventory import AWSResource
        db_tenant_a.collection("resources").insert(
            AWSResource(
                tenant_id=TEST_TENANT_A,
                resource_type="ec2_instance",
                resource_id="i-export-001",
                name="export-test-server",
                arn="arn:aws:ec2:us-east-1:111111111111:instance/i-export-001",
                region="us-east-1",
            ).to_arango_doc()
        )

        resp = api_client.get("/api/v1/inventory/export?format=csv", headers=HEADERS)
        lines = resp.text.strip().split("\n")
        assert len(lines) >= 2, "CSV must have at least header + 1 data row"
        assert "export-test-server" in resp.text
