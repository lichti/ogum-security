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
# DELETE /api/v1/providers/{provider_id}
# ──────────────────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestProvidersDeleteEndpoint:
    def test_delete_existing_provider(self, api_client, mocker):
        mocker.patch("app.api.v1.providers.discover_aws.delay", return_value=mocker.MagicMock(id="j1"))
        post_resp = api_client.post(
            "/api/v1/providers",
            json={
                "provider": "aws",
                "display_name": "Temp",
                "account_id": "555555555555",
                "validate_connection": False,
            },
            headers=HEADERS,
        )
        provider_id = post_resp.json()["data"]["provider_id"]

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
