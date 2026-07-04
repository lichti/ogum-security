"""Integration tests for GET /api/v1/findings/export."""

from __future__ import annotations

import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from app.api.v1.inventory import get_tenant_db
from app.db.init import init_tenant_schema
from app.main import app
from tests.conftest import TEST_TENANT_A

HEADERS = {"X-Tenant-Id": TEST_TENANT_A}


@pytest.fixture
def api_client(db_tenant_a):
    init_tenant_schema(db_tenant_a)
    app.dependency_overrides[get_tenant_db] = lambda: db_tenant_a
    client = TestClient(app, raise_server_exceptions=False)
    yield client
    app.dependency_overrides.clear()


def _seed(db, **overrides):
    doc = {
        "tenant_id": TEST_TENANT_A,
        "check_id": "check_s3_public",
        "title": "S3 Bucket Public",
        "description": "bucket allows public access",
        "resource_id": "my-bucket",
        "resource_arn": "arn:aws:s3:::my-bucket",
        "resource_type": "s3_bucket",
        "severity": "CRITICAL",
        "status": "FAIL",
        "provider": "aws",
        "region": "us-east-1",
        "account_id": "111111111111",
        "framework_mapping": ["CIS-AWS-2.0", "PCI_DSS"],
        "remediation": "Block public access",
        "remediation_code": None,
        "source": "cspm",
        "detected_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "mute_reason": None,
        "scan_job_id": None,
        **overrides,
    }
    db.collection("findings").insert(doc, overwrite=False)


@pytest.mark.integration
def test_export_csv_empty_returns_header_only(api_client) -> None:
    resp = api_client.get("/api/v1/findings/export?format=csv", headers=HEADERS)
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]
    reader = csv.DictReader(io.StringIO(resp.text))
    rows = list(reader)
    assert rows == []


@pytest.mark.integration
def test_export_csv_returns_findings(api_client, db_tenant_a) -> None:
    _seed(db_tenant_a)
    resp = api_client.get("/api/v1/findings/export?format=csv", headers=HEADERS)
    assert resp.status_code == 200
    reader = csv.DictReader(io.StringIO(resp.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["check_id"] == "check_s3_public"
    assert rows[0]["severity"] == "CRITICAL"
    # framework_mapping is pipe-joined in CSV
    assert "CIS-AWS-2.0" in rows[0]["framework_mapping"]


@pytest.mark.integration
def test_export_json_returns_findings(api_client, db_tenant_a) -> None:
    _seed(db_tenant_a)
    resp = api_client.get("/api/v1/findings/export?format=json", headers=HEADERS)
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    body = json.loads(resp.text)
    assert "data" in body
    assert len(body["data"]) == 1
    assert body["data"][0]["check_id"] == "check_s3_public"


@pytest.mark.integration
def test_export_csv_filename_contains_date(api_client) -> None:
    resp = api_client.get("/api/v1/findings/export?format=csv", headers=HEADERS)
    cd = resp.headers["content-disposition"]
    assert "findings_" in cd
    assert ".csv" in cd


@pytest.mark.integration
def test_export_csv_respects_severity_filter(api_client, db_tenant_a) -> None:
    _seed(db_tenant_a, check_id="critical_check", severity="CRITICAL")
    _seed(db_tenant_a, check_id="low_check", resource_id="other-bucket", severity="LOW")
    resp = api_client.get("/api/v1/findings/export?format=csv&severity=CRITICAL", headers=HEADERS)
    reader = csv.DictReader(io.StringIO(resp.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["check_id"] == "critical_check"


@pytest.mark.integration
def test_export_json_respects_source_filter(api_client, db_tenant_a) -> None:
    _seed(db_tenant_a, check_id="cspm_check", source="cspm")
    _seed(db_tenant_a, check_id="iac_check", resource_id="bucket-iac", source="iac")
    resp = api_client.get("/api/v1/findings/export?format=json&source=iac", headers=HEADERS)
    body = json.loads(resp.text)
    assert len(body["data"]) == 1
    assert body["data"][0]["check_id"] == "iac_check"
