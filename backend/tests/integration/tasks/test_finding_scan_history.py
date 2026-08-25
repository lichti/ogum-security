"""Integration tests for finding scan-history tracking (Epic 14 US-14.10 prerequisite).

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
"""

import pytest

from app.db.init import init_tenant_schema
from app.models.finding import Finding, FindingSource, FindingStatus, SeverityLevel
from app.workers.tasks.cloud_utils import upsert_finding

TEST_TENANT = "test-tenant-aaa"


def _make_finding(scan_job_id: str, status=FindingStatus.FAIL) -> Finding:
    return Finding(
        finding_id="test-finding",
        tenant_id=TEST_TENANT,
        check_id="ec2_public",
        title="Public EC2 instance",
        description="Instance is publicly reachable",
        resource_id="i-scan-history-001",
        resource_type="ec2_instance",
        severity=SeverityLevel.HIGH,
        status=status,
        provider="aws",
        account_id="111111111111",
        source=FindingSource.CSPM,
        scan_job_id=scan_job_id,
    )


@pytest.mark.integration
class TestUpsertFindingScanHistory:
    def test_first_insert_sets_scan_count_one_and_matching_scan_ids(self, db_tenant_a):
        init_tenant_schema(db_tenant_a)
        upsert_finding(db_tenant_a, _make_finding("scan-job-1"))

        doc = db_tenant_a.collection("findings").get(_make_finding("scan-job-1").arango_key())
        assert doc["first_seen_scan_id"] == "scan-job-1"
        assert doc["last_seen_scan_id"] == "scan-job-1"
        assert doc["scan_count"] == 1

    def test_second_scan_bumps_count_and_last_seen_but_not_first_seen(self, db_tenant_a):
        init_tenant_schema(db_tenant_a)
        key = _make_finding("scan-job-1").arango_key()

        upsert_finding(db_tenant_a, _make_finding("scan-job-1"))
        upsert_finding(db_tenant_a, _make_finding("scan-job-2"))

        doc = db_tenant_a.collection("findings").get(key)
        assert doc["first_seen_scan_id"] == "scan-job-1"
        assert doc["last_seen_scan_id"] == "scan-job-2"
        assert doc["scan_count"] == 2

    def test_detected_at_is_preserved_across_rescans(self, db_tenant_a):
        init_tenant_schema(db_tenant_a)
        key = _make_finding("scan-job-1").arango_key()

        upsert_finding(db_tenant_a, _make_finding("scan-job-1"))
        first_doc = db_tenant_a.collection("findings").get(key)

        upsert_finding(db_tenant_a, _make_finding("scan-job-2"))
        second_doc = db_tenant_a.collection("findings").get(key)

        assert second_doc["detected_at"] == first_doc["detected_at"]

    def test_status_and_severity_still_update_on_rescan(self, db_tenant_a):
        init_tenant_schema(db_tenant_a)
        key = _make_finding("scan-job-1").arango_key()

        upsert_finding(db_tenant_a, _make_finding("scan-job-1", status=FindingStatus.FAIL))
        upsert_finding(db_tenant_a, _make_finding("scan-job-2", status=FindingStatus.PASS_))

        doc = db_tenant_a.collection("findings").get(key)
        assert doc["status"] == "PASS"
