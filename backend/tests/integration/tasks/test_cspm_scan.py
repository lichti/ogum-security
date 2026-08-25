"""
Integration tests for CSPM scan Celery task.

Rules:
- ArangoDB: real instance (db_tenant_a fixture — never mocked)
- ProwlerService: mocked entirely — Prowler never calls real cloud APIs in CI
- Celery: task.apply() runs synchronously — no broker required
"""

from unittest.mock import MagicMock

import pytest

from app.db.init import init_tenant_schema
from app.models.finding import FindingStatus, SeverityLevel
from app.services.prowler_service import ScanResult
from app.workers.tasks.cspm_scan import run_cspm_scan

TEST_TENANT = "test-tenant-aaa"
PROVIDER_ID = "aws-111111111111"
ACCOUNT_ID = "111111111111"
FRAMEWORKS = ["CIS-AWS-2.0"]

_TASK_KWARGS = {
    "tenant_id": TEST_TENANT,
    "provider_id": PROVIDER_ID,
    "provider": "aws",
    "frameworks": FRAMEWORKS,
    "credentials": {"aws_access_key_id": None, "aws_secret_access_key": None},
    "account_id": ACCOUNT_ID,
    "regions": ["us-east-1"],
}


def _make_mock_finding(
    check_id: str = "iam_root_mfa_enabled",
    resource_id: str = "arn:aws:iam::111111111111:root",
    status=FindingStatus.FAIL,
):
    from app.models.finding import Finding, FindingSource

    return Finding(
        finding_id=f"test-{check_id}",
        tenant_id=TEST_TENANT,
        check_id=check_id,
        title=f"Test {check_id}",
        description="Test description",
        resource_id=resource_id,
        resource_type="iam_user",
        severity=SeverityLevel.CRITICAL,
        status=status,
        provider="aws",
        account_id=ACCOUNT_ID,
        source=FindingSource.CSPM,
    )


def _scan_result(findings):
    """Wrap findings in a ScanResult (raw_outputs empty — inventory extraction skipped)."""
    return ScanResult(findings=findings, raw_outputs=[])


@pytest.mark.integration
class TestCSPMScanTask:
    def test_scan_creates_scan_job_and_findings(self, db_tenant_a, mocker):
        """Happy path: ProwlerService returns 2 findings, both are persisted."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        findings = [
            _make_mock_finding("iam_root_mfa_enabled"),
            _make_mock_finding("s3_bucket_public_read", "my-bucket", FindingStatus.PASS_),
        ]
        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = _scan_result(findings)
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert result["provider"] == "aws"
        assert result["findings_found"] == 2
        assert result["findings_fail"] == 1
        assert "job_id" in result

        jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
        assert len(jobs) == 1
        job = jobs[0]
        assert job["status"] == "completed"
        assert job["tenant_id"] == TEST_TENANT
        assert job["findings_found"] == 2

        stored_findings = list(db_tenant_a.aql.execute("FOR f IN findings RETURN f"))
        assert len(stored_findings) == 2

    def test_scan_job_created_before_findings_persisted(self, db_tenant_a, mocker):
        """scan_job document must exist before ProwlerService runs (status: running)."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        captured_status = {}

        def check_job_exists(*args, **kwargs):
            jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
            if jobs:
                captured_status["status"] = jobs[0]["status"]
            return _scan_result([])

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.side_effect = check_job_exists
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        assert captured_status.get("status") == "running"

    def test_scan_with_zero_findings(self, db_tenant_a, mocker):
        """Empty findings list must result in completed job with 0 findings."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = _scan_result([])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert result["findings_found"] == 0
        assert result["findings_fail"] == 0
        jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
        assert jobs[0]["status"] == "completed"

    def test_finding_upsert_is_idempotent(self, db_tenant_a, mocker):
        """Running the same scan twice must not duplicate findings."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        findings = [_make_mock_finding("iam_root_mfa_enabled")]
        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = _scan_result(findings)
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        stored = list(db_tenant_a.aql.execute("FOR f IN findings RETURN f"))
        assert len(stored) == 1

    def test_unsupported_provider_produces_empty_findings(self, db_tenant_a, mocker):
        """GCP scan returns empty ScanResult when credentials are not provided."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_gcp_scan.return_value = _scan_result([])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "gcp"}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["findings_found"] == 0
        mock_prowler.run_aws_scan.assert_not_called()

    def test_azure_scan_dispatch(self, db_tenant_a, mocker):
        """Azure provider routes to run_azure_scan (not run_aws_scan)."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_azure_scan.return_value = _scan_result([])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "azure", "frameworks": ["CIS-AZURE-2.0"]}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["provider"] == "azure"
        assert result["findings_found"] == 0
        mock_prowler.run_azure_scan.assert_called_once()
        mock_prowler.run_aws_scan.assert_not_called()

    def test_k8s_scan_dispatch(self, db_tenant_a, mocker):
        """Kubernetes provider routes to run_kubernetes_scan."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_kubernetes_scan.return_value = _scan_result([])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "k8s", "frameworks": ["CIS-K8S-1.12"]}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["provider"] == "k8s"
        assert result["findings_found"] == 0
        mock_prowler.run_kubernetes_scan.assert_called_once()
        mock_prowler.run_aws_scan.assert_not_called()

    def test_unknown_provider_falls_back_to_empty(self, db_tenant_a, mocker):
        """Unrecognized provider returns completed job with zero findings."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        kwargs = {**_TASK_KWARGS, "provider": "oracle"}
        result = run_cspm_scan.apply(kwargs=kwargs).get()

        assert result["findings_found"] == 0
        jobs = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))
        assert jobs[0]["status"] == "completed"

    def test_inventory_extracted_from_raw_outputs(self, db_tenant_a, mocker):
        """Inventory extraction runs when scan produces raw OutputFinding objects."""
        from types import SimpleNamespace

        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        # EC2 instance routes to "resources" collection (not data_assets like S3)
        resource_uid = "arn:aws:ec2:us-east-1:111111111111:instance/i-abc123"
        meta = SimpleNamespace(
            CheckID="ec2_instance_imdsv2_enabled",
            CheckTitle="EC2 IMDSv2 Enabled",
            Description="desc",
            Severity="high",
            ResourceType="aws_ec2_instance",
            Remediation=None,
        )
        raw_output = SimpleNamespace(
            status="FAIL",
            status_extended="IMDSv2 not enabled",
            resource_uid=resource_uid,
            resource_name="my-ec2",
            region="us-east-1",
            account_uid=ACCOUNT_ID,
            metadata=meta,
            compliance={},
            resource_metadata={},
        )

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[_make_mock_finding("ec2_instance_imdsv2_enabled", resource_uid)],
            raw_outputs=[raw_output],
        )
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert result["findings_found"] == 1
        assert result["inventory_upserted"] >= 1

        resources = list(db_tenant_a.aql.execute("FOR r IN resources RETURN r"))
        assert len(resources) >= 1
        assert resources[0]["resource_id"] == resource_uid

    def test_graph_edges_built_from_scan_output(self, db_tenant_a, mocker):
        """EC2 instance with a security group + instance profile produces
        ATTACHED_TO and ASSUMES_ROLE edges after a single scan — no separate
        discovery run needed."""
        from types import SimpleNamespace

        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        role_arn = "arn:aws:iam::111111111111:role/AppRole"
        role_uid = role_arn
        role_meta = SimpleNamespace(
            CheckID="iam_role_test",
            CheckTitle="IAM Role",
            Description="desc",
            Severity="medium",
            ResourceType="AwsIamRole",
            Remediation=None,
        )
        role_output = SimpleNamespace(
            status="PASS",
            status_extended="ok",
            resource_uid=role_uid,
            resource_name="AppRole",
            region=None,
            account_uid=ACCOUNT_ID,
            metadata=role_meta,
            compliance={},
            resource_metadata={"assume_role_policy": {}, "attached_policies": [], "inline_policies": []},
        )

        sg_arn = "arn:aws:ec2:us-east-1:111111111111:security-group/sg-abc"
        sg_meta = SimpleNamespace(
            CheckID="ec2_sg_test",
            CheckTitle="SG",
            Description="desc",
            Severity="medium",
            ResourceType="AwsEc2SecurityGroup",
            Remediation=None,
        )
        sg_output = SimpleNamespace(
            status="PASS",
            status_extended="ok",
            resource_uid=sg_arn,
            resource_name="sg-abc",
            region="us-east-1",
            account_uid=ACCOUNT_ID,
            metadata=sg_meta,
            compliance={},
            resource_metadata={},
        )

        ec2_arn = "arn:aws:ec2:us-east-1:111111111111:instance/i-abc123"
        ec2_meta = SimpleNamespace(
            CheckID="ec2_instance_test",
            CheckTitle="EC2",
            Description="desc",
            Severity="high",
            ResourceType="AwsEc2Instance",
            Remediation=None,
        )
        ec2_output = SimpleNamespace(
            status="FAIL",
            status_extended="fail",
            resource_uid=ec2_arn,
            resource_name="my-ec2",
            region="us-east-1",
            account_uid=ACCOUNT_ID,
            metadata=ec2_meta,
            compliance={},
            resource_metadata={
                "security_groups": ["sg-abc"],
                "subnet_id": "",
                "instance_profile": {"Arn": "arn:aws:iam::111111111111:instance-profile/AppRole"},
            },
        )

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[
                _make_mock_finding("iam_role_test", role_uid, FindingStatus.PASS_),
                _make_mock_finding("ec2_sg_test", sg_arn, FindingStatus.PASS_),
                _make_mock_finding("ec2_instance_test", ec2_arn),
            ],
            raw_outputs=[role_output, sg_output, ec2_output],
        )
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert result["resource_edges"]["ATTACHED_TO"] == 1
        assert result["resource_edges"]["ASSUMES_ROLE"] == 1

        attached_to = list(db_tenant_a.aql.execute("FOR e IN ATTACHED_TO RETURN e"))
        assert len(attached_to) == 1
        assumes_role = list(db_tenant_a.aql.execute("FOR e IN ASSUMES_ROLE RETURN e"))
        assert len(assumes_role) == 1

    def test_stale_resource_soft_deleted_on_rescan(self, db_tenant_a, mocker):
        """A resource present in scan 1 but absent from scan 2 is marked deleted,
        not removed — matches the old discovery.py upsert-not-truncate contract."""
        from types import SimpleNamespace

        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        def _ec2_output(uid: str, name: str):
            meta = SimpleNamespace(
                CheckID="ec2_instance_test",
                CheckTitle="EC2",
                Description="desc",
                Severity="high",
                ResourceType="AwsEc2Instance",
                Remediation=None,
            )
            return SimpleNamespace(
                status="PASS",
                status_extended="ok",
                resource_uid=uid,
                resource_name=name,
                region="us-east-1",
                account_uid=ACCOUNT_ID,
                metadata=meta,
                compliance={},
                resource_metadata={},
            )

        uid_a = "arn:aws:ec2:us-east-1:111111111111:instance/i-aaa"
        uid_b = "arn:aws:ec2:us-east-1:111111111111:instance/i-bbb"

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[
                _make_mock_finding("ec2_instance_test", uid_a, FindingStatus.PASS_),
                _make_mock_finding("ec2_instance_test", uid_b, FindingStatus.PASS_),
            ],
            raw_outputs=[_ec2_output(uid_a, "i-aaa"), _ec2_output(uid_b, "i-bbb")],
        )
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)
        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        active = list(db_tenant_a.aql.execute("FOR r IN resources FILTER r.status != 'deleted' RETURN r.resource_id"))
        assert set(active) == {uid_a, uid_b}

        # Second scan only sees i-aaa — i-bbb was removed from the cloud.
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[_make_mock_finding("ec2_instance_test", uid_a, FindingStatus.PASS_)],
            raw_outputs=[_ec2_output(uid_a, "i-aaa")],
        )
        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        assert result["inventory_deleted"] == 1

        docs = {d["resource_id"]: d["status"] for d in db_tenant_a.aql.execute("FOR r IN resources RETURN r")}
        assert docs[uid_a] == "active"
        assert docs[uid_b] == "deleted"

        # The resource is soft-deleted (kept, for the inventory audit trail) but its
        # finding — no longer actionable — is hard-deleted, not left as an orphan.
        assert result["findings_removed"] == 1
        job = list(db_tenant_a.aql.execute("FOR j IN scan_jobs SORT j.created_at DESC LIMIT 1 RETURN j"))[0]
        assert job["assets_removed"] == 1
        assert job["assets_total"] == 1  # only uid_a in this run's inventory

        remaining_findings = {f["resource_id"] for f in db_tenant_a.aql.execute("FOR f IN findings RETURN f")}
        assert remaining_findings == {uid_a}

        remaining_edges = list(db_tenant_a.aql.execute("FOR e IN HAS_FINDING RETURN e"))
        assert all(uid_b not in e["_to"] for e in remaining_edges)

    def test_findings_new_and_updated_counted_across_rescans(self, db_tenant_a, mocker):
        """First scan: both findings are new. Second scan re-affirms the same
        two findings — new=0, updated=2 (US-14.23, the Scans page summary)."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        findings = [
            _make_mock_finding("iam_root_mfa_enabled"),
            _make_mock_finding("s3_bucket_public_read", "my-bucket", FindingStatus.PASS_),
        ]

        # ProwlerService is mocked wholesale, bypassing _normalize (which is what
        # really stamps Finding.scan_job_id from run_cspm_scan's freshly-generated
        # job_id) — a side_effect reading the real scan_job_id kwarg keeps this
        # test honest about that per-run stamping instead of hardcoding one.
        def _run_aws_scan(**kwargs):
            for f in findings:
                f.scan_job_id = kwargs["scan_job_id"]
            return _scan_result(findings)

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.side_effect = _run_aws_scan
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        first = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        assert first["findings_new"] == 2
        assert first["findings_updated"] == 0

        second = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        assert second["findings_new"] == 0
        assert second["findings_updated"] == 2

    def test_duration_seconds_recorded_on_completion(self, db_tenant_a, mocker):
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)
        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = _scan_result([_make_mock_finding()])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        job = list(db_tenant_a.aql.execute("FOR j IN scan_jobs RETURN j"))[0]
        assert job["duration_seconds"] is not None
        assert job["duration_seconds"] >= 0

    def test_compliance_score_snapshot_written_and_idempotent(self, db_tenant_a, mocker):
        """A completed scan writes one compliance_score_snapshots doc per framework
        (Epic 14 Sprint 4, US-14.15); running the scan twice the same day upserts by
        (tenant, framework, day) instead of duplicating."""
        from app.models.finding import Finding, FindingSource

        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        finding = Finding(
            finding_id="test-cis-2.1.1",
            tenant_id=TEST_TENANT,
            check_id="iam_root_mfa_enabled",
            title="Test",
            description="desc",
            resource_id="arn:aws:iam::111111111111:root",
            resource_type="iam_user",
            severity=SeverityLevel.CRITICAL,
            status=FindingStatus.FAIL,
            provider="aws",
            account_id=ACCOUNT_ID,
            source=FindingSource.CSPM,
            framework_mapping=["CIS-7.0/2.1.1"],
        )
        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = _scan_result([finding])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()
        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        snapshots = list(
            db_tenant_a.aql.execute(
                "FOR s IN compliance_score_snapshots FILTER s.tenant_id == @t RETURN s",
                bind_vars={"t": TEST_TENANT},
            )
        )
        assert len(snapshots) == 1
        assert snapshots[0]["framework_id"] == "CIS-7.0"
        assert snapshots[0]["fail_count"] == 1
        # score_by_control = (Pass + Unscored) / Total — the one real Fail is the only
        # thing dragging the score down from 100%, every other catalog control is
        # Unscored and counts toward Pass.
        total = snapshots[0]["pass_count"] + snapshots[0]["fail_count"] + snapshots[0]["unscored_count"]
        assert snapshots[0]["score_by_control"] == round(snapshots[0]["unscored_count"] / total * 100, 1)


@pytest.mark.integration
class TestAutoTriggerSideScans:
    """
    First-seen-only auto side-scan trigger, hooked into run_cspm_scan right after
    inventory upsert. enqueue_side_scan itself (AWS session, describe_instances,
    task .delay()) is covered by test_side_scans_trigger.py — here we only verify
    the CSPM scan task calls it exactly once per new EC2/Lambda resource, and
    skips resources that already have a prior scan_jobs entry (dedup uses the
    real scan_jobs collection, not a mock — ArangoDB is never mocked).
    """

    @staticmethod
    def _output(uid: str, name: str, resource_type: str):
        from types import SimpleNamespace

        meta = SimpleNamespace(
            CheckID="test_check",
            CheckTitle="Test",
            Description="desc",
            Severity="high",
            ResourceType=resource_type,
            Remediation=None,
        )
        return SimpleNamespace(
            status="PASS",
            status_extended="ok",
            resource_uid=uid,
            resource_name=name,
            region="us-east-1",
            account_uid=ACCOUNT_ID,
            metadata=meta,
            compliance={},
            resource_metadata={},
        )

    def test_first_seen_ec2_and_lambda_trigger_side_scan(self, db_tenant_a, mocker):
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        ec2_uid = "arn:aws:ec2:us-east-1:111111111111:instance/i-newec2"
        lambda_uid = "arn:aws:lambda:us-east-1:111111111111:function:my-fn"

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[],
            raw_outputs=[
                self._output(ec2_uid, "i-newec2", "AwsEc2Instance"),
                self._output(lambda_uid, "my-fn", "AwsLambdaFunction"),
            ],
        )
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        enqueue_mock = mocker.patch("app.workers.tasks.cspm_scan.enqueue_side_scan", return_value="fake-job-id")

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        assert enqueue_mock.call_count == 2
        triggered_types = {call.args[2]["resource_type"] for call in enqueue_mock.call_args_list}
        assert triggered_types == {"ec2_instance", "lambda_function"}
        assert result is not None  # scan still completes normally

    def test_resource_with_prior_scan_job_is_not_retriggered(self, db_tenant_a, mocker):
        """A resource that already has any ec2/lambda scan_jobs entry (queued,
        running, completed, or failed) is skipped — first-seen semantics, not a
        time-window cooldown."""
        from app.services.prowler_inventory import resource_arango_key

        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        ec2_uid = "arn:aws:ec2:us-east-1:111111111111:instance/i-existing"
        resource_key = resource_arango_key(ec2_uid, TEST_TENANT)
        db_tenant_a.collection("scan_jobs").insert(
            {
                "_key": "prior-ec2-job",
                "tenant_id": TEST_TENANT,
                "type": "ec2",
                "status": "completed",
                "resource_id": resource_key,
            }
        )

        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[],
            raw_outputs=[self._output(ec2_uid, "i-existing", "AwsEc2Instance")],
        )
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        enqueue_mock = mocker.patch("app.workers.tasks.cspm_scan.enqueue_side_scan")

        run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        enqueue_mock.assert_not_called()

    def test_non_aws_provider_never_auto_triggers(self, db_tenant_a, mocker):
        """Side-scanning is AWS-only — Azure/GCP/K8s scans must never call enqueue_side_scan."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        mock_prowler = MagicMock()
        mock_prowler.run_azure_scan.return_value = ScanResult(findings=[], raw_outputs=[])
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)

        enqueue_mock = mocker.patch("app.workers.tasks.cspm_scan.enqueue_side_scan")

        azure_kwargs = {**_TASK_KWARGS, "provider": "azure"}
        run_cspm_scan.apply(kwargs=azure_kwargs).get()

        enqueue_mock.assert_not_called()

    def test_enqueue_failure_for_one_resource_does_not_fail_scan(self, db_tenant_a, mocker):
        """A single resource's enqueue error is logged and skipped — never fails the CSPM job."""
        init_tenant_schema(db_tenant_a)
        mocker.patch("app.workers.tasks.cspm_scan._get_tenant_db", return_value=db_tenant_a)

        ec2_uid = "arn:aws:ec2:us-east-1:111111111111:instance/i-broken"
        mock_prowler = MagicMock()
        mock_prowler.run_aws_scan.return_value = ScanResult(
            findings=[],
            raw_outputs=[self._output(ec2_uid, "i-broken", "AwsEc2Instance")],
        )
        mocker.patch("app.workers.tasks.cspm_scan.ProwlerService", return_value=mock_prowler)
        mocker.patch("app.workers.tasks.cspm_scan.enqueue_side_scan", side_effect=RuntimeError("boom"))

        result = run_cspm_scan.apply(kwargs=_TASK_KWARGS).get()

        jobs = list(
            db_tenant_a.aql.execute(
                "FOR j IN scan_jobs FILTER j.tenant_id == @t RETURN j", bind_vars={"t": TEST_TENANT}
            )
        )
        assert any(j["status"] == "completed" for j in jobs)
        assert result["findings_found"] == 0
