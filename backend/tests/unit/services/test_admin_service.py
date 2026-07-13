"""Unit tests for admin_service's job-doc → API-model conversion helpers.

_infer_task_name / _doc_to_job_summary / _doc_to_job_detail are pure
functions (no DB access), so these are plain unit tests — no ArangoDB fixture
needed.
"""

from __future__ import annotations

import pytest

from app.services.admin_service import _doc_to_job_detail, _doc_to_job_summary, _infer_task_name


@pytest.mark.unit
class TestInferTaskName:
    def test_uses_explicit_task_name_when_present(self) -> None:
        assert _infer_task_name({"task_name": "cspm_scan/aws", "provider": "azure"}) == "cspm_scan/aws"

    def test_ec2_side_scan_without_task_name(self) -> None:
        """Regression guard: docs written by trigger.py before task_name was
        added there had no `provider` field either, so the old fallback
        (f"cspm_scan/{provider}") produced the misleading "cspm_scan/" for
        every side-scan job."""
        assert _infer_task_name({"type": "ec2"}) == "side_scan/ec2"

    def test_lambda_side_scan_without_task_name(self) -> None:
        assert _infer_task_name({"type": "lambda"}) == "side_scan/lambda"

    def test_iac_scan_without_task_name(self) -> None:
        """Regression guard: iac_scan.py's ScanJob has provider="iac", which
        the old fallback rendered as "cspm_scan/iac" — an IaC scan mislabeled
        as a CSPM scan."""
        assert _infer_task_name({"provider": "iac", "iac_config": {"repo_url": "x"}}) == "iac_scan/iac"

    def test_cspm_scan_without_task_name(self) -> None:
        assert _infer_task_name({"provider": "aws"}) == "cspm_scan/aws"

    def test_completely_unknown_doc(self) -> None:
        assert _infer_task_name({}) == "cspm_scan/unknown"


@pytest.mark.unit
class TestDocToJobSummary:
    def test_infers_task_name_for_legacy_docs(self) -> None:
        doc = {"_key": "j1", "tenant_id": "t1", "status": "queued", "type": "ec2"}
        summary = _doc_to_job_summary(doc)
        assert summary.job_id == "j1"
        assert summary.task_name == "side_scan/ec2"

    def test_prefers_persisted_job_id_over_key(self) -> None:
        doc = {"_key": "arango-key", "job_id": "real-job-id", "tenant_id": "t1", "status": "running"}
        assert _doc_to_job_summary(doc).job_id == "real-job-id"


@pytest.mark.unit
class TestDocToJobDetail:
    def test_includes_logs_field(self) -> None:
        doc = {"_key": "j1", "tenant_id": "t1", "status": "completed", "logs": ["line 1", "line 2"]}
        detail = _doc_to_job_detail(doc)
        assert detail.logs == ["line 1", "line 2"]

    def test_defaults_logs_to_empty_list(self) -> None:
        doc = {"_key": "j1", "tenant_id": "t1", "status": "queued"}
        assert _doc_to_job_detail(doc).logs == []

    def test_infers_task_name_for_iac_scan(self) -> None:
        doc = {"_key": "j1", "tenant_id": "t1", "status": "completed", "provider": "iac", "iac_config": {}}
        assert _doc_to_job_detail(doc).task_name == "iac_scan/iac"
