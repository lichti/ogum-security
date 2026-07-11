"""IaC scan Celery task — clones a git repository and runs Checkov."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from app.db.init import init_tenant_schema
from app.models.finding import ScanJob, ScanJobStatus
from app.services.checkov_service import CheckovService
from app.workers.celery_app import celery_app
from app.workers.tasks.cloud_utils import _get_tenant_db
from app.workers.tasks.cspm_scan import _update_job, _upsert_finding

logger = logging.getLogger(__name__)


def _authenticated_url(repo_url: str, token: str) -> str:
    """Inject token into HTTPS URL without exposing it in process list."""
    parsed = urlparse(repo_url)
    authed = parsed._replace(netloc=f"x-token:{token}@{parsed.netloc}")
    return urlunparse(authed)


def _clone_repo(repo_url: str, branch: str, dest: Path, token: str | None) -> None:
    clone_url = _authenticated_url(repo_url, token) if token and repo_url.startswith("https://") else repo_url
    result = subprocess.run(
        ["git", "clone", "--depth=1", "--branch", branch, clone_url, str(dest)],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ},
    )
    if result.returncode != 0:
        safe_msg = result.stderr.replace(token, "***") if token else result.stderr
        raise RuntimeError(f"git clone failed: {safe_msg[:500]}")


@celery_app.task(bind=True, max_retries=2, default_retry_delay=60)
def run_iac_scan(
    self: Any,
    tenant_id: str,
    repo_url: str,
    branch: str,
    path: str,
    account_id: str,
    repo_token: str | None = None,
) -> dict[str, Any]:
    """Clone a git repository and run Checkov IaC checks against it."""
    db = _get_tenant_db(tenant_id)
    init_tenant_schema(db)

    job_id = str(uuid.uuid4())
    job = ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        provider_id="iac",
        provider="iac",
        frameworks=["checkov"],
        status=ScanJobStatus.RUNNING,
        started_at=datetime.now(UTC),
        iac_config={"repo_url": repo_url, "branch": branch, "path": path},
    )
    db.collection("scan_jobs").insert(job.to_arango_doc())

    tmpdir: str | None = None
    try:
        tmpdir = tempfile.mkdtemp(prefix="ogum_iac_")
        clone_dest = Path(tmpdir) / "repo"

        _clone_repo(repo_url, branch, clone_dest, repo_token)

        scan_dir = clone_dest / path
        if not scan_dir.exists():
            raise FileNotFoundError(f"Scan path '{path}' not found in repository")

        service = CheckovService()
        findings = service.run_scan(scan_dir, tenant_id, account_id=account_id, scan_job_id=job_id)

        for finding in findings:
            _upsert_finding(db, finding)

        fail_count = sum(1 for f in findings if f.status == "FAIL")
        _update_job(
            db,
            job_id,
            status=ScanJobStatus.COMPLETED,
            checks_total=len(findings),
            checks_completed=len(findings),
            findings_found=len(findings),
            findings_fail=fail_count,
            completed_at=datetime.now(UTC).isoformat(),
        )

        logger.info(
            "IaC scan complete [tenant=%s repo=%s branch=%s]: findings=%d fail=%d",
            tenant_id,
            repo_url,
            branch,
            len(findings),
            fail_count,
        )
        return {
            "job_id": job_id,
            "tenant_id": tenant_id,
            "findings_found": len(findings),
            "findings_fail": fail_count,
        }

    except Exception as exc:
        logger.exception("IaC scan failed [tenant=%s job=%s]: %s", tenant_id, job_id, exc)
        _update_job(
            db,
            job_id,
            status=ScanJobStatus.FAILED,
            error_message=str(exc),
            completed_at=datetime.now(UTC).isoformat(),
        )
        raise self.retry(exc=exc)

    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
