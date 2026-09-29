"""US-03.16 — semântica de falha honesta em jobs de side-scanning.

Um task que falha termina com job `failed` + erro registrado — nunca
`completed` com 0 findings. Retry com backoff 5s/15s/45s; esgotado → failed.
SoftTimeLimitExceeded → failed com mensagem de timeout.
"""

from __future__ import annotations

import pytest
from celery.exceptions import SoftTimeLimitExceeded

from app.workers.tasks.side_scanning import scan_k8s_container
from tests.conftest import TEST_TENANT_A

pytestmark = pytest.mark.integration


def _seed_job(db, job_id: str) -> None:
    """O job doc é pré-criado pelo webhook (convenção dos tasks) — o teste
    reproduz isso antes de aplicar o task."""
    from app.db.init import init_tenant_schema

    init_tenant_schema(db)
    db.collection("scan_jobs").insert(
        {
            "_key": job_id,
            "job_id": job_id,
            "tenant_id": TEST_TENANT_A,
            "type": "k8s_container",
            "status": "queued",
            "resource_id": "res-1",
            "created_at": "0",
        }
    )


def _apply_failing_task(db_tenant_a, mocker, tmp_path, exc: Exception, retries: int = 3):
    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch(
        "app.workers.tasks.side_scanning.run_trivy_rootfs",
        side_effect=exc,
    )
    mocker.patch("app.workers.tasks.side_scanning.os.path.exists", return_value=True)
    _seed_job(db_tenant_a, "job-failure-test")
    with pytest.raises(type(exc)):
        scan_k8s_container.apply(
            kwargs={
                "tenant_id": TEST_TENANT_A,
                "pod_name": "p",
                "pod_namespace": "default",
                "container_name": "c",
                "pid": 1,
                "node_name": "n",
                "resource_id": "res-1",
                "provider_id": "k8s-provider",
                "job_id": "job-failure-test",
                # scan_path precisa existir para passar do check os.path.exists
                "host_proc_root": str(tmp_path),
            },
            retries=retries,
        ).get(propagate=True)


def test_task_failure_marks_job_failed_after_retries_exhausted(db_tenant_a, mocker, tmp_path):
    _apply_failing_task(db_tenant_a, mocker, tmp_path, RuntimeError("trivy exploded"), retries=3)
    doc = db_tenant_a.collection("scan_jobs").get("job-failure-test")
    assert doc["status"] == "failed"
    assert "RuntimeError" in doc["error_message"]
    assert "trivy exploded" in doc["error_message"]


def test_retry_path_reexecutes_before_failing(db_tenant_a, mocker, tmp_path):
    """Retry ativo: o task é re-executado (eager: loop do apply até exaurir
    max_retries) e só então o job vai a failed com a última causa — nunca
    falha permanente na primeira tentativa transiente."""
    rootfs = mocker.patch(
        "app.workers.tasks.side_scanning.run_trivy_rootfs",
        side_effect=[RuntimeError("t1"), RuntimeError("t2"), RuntimeError("t3"), RuntimeError("t4")],
    )
    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.workers.tasks.side_scanning.os.path.exists", return_value=True)
    _seed_job(db_tenant_a, "job-retry-test")
    with pytest.raises(RuntimeError):
        scan_k8s_container.apply(
            kwargs={
                "tenant_id": TEST_TENANT_A,
                "pod_name": "p",
                "pod_namespace": "default",
                "container_name": "c",
                "pid": 1,
                "node_name": "n",
                "resource_id": "res-1",
                "provider_id": "k8s-provider",
                "job_id": "job-retry-test",
                "host_proc_root": str(tmp_path),
            },
            retries=0,
        ).get(propagate=True)
    # Retry ativo: initial + max_retries(3) = 4 execuções antes de exaurir
    assert rootfs.call_count == 4
    doc = db_tenant_a.collection("scan_jobs").get("job-retry-test")
    assert doc["status"] == "failed"
    assert "RuntimeError: t4" in doc["error_message"]


def test_soft_time_limit_marks_failed_timeout(db_tenant_a, mocker, tmp_path):
    _apply_failing_task(db_tenant_a, mocker, tmp_path, SoftTimeLimitExceeded("soft"), retries=0)
    doc = db_tenant_a.collection("scan_jobs").get("job-failure-test")
    assert doc["status"] == "failed"
    assert "timeout" in doc["error_message"]


def test_success_still_completes(db_tenant_a, mocker, tmp_path):
    """Regressão: sucesso segue para completed (nunca perdemos o caminho feliz)."""
    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch(
        "app.workers.tasks.side_scanning.run_trivy_rootfs",
        return_value=([], []),
    )
    mocker.patch("app.workers.tasks.side_scanning.os.path.exists", return_value=True)
    mocker.patch(
        "app.workers.tasks.side_scanning._generate_sbom_rootfs",
        return_value={},
    )
    _seed_job(db_tenant_a, "job-success-test")
    scan_k8s_container.apply(
        kwargs={
            "tenant_id": TEST_TENANT_A,
            "pod_name": "p",
            "pod_namespace": "default",
            "container_name": "c",
            "pid": 1,
            "node_name": "n",
            "resource_id": "res-1",
            "provider_id": "k8s-provider",
            "job_id": "job-success-test",
            "host_proc_root": str(tmp_path),
        }
    ).get(propagate=True)
    doc = db_tenant_a.collection("scan_jobs").get("job-success-test")
    assert doc["status"] == "completed"
