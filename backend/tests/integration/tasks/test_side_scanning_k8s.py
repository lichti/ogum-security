"""
Integration tests for Sprint 3 side-scanning: scan_k8s_container.

Strategy:
- subprocess.run (trivy calls) → mocked via pytest-mock / monkeypatch
- ArangoDB → real instance via Docker (never mocked)
- scan_k8s_container called directly (not via Celery queue)
- /proc/<PID>/root path → simulated via tmp_path fixture
"""

from __future__ import annotations

import json
from subprocess import CompletedProcess
from typing import Any

import pytest

from app.db.init import init_tenant_schema
from app.workers.tasks.side_scanning import scan_k8s_container

TENANT_A = "test-k8s-scan-a"
TENANT_B = "test-k8s-scan-b"


def _trivy_vuln_json(cve: str = "CVE-2025-1111", severity: str = "CRITICAL", cvss: float = 4.0) -> str:
    return json.dumps(
        {
            "Results": [
                {
                    "Target": "usr/lib/libssl.so",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": cve,
                            "PkgName": "libssl",
                            "InstalledVersion": "1.1.1",
                            "FixedVersion": "1.1.1k",
                            "Severity": severity,
                            "CVSS": {"nvd": {"V3Score": cvss}},
                            "Title": f"Test vuln {cve}",
                            "Description": "Test description",
                        }
                    ],
                    "Secrets": [],
                }
            ]
        }
    )


def _trivy_secret_json() -> str:
    return json.dumps(
        {
            "Results": [
                {
                    "Target": "etc/environment",
                    "Vulnerabilities": [],
                    "Secrets": [
                        {
                            "RuleID": "aws-access-key-id",
                            "Category": "AWS",
                            "Title": "AWS Access Key ID",
                            "Severity": "HIGH",
                            "Match": "****",
                        }
                    ],
                }
            ]
        }
    )


def _trivy_sbom_json() -> str:
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "metadata": {"component": {"version": "2025-01-01"}},
            "components": [{"name": "libssl", "version": "1.1.1"}],
        }
    )


def _ok(stdout: str, returncode: int = 0) -> CompletedProcess[str]:
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.mark.integration
def test_k8s_findings_persisted_in_arango(db_tenant_a: Any, tmp_path: Any, mocker: Any) -> None:
    """CVE finding from K8s container scan is persisted in ArangoDB."""
    init_tenant_schema(db_tenant_a)

    # Simulate /host/proc/{pid}/root
    proc_root = tmp_path / "1234" / "root"
    proc_root.mkdir(parents=True)

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok("{}")
        return _ok(_trivy_vuln_json())

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", side_effect=_subprocess_mock)

    db_tenant_a.collection("resources").insert(
        {"_key": "pod-abc-key", "tenant_id": TENANT_A, "provider": "k8s", "resource_type": "pod"}
    )

    result = scan_k8s_container(
        tenant_id=TENANT_A,
        pod_name="my-pod",
        pod_namespace="default",
        container_name="app",
        pid=1234,
        node_name="node-1",
        resource_id="pod-abc-key",
        provider_id="k8s-provider",
        job_id="job-k8s-001",
        trivy_server_url="http://trivy-server:4954",
        host_proc_root=str(tmp_path),
    )

    assert result["cve_count"] == 1
    assert result["findings_count"] >= 1

    cursor = db_tenant_a.aql.execute(
        "FOR f IN findings FILTER f.tenant_id == @tid RETURN f",
        bind_vars={"tid": TENANT_A},
    )
    findings = list(cursor)
    assert len(findings) >= 1
    assert any(f["check_id"] == "side_scanning/cve/CVE-2025-1111" for f in findings)
    assert all(f["tenant_id"] == TENANT_A for f in findings)


@pytest.mark.integration
def test_k8s_sbom_persisted_in_arango(db_tenant_a: Any, tmp_path: Any, mocker: Any) -> None:
    """CycloneDX SBOM is generated and stored in the sboms collection with HAS_SBOM edge."""
    init_tenant_schema(db_tenant_a)

    proc_root = tmp_path / "5678" / "root"
    proc_root.mkdir(parents=True)

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok(_trivy_sbom_json())
        return _ok(_trivy_vuln_json())

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", side_effect=_subprocess_mock)

    db_tenant_a.collection("resources").insert(
        {"_key": "pod-sbom-key", "tenant_id": TENANT_A, "provider": "k8s", "resource_type": "pod"}
    )

    scan_k8s_container(
        tenant_id=TENANT_A,
        pod_name="sbom-pod",
        pod_namespace="kube-system",
        container_name="sidecar",
        pid=5678,
        node_name="node-2",
        resource_id="pod-sbom-key",
        provider_id="k8s-provider",
        job_id="job-k8s-sbom",
        trivy_server_url="http://trivy-server:4954",
        host_proc_root=str(tmp_path),
    )

    sboms = list(
        db_tenant_a.aql.execute(
            "FOR s IN sboms FILTER s.tenant_id == @tid RETURN s",
            bind_vars={"tid": TENANT_A},
        )
    )
    assert len(sboms) == 1
    assert sboms[0]["component_count"] == 1
    assert sboms[0]["format"] == "cyclonedx"

    edges = list(
        db_tenant_a.aql.execute(
            "FOR e IN HAS_SBOM FILTER e.tenant_id == @tid RETURN e",
            bind_vars={"tid": TENANT_A},
        )
    )
    assert len(edges) == 1


@pytest.mark.integration
def test_k8s_raises_when_proc_path_missing(db_tenant_a: Any, monkeypatch: Any) -> None:
    """FileNotFoundError raised when /proc/<PID>/root does not exist."""
    init_tenant_schema(db_tenant_a)
    monkeypatch.setattr("app.workers.tasks.side_scanning._get_tenant_db", lambda tid: db_tenant_a)

    with pytest.raises(FileNotFoundError):
        scan_k8s_container(
            tenant_id=TENANT_A,
            pod_name="ghost-pod",
            pod_namespace="default",
            container_name="app",
            pid=99999999,
            node_name="node-1",
            resource_id="ghost-pod-key",
            provider_id="k8s-provider",
            job_id="job-k8s-missing",
            host_proc_root="/nonexistent/path",
        )


@pytest.mark.security
def test_k8s_tenant_isolation(db_tenant_a: Any, db_tenant_b: Any, tmp_path: Any, mocker: Any) -> None:
    """Findings from tenant A are not visible to tenant B."""
    init_tenant_schema(db_tenant_a)
    init_tenant_schema(db_tenant_b)

    proc_root = tmp_path / "9999" / "root"
    proc_root.mkdir(parents=True)

    def _get_db(tenant_id: str) -> Any:
        return db_tenant_a if tenant_id == TENANT_A else db_tenant_b

    def _subprocess_iso(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok("{}")
        return _ok(_trivy_vuln_json())

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", side_effect=_get_db)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", side_effect=_subprocess_iso)

    db_tenant_a.collection("resources").insert(
        {"_key": "pod-iso-key", "tenant_id": TENANT_A, "provider": "k8s", "resource_type": "pod"}
    )

    scan_k8s_container(
        tenant_id=TENANT_A,
        pod_name="iso-pod",
        pod_namespace="default",
        container_name="app",
        pid=9999,
        node_name="node-1",
        resource_id="pod-iso-key",
        provider_id="k8s-provider",
        job_id="job-k8s-iso",
        host_proc_root=str(tmp_path),
    )

    # Tenant A has findings
    findings_a = list(
        db_tenant_a.aql.execute(
            "FOR f IN findings FILTER f.tenant_id == @tid RETURN f",
            bind_vars={"tid": TENANT_A},
        )
    )
    assert len(findings_a) >= 1

    # Tenant B has no findings (separate DB)
    findings_b = list(
        db_tenant_b.aql.execute(
            "FOR f IN findings FILTER f.tenant_id == @tid RETURN f",
            bind_vars={"tid": TENANT_B},
        )
    )
    assert len(findings_b) == 0


@pytest.mark.integration
def test_k8s_severity_from_trivy_field(db_tenant_a: Any, tmp_path: Any, mocker: Any) -> None:
    """Trivy Severity=CRITICAL with CVSS=4.0 → finding persisted as CRITICAL (not MEDIUM)."""
    init_tenant_schema(db_tenant_a)

    proc_root = tmp_path / "1111" / "root"
    proc_root.mkdir(parents=True)

    def _subprocess_sev(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok("{}")
        return _ok(_trivy_vuln_json(severity="CRITICAL", cvss=4.0))

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", side_effect=_subprocess_sev)

    db_tenant_a.collection("resources").insert(
        {"_key": "pod-sev-key", "tenant_id": TENANT_A, "provider": "k8s", "resource_type": "pod"}
    )

    scan_k8s_container(
        tenant_id=TENANT_A,
        pod_name="sev-pod",
        pod_namespace="default",
        container_name="app",
        pid=1111,
        node_name="node-1",
        resource_id="pod-sev-key",
        provider_id="k8s-provider",
        job_id="job-k8s-sev",
        host_proc_root=str(tmp_path),
    )

    cursor = db_tenant_a.aql.execute(
        "FOR f IN findings FILTER f.tenant_id == @tid RETURN f",
        bind_vars={"tid": TENANT_A},
    )
    findings = list(cursor)
    assert len(findings) >= 1
    # Severity must come from Trivy field (CRITICAL), not CVSS score 4.0 (which would be MEDIUM)
    assert findings[0]["severity"] == "CRITICAL"
