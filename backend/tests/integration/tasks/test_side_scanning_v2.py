"""
Integration tests for side-scanning tasks:
  - scan_ec2_instance_v2 (EBS Direct API via Trivy sidecar, plus optional scoped-mount YARA)
  - scan_lambda_function (ZIP download to /dev/shm)
  - rescan_sboms (daily re-scan of stored CycloneDX SBOMs)

Strategy:
- boto3 (EC2/Lambda API calls) → mocked via moto @mock_aws
- subprocess.run (trivy calls) → mocked via pytest-mock
- httpx.get (Lambda code download) → mocked via pytest-mock
- ArangoDB → real instance via Docker (never mocked)
- Snapshot lifecycle → moto (snapshots complete immediately in moto)
- mount_volume_ro/umount_volume (real mount syscalls) → mocked via pytest-mock
"""

from __future__ import annotations

import io
import json
import zipfile
from subprocess import CompletedProcess
from typing import Any
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

from app.db.init import init_tenant_schema
from app.workers.tasks.side_scanning import (
    rescan_sboms,
    scan_ec2_instance_v2,
    scan_lambda_function,
)

REGION = "us-east-1"
TENANT = "test-sidescanning-v2"
ACCOUNT = "123456789012"
AZ = "us-east-1a"
TRIVY_URL = "http://trivy-server:4954"


def _seed_ec2(ec2_client: Any) -> tuple[str, str]:
    """Create moto EC2 volume. Returns (instance_id, volume_id)."""
    vol = ec2_client.create_volume(AvailabilityZone=AZ, Size=8, VolumeType="gp3")
    volume_id = vol["VolumeId"]
    ec2_resource = boto3.resource("ec2", region_name=REGION)
    instances = ec2_resource.create_instances(ImageId="ami-00000000", MinCount=1, MaxCount=1)
    return instances[0].id, volume_id


def _trivy_vuln_json(cve: str = "CVE-2024-9999", severity: str = "CRITICAL", cvss: float = 5.0) -> str:
    return json.dumps(
        {
            "Results": [
                {
                    "Target": "usr/bin/python3",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": cve,
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.0",
                            "FixedVersion": "3.0.8",
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
            "metadata": {"component": {"version": "2024-01-01"}},
            "components": [{"name": "openssl", "version": "3.0.0"}],
        }
    )


def _ok(stdout: str, returncode: int = 0) -> CompletedProcess[str]:
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def _make_zip(content: bytes = b"# requirements\nrequests==2.0.0\n") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("requirements.txt", content.decode())
    return buf.getvalue()


# ─── scan_ec2_instance_v2 ─────────────────────────────────────────────────────


@pytest.mark.integration
@mock_aws
def test_v2_snapshot_created_and_deleted(db_tenant_a: Any, mocker: Any) -> None:
    """Snapshot is created via moto and deleted in the finally block."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    call_count = [0]

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        call_count[0] += 1
        if "cyclonedx" in cmd:
            return _ok(_trivy_sbom_json())
        return _ok(_trivy_vuln_json())

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", _subprocess_mock)
    # wait_for_snapshot polls until completed — moto snapshots are immediate
    mocker.patch("app.workers.tasks.side_scanning.wait_for_snapshot", return_value=None)

    result = scan_ec2_instance_v2(
        tenant_id=TENANT,
        instance_id=instance_id,
        volume_id=volume_id,
        provider_id="test-provider",
        job_id="job-v2-001",
        trivy_server_url=TRIVY_URL,
        region=REGION,
        account_id=ACCOUNT,
        resource_key="test-ec2-key",
    )

    assert result["instance_id"] == instance_id

    # Snapshot must be gone (deleted in finally)
    snaps = ec2_client.describe_snapshots(
        Filters=[{"Name": "tag:ogum:scan", "Values": ["true"]}],
        OwnerIds=["self"],
    )
    assert len(snaps["Snapshots"]) == 0


@pytest.mark.integration
@mock_aws
def test_v2_findings_persisted_in_arango(db_tenant_a: Any, mocker: Any) -> None:
    """CVE + secret findings are persisted in ArangoDB with correct tenant_id."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    # 1 CVE + 1 secret in the same scan
    combined = json.dumps(
        {
            "Results": [
                {
                    "Target": "usr/lib/python3",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1111",
                            "PkgName": "requests",
                            "InstalledVersion": "2.0",
                            "FixedVersion": "2.1",
                            "Severity": "HIGH",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                            "Title": "Requests vuln",
                            "Description": "...",
                        }
                    ],
                    "Secrets": [
                        {
                            "RuleID": "github-token",
                            "Category": "GitHub",
                            "Title": "GitHub Personal Access Token",
                            "Severity": "CRITICAL",
                            "Match": "****",
                        }
                    ],
                }
            ]
        }
    )

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok(_trivy_sbom_json())
        return _ok(combined)

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.wait_for_snapshot", return_value=None)

    db_tenant_a.collection("resources").insert(
        {"_key": "ec2-findings-key", "tenant_id": TENANT, "provider": "aws", "resource_type": "ec2_instance"}
    )

    result = scan_ec2_instance_v2(
        tenant_id=TENANT,
        instance_id=instance_id,
        volume_id=volume_id,
        provider_id="test-provider",
        job_id="job-v2-002",
        trivy_server_url=TRIVY_URL,
        region=REGION,
        account_id=ACCOUNT,
        resource_key="ec2-findings-key",
    )

    assert result["cve_count"] == 1
    assert result["secret_count"] == 1
    assert result["findings_count"] == 2

    cursor = db_tenant_a.aql.execute("FOR f IN findings FILTER f.tenant_id == @tid RETURN f", bind_vars={"tid": TENANT})
    findings = list(cursor)
    assert len(findings) == 2

    check_ids = {f["check_id"] for f in findings}
    assert "side_scanning/cve/CVE-2024-1111" in check_ids
    assert "side_scanning/secret/github-token" in check_ids


@pytest.mark.integration
@mock_aws
def test_v2_sbom_persisted_in_arango(db_tenant_a: Any, mocker: Any) -> None:
    """CycloneDX SBOM is generated and stored in the sboms collection with HAS_SBOM edge."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok(_trivy_sbom_json())
        return _ok(_trivy_vuln_json())

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.wait_for_snapshot", return_value=None)

    db_tenant_a.collection("resources").insert(
        {"_key": "ec2-sbom-key", "tenant_id": TENANT, "provider": "aws", "resource_type": "ec2_instance"}
    )

    result = scan_ec2_instance_v2(
        tenant_id=TENANT,
        instance_id=instance_id,
        volume_id=volume_id,
        provider_id="test-provider",
        job_id="job-v2-003",
        trivy_server_url=TRIVY_URL,
        region=REGION,
        account_id=ACCOUNT,
        resource_key="ec2-sbom-key",
    )

    assert result["sbom_components"] == 1

    sboms = list(db_tenant_a.collection("sboms").all())
    assert len(sboms) == 1
    assert sboms[0]["tenant_id"] == TENANT
    assert sboms[0]["format"] == "cyclonedx"
    assert sboms[0]["component_count"] == 1

    edges = list(db_tenant_a.collection("HAS_SBOM").all())
    assert len(edges) == 1


@pytest.mark.integration
@mock_aws
def test_v2_snapshot_deleted_even_on_trivy_error(db_tenant_a: Any, mocker: Any) -> None:
    """Snapshot is always deleted in finally even when trivy raises RuntimeError."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch(
        "app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run",
        return_value=_ok("", returncode=2),
    )
    mocker.patch("app.workers.tasks.side_scanning.wait_for_snapshot", return_value=None)

    with pytest.raises(RuntimeError):
        scan_ec2_instance_v2(
            tenant_id=TENANT,
            instance_id=instance_id,
            volume_id=volume_id,
            provider_id="test-provider",
            job_id="job-v2-004",
            trivy_server_url=TRIVY_URL,
            region=REGION,
            account_id=ACCOUNT,
            resource_key="ec2-error-key",
        )

    # Despite the error, snapshot must be gone
    snaps = ec2_client.describe_snapshots(
        Filters=[{"Name": "tag:ogum:scan", "Values": ["true"]}],
        OwnerIds=["self"],
    )
    assert len(snaps["Snapshots"]) == 0


@pytest.mark.integration
@mock_aws
def test_v2_severity_from_trivy_field_not_cvss(db_tenant_a: Any, mocker: Any) -> None:
    """Trivy Severity=CRITICAL with CVSSv3=5.0 → finding must be CRITICAL (not MEDIUM)."""
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    # Severity="CRITICAL" but CVSS=5.0 (would be MEDIUM if CVSS were used)
    vuln_json = _trivy_vuln_json(severity="CRITICAL", cvss=5.0)

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok("{}")
        return _ok(vuln_json)

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.wait_for_snapshot", return_value=None)

    db_tenant_a.collection("resources").insert(
        {"_key": "ec2-severity-key", "tenant_id": TENANT, "provider": "aws", "resource_type": "ec2_instance"}
    )

    scan_ec2_instance_v2(
        tenant_id=TENANT,
        instance_id=instance_id,
        volume_id=volume_id,
        provider_id="test-provider",
        job_id="job-v2-005",
        trivy_server_url=TRIVY_URL,
        region=REGION,
        account_id=ACCOUNT,
        resource_key="ec2-severity-key",
    )

    cursor = db_tenant_a.aql.execute("FOR f IN findings FILTER f.tenant_id == @tid RETURN f", bind_vars={"tid": TENANT})
    findings = list(cursor)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"


@pytest.mark.integration
@mock_aws
def test_v2_yara_skipped_without_scanner_instance(db_tenant_a: Any, mocker: Any) -> None:
    """
    Without OGUM_SCANNER_INSTANCE_ID / availability_zone, YARA is skipped (not silently
    pretended to have run) and no scoped volume is created.
    """
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok(_trivy_sbom_json())
        return _ok(_trivy_vuln_json())

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.wait_for_snapshot", return_value=None)
    mocker.patch("app.workers.tasks.side_scanning._SCANNER_INSTANCE_ID", "")
    run_yara_mock = mocker.patch("app.workers.tasks.side_scanning.run_yara")

    baseline_volume_count = len(ec2_client.describe_volumes()["Volumes"])

    result = scan_ec2_instance_v2(
        tenant_id=TENANT,
        instance_id=instance_id,
        volume_id=volume_id,
        provider_id="test-provider",
        job_id="job-v2-yara-skip",
        trivy_server_url=TRIVY_URL,
        region=REGION,
        account_id=ACCOUNT,
        resource_key="ec2-yara-skip-key",
        # availability_zone intentionally omitted
    )

    assert result["malware_count"] == 0
    run_yara_mock.assert_not_called()

    # No scoped scan volume created — volume count unchanged from baseline
    volumes = ec2_client.describe_volumes()["Volumes"]
    assert len(volumes) == baseline_volume_count


@pytest.mark.integration
@mock_aws
def test_v2_yara_runs_via_scoped_mount_when_scanner_configured(db_tenant_a: Any, mocker: Any) -> None:
    """
    With OGUM_SCANNER_INSTANCE_ID + availability_zone set, scan_ec2_instance_v2 creates a
    scoped volume, mounts it, runs YARA, and cleans up the volume afterwards — restoring
    malware detection that EBS Direct API alone cannot provide (no file-level access).
    """
    ec2_client = boto3.client("ec2", region_name=REGION)
    instance_id, volume_id = _seed_ec2(ec2_client)
    init_tenant_schema(db_tenant_a)

    db_tenant_a.collection("resources").insert(
        {"_key": "ec2-yara-hit-key", "tenant_id": TENANT, "provider": "aws", "resource_type": "ec2_instance"}
    )

    def _subprocess_mock(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
        if "cyclonedx" in cmd:
            return _ok(_trivy_sbom_json())
        return _ok(_trivy_vuln_json())

    yara_output = [{"rule": "Webshell_Generic", "path": "/mnt/target/var/www/html/shell.php"}]

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", _subprocess_mock)
    mocker.patch("app.workers.tasks.side_scanning.wait_for_snapshot", return_value=None)
    mocker.patch("app.workers.tasks.side_scanning._SCANNER_INSTANCE_ID", instance_id)
    mocker.patch("app.workers.tasks.side_scanning.mount_volume_ro", return_value=None)
    mocker.patch("app.workers.tasks.side_scanning.umount_volume", return_value=None)
    mocker.patch("app.workers.tasks.side_scanning.run_yara", return_value=yara_output)

    baseline_volume_count = len(ec2_client.describe_volumes()["Volumes"])

    result = scan_ec2_instance_v2(
        tenant_id=TENANT,
        instance_id=instance_id,
        volume_id=volume_id,
        provider_id="test-provider",
        job_id="job-v2-yara-hit",
        trivy_server_url=TRIVY_URL,
        region=REGION,
        account_id=ACCOUNT,
        resource_key="ec2-yara-hit-key",
        availability_zone=AZ,
    )

    assert result["malware_count"] == 1

    cursor = db_tenant_a.aql.execute(
        "FOR f IN findings FILTER f.tenant_id == @tid AND CONTAINS(f.check_id, 'malware') RETURN f",
        bind_vars={"tid": TENANT},
    )
    findings = list(cursor)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"

    # Scoped scan volume must be created (proving the mount path ran) then cleaned up —
    # volume count is back at baseline after the task completes
    volumes = ec2_client.describe_volumes()["Volumes"]
    assert len(volumes) == baseline_volume_count


# ─── scan_lambda_function ─────────────────────────────────────────────────────


@pytest.mark.integration
@mock_aws
def test_lambda_downloads_zip_and_scans(db_tenant_a: Any, mocker: Any) -> None:
    """Lambda task downloads code ZIP, scans it, persists finding, and cleans up /dev/shm."""
    init_tenant_schema(db_tenant_a)

    # Seed a Lambda function in moto
    iam_client = boto3.client("iam", region_name=REGION)
    role = iam_client.create_role(
        RoleName="test-lambda-role",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )
    role_arn = role["Role"]["Arn"]

    lambda_client = boto3.client("lambda", region_name=REGION)
    lambda_client.create_function(
        FunctionName="test-function",
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _make_zip()},
    )

    # Mock httpx.get to return the ZIP bytes
    zip_bytes = _make_zip()
    mock_response = MagicMock()
    mock_response.content = zip_bytes
    mock_response.raise_for_status = MagicMock()
    mocker.patch("app.workers.tasks.side_scanning.httpx.get", return_value=mock_response)

    # Mock trivy fs subprocess
    mocker.patch(
        "app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run",
        return_value=_ok(_trivy_vuln_json(cve="CVE-2024-LAMBDA", severity="HIGH")),
    )

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)

    function_arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:test-function"
    db_tenant_a.collection("resources").insert(
        {
            "_key": function_arn.replace("/", "_").replace(":", "_"),
            "tenant_id": TENANT,
            "provider": "aws",
            "resource_type": "lambda_function",
        }
    )

    result = scan_lambda_function(
        tenant_id=TENANT,
        function_name="test-function",
        function_arn=function_arn,
        provider_id="test-provider",
        job_id="job-lambda-001",
        trivy_server_url=TRIVY_URL,
        region=REGION,
        account_id=ACCOUNT,
    )

    assert result["function_name"] == "test-function"
    assert result["findings_count"] == 1

    cursor = db_tenant_a.aql.execute(
        "FOR f IN findings FILTER f.tenant_id == @tid AND f.resource_type == 'lambda_function' RETURN f",
        bind_vars={"tid": TENANT},
    )
    findings = list(cursor)
    assert len(findings) == 1
    assert findings[0]["raw_output"]["detection_method"] == "lambda_zip"


@pytest.mark.integration
@mock_aws
def test_lambda_cleanup_runs_on_error(db_tenant_a: Any, mocker: Any) -> None:
    """RAM disk (/dev/shm) is cleaned up even when trivy raises."""
    init_tenant_schema(db_tenant_a)

    iam_client = boto3.client("iam", region_name=REGION)
    role = iam_client.create_role(
        RoleName="test-lambda-role-err",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )
    lambda_client = boto3.client("lambda", region_name=REGION)
    lambda_client.create_function(
        FunctionName="test-function-err",
        Runtime="python3.12",
        Role=role["Role"]["Arn"],
        Handler="index.handler",
        Code={"ZipFile": _make_zip()},
    )

    mock_response = MagicMock()
    mock_response.content = _make_zip()
    mock_response.raise_for_status = MagicMock()
    mocker.patch("app.workers.tasks.side_scanning.httpx.get", return_value=mock_response)

    mocker.patch(
        "app.services.side_scanning.analyzers.trivy_analyzer.subprocess.run",
        return_value=_ok("", returncode=2),
    )
    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)

    import os

    function_arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:test-function-err"
    job_id = "job-lambda-err"

    # Trivy raises → task should either handle or propagate, but /dev/shm must be gone
    try:
        scan_lambda_function(
            tenant_id=TENANT,
            function_name="test-function-err",
            function_arn=function_arn,
            provider_id="test-provider",
            job_id=job_id,
            trivy_server_url=TRIVY_URL,
            region=REGION,
            account_id=ACCOUNT,
        )
    except Exception:
        pass

    # RAM disk must not exist regardless of task outcome
    ram_dir = f"/dev/shm/ogum-{job_id}"
    assert not os.path.exists(ram_dir), f"RAM disk {ram_dir} was not cleaned up"


# ─── rescan_sboms ─────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_rescan_sboms_rescans_existing_sbom(db_tenant_a: Any, mocker: Any) -> None:
    """rescan_sboms finds a stored SBOM, runs trivy, and persists new CVE finding."""
    init_tenant_schema(db_tenant_a)

    sbom_content = json.loads(_trivy_sbom_json())
    db_tenant_a.collection("sboms").insert(
        {
            "_key": f"{TENANT}_ec2-rescan-key",
            "tenant_id": TENANT,
            "resource_id": "ec2-rescan-key",
            "format": "cyclonedx",
            "content": sbom_content,
            "component_count": 1,
        }
    )

    rescan_trivy_output = json.dumps(
        {
            "Results": [
                {
                    "Target": "sbom",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-RESCAN",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.0",
                            "FixedVersion": "3.0.9",
                            "Severity": "HIGH",
                            "Title": "New CVE from SBOM rescan",
                            "Description": "Found via SBOM rescan",
                        }
                    ],
                }
            ]
        }
    )

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", return_value=_ok(rescan_trivy_output))

    result = rescan_sboms(tenant_id=TENANT, trivy_server_url=TRIVY_URL)

    assert result["sboms_scanned"] == 1
    assert result["new_findings"] == 1

    cursor = db_tenant_a.aql.execute("FOR f IN findings FILTER f.tenant_id == @tid RETURN f", bind_vars={"tid": TENANT})
    findings = list(cursor)
    assert len(findings) == 1
    assert findings[0]["raw_output"]["detection_method"] == "sbom_rescan"
    assert findings[0]["check_id"] == "side_scanning/cve/CVE-2024-RESCAN"


@pytest.mark.integration
def test_rescan_sboms_empty_returns_zero(db_tenant_a: Any, mocker: Any) -> None:
    """rescan_sboms with no SBOMs in DB returns zero counts without error."""
    init_tenant_schema(db_tenant_a)
    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)

    result = rescan_sboms(tenant_id=TENANT, trivy_server_url=TRIVY_URL)

    assert result["sboms_scanned"] == 0
    assert result["new_findings"] == 0


@pytest.mark.integration
def test_rescan_sboms_severity_from_trivy_field(db_tenant_a: Any, mocker: Any) -> None:
    """Severity field from Trivy is used even for rescan findings (not CVSS)."""
    init_tenant_schema(db_tenant_a)

    sbom_content = json.loads(_trivy_sbom_json())
    db_tenant_a.collection("sboms").insert(
        {
            "_key": f"{TENANT}_ec2-sev-key",
            "tenant_id": TENANT,
            "resource_id": "ec2-sev-key",
            "format": "cyclonedx",
            "content": sbom_content,
            "component_count": 1,
        }
    )

    rescan_output = json.dumps(
        {
            "Results": [
                {
                    "Target": "sbom",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-SEV",
                            "PkgName": "curl",
                            "Severity": "CRITICAL",  # Trivy says CRITICAL
                            # No CVSS block — fallback would be INFORMATIONAL without Severity field
                        }
                    ],
                }
            ]
        }
    )

    mocker.patch("app.workers.tasks.side_scanning._get_tenant_db", return_value=db_tenant_a)
    mocker.patch("app.workers.tasks.side_scanning.subprocess.run", return_value=_ok(rescan_output))

    result = rescan_sboms(tenant_id=TENANT, trivy_server_url=TRIVY_URL)
    assert result["new_findings"] == 1

    cursor = db_tenant_a.aql.execute("FOR f IN findings FILTER f.tenant_id == @tid RETURN f", bind_vars={"tid": TENANT})
    findings = list(cursor)
    assert findings[0]["severity"] == "CRITICAL"
