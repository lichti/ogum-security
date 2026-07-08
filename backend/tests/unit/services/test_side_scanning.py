"""Unit tests for side-scanning service helpers."""

from __future__ import annotations

import json
import subprocess
from subprocess import CompletedProcess
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.models.finding import SeverityLevel
from app.services.side_scanning import cvss_to_severity
from app.services.side_scanning.analyzers.trivy_analyzer import (
    _extract_cvss,
    run_trivy_ebs,
    run_trivy_image,
    run_trivy_rootfs,
)
from app.services.side_scanning.snapshot_manager import delete_snapshot_safe, scan_with_ebs_direct


@pytest.mark.unit
class TestCvssToSeverity:
    def test_critical_threshold(self):
        assert cvss_to_severity(9.0) == SeverityLevel.CRITICAL

    def test_critical_above_threshold(self):
        assert cvss_to_severity(10.0) == SeverityLevel.CRITICAL

    def test_high_threshold(self):
        assert cvss_to_severity(7.0) == SeverityLevel.HIGH

    def test_high_below_critical(self):
        assert cvss_to_severity(8.9) == SeverityLevel.HIGH

    def test_medium_threshold(self):
        assert cvss_to_severity(4.0) == SeverityLevel.MEDIUM

    def test_medium_below_high(self):
        assert cvss_to_severity(6.9) == SeverityLevel.MEDIUM

    def test_low_above_zero(self):
        assert cvss_to_severity(3.9) == SeverityLevel.LOW

    def test_low_minimum(self):
        assert cvss_to_severity(0.1) == SeverityLevel.LOW

    def test_informational_zero(self):
        assert cvss_to_severity(0.0) == SeverityLevel.INFORMATIONAL

    def test_informational_negative(self):
        # Defensive: negative score (malformed input) maps to INFORMATIONAL
        assert cvss_to_severity(-1.0) == SeverityLevel.INFORMATIONAL


@pytest.mark.unit
class TestExtractCvss:
    def test_extracts_nvd_v3_score(self):
        vuln = {"CVSS": {"nvd": {"V3Score": 7.5}}}
        assert _extract_cvss(vuln) == 7.5

    def test_extracts_vendor_score(self):
        vuln = {"CVSS": {"redhat": {"V3Score": 5.0}}}
        assert _extract_cvss(vuln) == 5.0

    def test_returns_zero_when_no_cvss(self):
        assert _extract_cvss({}) == 0.0

    def test_returns_zero_when_no_v3(self):
        vuln = {"CVSS": {"nvd": {"V2Score": 6.0}}}
        assert _extract_cvss(vuln) == 0.0

    def test_handles_malformed_cvss(self):
        vuln = {"CVSS": {"nvd": {"V3Score": "not-a-number"}}}
        assert _extract_cvss(vuln) == 0.0


# ─── Sprint 2: run_trivy_ebs ─────────────────────────────────────────────────

_TRIVY_EBS_JSON = json.dumps(
    {
        "Results": [
            {
                "Target": "usr/bin/python3",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.0",
                        "FixedVersion": "3.0.8",
                        "Severity": "CRITICAL",
                        "CVSS": {"nvd": {"V3Score": 5.0}},  # CVSS says MEDIUM but Severity says CRITICAL
                        "Title": "OpenSSL heap overflow",
                        "Description": "Critical heap overflow in OpenSSL",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Title": "AWS Access Key ID",
                        "Severity": "HIGH",
                        "Match": "****",  # redacted by Trivy
                    }
                ],
            }
        ]
    }
)


def _make_completed(returncode: int = 0, stdout: str = _TRIVY_EBS_JSON, stderr: str = "") -> CompletedProcess[str]:
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.mark.unit
class TestRunTrivyEbs:
    def test_parses_vulnerabilities_from_json(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed())
        vulns, _ = run_trivy_ebs("snap-abc")
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2024-1234"
        assert vulns[0]["package"] == "openssl"

    def test_parses_secrets_from_json(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed())
        _, secrets = run_trivy_ebs("snap-abc")
        assert len(secrets) == 1
        assert secrets[0]["rule_id"] == "aws-access-key-id"
        assert "Match" not in secrets[0]

    def test_trivy_severity_takes_precedence_over_cvss(self, monkeypatch: Any) -> None:
        """Trivy Severity=CRITICAL with CVSSv3=5.0 → severity field should be CRITICAL, not MEDIUM."""
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed())
        vulns, _ = run_trivy_ebs("snap-abc")
        assert vulns[0]["severity"] == "CRITICAL"
        assert vulns[0]["cvss_score"] == 5.0  # CVSS score is preserved but not used for severity

    def test_empty_output_returns_empty_lists(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed(stdout=""))
        vulns, secrets = run_trivy_ebs("snap-abc")
        assert vulns == []
        assert secrets == []

    def test_nonzero_exit_raises_runtimeerror(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed(returncode=2, stderr="fatal error"))
        with pytest.raises(RuntimeError, match="trivy client exited 2"):
            run_trivy_ebs("snap-abc")

    def test_includes_ignorefile_when_provided(self, monkeypatch: Any) -> None:
        captured: list[list[str]] = []

        def _run(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
            captured.append(cmd)
            return _make_completed()

        monkeypatch.setattr(subprocess, "run", _run)
        run_trivy_ebs("snap-abc", trivyignore_path="/etc/trivy/.trivyignore")
        assert "--ignorefile" in captured[0]
        assert "/etc/trivy/.trivyignore" in captured[0]

    def test_target_field_propagated_to_secrets(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed())
        _, secrets = run_trivy_ebs("snap-abc")
        assert secrets[0]["target"] == "usr/bin/python3"


@pytest.mark.unit
class TestDeleteSnapshotSafe:
    def test_deletes_snapshot(self) -> None:
        ec2 = MagicMock()
        delete_snapshot_safe(ec2, "snap-12345")
        ec2.delete_snapshot.assert_called_once_with(SnapshotId="snap-12345")

    def test_error_is_logged_not_raised(self) -> None:
        ec2 = MagicMock()
        ec2.delete_snapshot.side_effect = Exception("throttled")
        # Must not raise
        delete_snapshot_safe(ec2, "snap-12345")


@pytest.mark.unit
class TestScanWithEbsDirect:
    def test_builds_correct_trivy_command(self, monkeypatch: Any) -> None:
        captured: list[list[str]] = []

        def _run(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
            captured.append(cmd)
            return _make_completed()

        monkeypatch.setattr(subprocess, "run", _run)
        scan_with_ebs_direct(
            trivy_server_url="http://trivy-server:4954",
            snapshot_id="snap-xyz",
            job_id="job-001",
            tenant_id="tenant1",
        )
        cmd = captured[0]
        assert "trivy" in cmd
        assert "client" in cmd
        assert "--server" in cmd
        assert "http://trivy-server:4954" in cmd
        assert "vm" in cmd
        assert "ebs:snap-xyz" in cmd

    def test_includes_ignorefile_when_provided(self, monkeypatch: Any) -> None:
        captured: list[list[str]] = []

        def _run(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
            captured.append(cmd)
            return _make_completed()

        monkeypatch.setattr(subprocess, "run", _run)
        scan_with_ebs_direct(
            trivy_server_url="http://trivy-server:4954",
            snapshot_id="snap-xyz",
            job_id="job-001",
            tenant_id="tenant1",
            trivyignore_path="/etc/.trivyignore",
        )
        assert "--ignorefile" in captured[0]

    def test_raises_on_nonzero_exit(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed(returncode=2, stderr="error"))
        with pytest.raises(RuntimeError):
            scan_with_ebs_direct(
                trivy_server_url="http://localhost:4954",
                snapshot_id="snap-xyz",
                job_id="job-001",
                tenant_id="t1",
            )

    def test_empty_stdout_returns_empty_results(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _make_completed(stdout=""))
        result = scan_with_ebs_direct(
            trivy_server_url="http://localhost:4954",
            snapshot_id="snap-xyz",
            job_id="job-001",
            tenant_id="t1",
        )
        assert result == {"Results": []}


# ─── Sprint 3: run_trivy_rootfs ───────────────────────────────────────────────

_TRIVY_ROOTFS_JSON = json.dumps(
    {
        "Results": [
            {
                "Target": "usr/lib/python3",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-0001",
                        "PkgName": "libssl",
                        "InstalledVersion": "1.1.1",
                        "FixedVersion": "1.1.1k",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 7.8}},
                        "Title": "SSL buffer overflow",
                        "Description": "Buffer overflow in SSL",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "private-key",
                        "Category": "AsymmetricPrivateKey",
                        "Title": "Asymmetric Private Key",
                        "Severity": "HIGH",
                        "Match": "****",
                    }
                ],
            }
        ]
    }
)


def _rootfs_ok(stdout: str = _TRIVY_ROOTFS_JSON, returncode: int = 0) -> CompletedProcess[str]:
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.mark.unit
class TestRunTrivyRootfs:
    def test_parses_vulnerabilities(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _rootfs_ok())
        vulns, _ = run_trivy_rootfs("/host/proc/1234/root")
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2025-0001"
        assert vulns[0]["package"] == "libssl"

    def test_parses_secrets(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _rootfs_ok())
        _, secrets = run_trivy_rootfs("/host/proc/1234/root")
        assert len(secrets) == 1
        assert secrets[0]["rule_id"] == "private-key"
        assert "Match" not in secrets[0]

    def test_nonzero_exit_raises(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _rootfs_ok(stdout="", returncode=2))
        with pytest.raises(RuntimeError, match="trivy rootfs exited 2"):
            run_trivy_rootfs("/host/proc/1234/root")

    def test_empty_output_returns_empty_lists(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _rootfs_ok(stdout=""))
        vulns, secrets = run_trivy_rootfs("/host/proc/1234/root")
        assert vulns == []
        assert secrets == []

    def test_includes_skip_dirs_in_command(self, monkeypatch: Any) -> None:
        captured: list[list[str]] = []

        def _run(cmd: list[str], **kw: Any) -> CompletedProcess[str]:
            captured.append(cmd)
            return _rootfs_ok()

        monkeypatch.setattr(subprocess, "run", _run)
        run_trivy_rootfs("/host/proc/1234/root", skip_dirs="/proc,/sys,/dev")
        assert "--skip-dirs" in captured[0]
        assert "/proc,/sys,/dev" in captured[0]


# ─── Sprint 4: run_trivy_image ────────────────────────────────────────────────

_TRIVY_IMAGE_JSON = json.dumps(
    {
        "Results": [
            {
                "Target": "python:3.11-slim (debian 12.1)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "libcurl",
                        "InstalledVersion": "7.88.1",
                        "FixedVersion": "7.88.1-1+deb12u1",
                        "Severity": "HIGH",
                        "CVSS": {"nvd": {"V3Score": 8.1}},
                        "Title": "curl heap overflow",
                        "Description": "Heap overflow in curl",
                    }
                ],
                "Secrets": [
                    {
                        "RuleID": "aws-access-key-id",
                        "Category": "AWS",
                        "Title": "AWS Access Key ID",
                        "Severity": "CRITICAL",
                        "Match": "****",
                    }
                ],
                "Misconfigurations": [
                    {
                        "ID": "AVD-DS-0001",
                        "Title": "Missing USER instruction",
                        "Description": "Image runs as root",
                        "Severity": "HIGH",
                        "Resolution": "Add a non-root USER instruction",
                        "References": ["https://cis.org"],
                    }
                ],
            }
        ]
    }
)


def _image_ok(stdout: str = _TRIVY_IMAGE_JSON, returncode: int = 0) -> CompletedProcess[str]:
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


@pytest.mark.unit
class TestRunTrivyImage:
    def test_parses_vulnerabilities(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _image_ok())
        vulns, _, _ = run_trivy_image("123.dkr.ecr.us-east-1.amazonaws.com/app", "sha256:abc")
        assert len(vulns) == 1
        assert vulns[0]["cve_id"] == "CVE-2024-0001"
        assert vulns[0]["severity"] == "HIGH"
        assert vulns[0]["package"] == "libcurl"

    def test_parses_secrets(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _image_ok())
        _, secrets, _ = run_trivy_image("123.dkr.ecr.us-east-1.amazonaws.com/app", "sha256:abc")
        assert len(secrets) == 1
        assert secrets[0]["rule_id"] == "aws-access-key-id"
        assert "Match" not in secrets[0]

    def test_parses_misconfigurations(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _image_ok())
        _, _, misconfigs = run_trivy_image("123.dkr.ecr.us-east-1.amazonaws.com/app", "sha256:abc")
        assert len(misconfigs) == 1
        assert misconfigs[0]["id"] == "AVD-DS-0001"
        assert misconfigs[0]["severity"] == "HIGH"

    def test_nonzero_exit_raises(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _image_ok(stdout="", returncode=2))
        with pytest.raises(RuntimeError, match="trivy image exited 2"):
            run_trivy_image("img", "sha256:abc")

    def test_empty_output_returns_empty_tuples(self, monkeypatch: Any) -> None:
        monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _image_ok(stdout=""))
        vulns, secrets, misconfigs = run_trivy_image("img", "sha256:abc")
        assert vulns == []
        assert secrets == []
        assert misconfigs == []
