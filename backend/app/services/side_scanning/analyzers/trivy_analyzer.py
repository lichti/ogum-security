"""Trivy filesystem scan wrapper for side-scanning."""

from __future__ import annotations

import json
import logging
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


def run_trivy_fs(path: str, timeout: int = 1800) -> list[dict[str, Any]]:
    """Run `trivy fs` on a mounted path. Returns list of normalised vulnerability dicts."""
    result = subprocess.run(
        ["trivy", "fs", "--format", "json", "--quiet", "--no-progress", path],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    # trivy exits 1 when vulnerabilities are found — not an error
    if result.returncode not in (0, 1):
        raise RuntimeError(f"trivy exited {result.returncode}: {result.stderr[:500]}")
    if not result.stdout.strip():
        return []
    data = json.loads(result.stdout)
    vulns: list[dict[str, Any]] = []
    for item in data.get("Results", []):
        for v in item.get("Vulnerabilities") or []:
            vulns.append(
                {
                    "cve_id": v.get("VulnerabilityID", ""),
                    "package": v.get("PkgName", ""),
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", ""),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "cvss_score": _extract_cvss(v),
                    "title": v.get("Title", "")[:200],
                    "description": (v.get("Description") or "")[:500],
                }
            )
    logger.info("Trivy found %d vulnerabilities in %s", len(vulns), path)
    return vulns


def run_trivy_ebs(
    snapshot_id: str,
    trivy_server_url: str = "http://trivy-server:4954",
    timeout: int = 1800,
    trivyignore_path: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Scan an EBS snapshot via EBS Direct API using trivy client + sidecar server.
    Returns (vulnerabilities, secrets). Trivy Severity field takes precedence over CVSS score.
    """
    cmd = [
        "trivy",
        "client",
        "--server",
        trivy_server_url,
        "vm",
        f"ebs:{snapshot_id}",
        "--scanners",
        "vuln,secret",
        "--ignore-unfixed",
        "--format",
        "json",
        "--quiet",
        "--no-progress",
    ]
    if trivyignore_path:
        cmd.extend(["--ignorefile", trivyignore_path])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    if result.returncode not in (0, 1):
        raise RuntimeError(f"trivy client exited {result.returncode}: {result.stderr[:500]}")
    if not result.stdout.strip():
        return [], []

    data = json.loads(result.stdout)
    vulns: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []

    for item in data.get("Results", []):
        target = item.get("Target", "")
        for v in item.get("Vulnerabilities") or []:
            # Trivy Severity field is primary; CVSS only as fallback for UNKNOWN
            vulns.append(
                {
                    "cve_id": v.get("VulnerabilityID", ""),
                    "package": v.get("PkgName", ""),
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", ""),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "cvss_score": _extract_cvss(v),
                    "title": v.get("Title", "")[:200],
                    "description": (v.get("Description") or "")[:500],
                }
            )
        for s in item.get("Secrets") or []:
            # Never include Match field — redacted by Trivy as ****
            secrets.append(
                {
                    "rule_id": s.get("RuleID", ""),
                    "category": s.get("Category", ""),
                    "title": s.get("Title", ""),
                    "severity": s.get("Severity", "HIGH"),
                    "target": target,
                }
            )

    logger.info("Trivy EBS scan: %d vulns, %d secrets from snapshot %s", len(vulns), len(secrets), snapshot_id)
    return vulns, secrets


def _extract_cvss(vuln: dict[str, Any]) -> float:
    """Extract the best available CVSS v3 score, fallback 0.0."""
    cvss_block = vuln.get("CVSS") or {}
    for _source, scores in cvss_block.items():
        v3 = scores.get("V3Score")
        if v3 is not None:
            try:
                return float(v3)
            except (TypeError, ValueError):
                pass
    return 0.0
