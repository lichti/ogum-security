"""TruffleHog3 secret scanner wrapper for side-scanning."""

from __future__ import annotations

import json
import logging
import subprocess

logger = logging.getLogger(__name__)


def run_trufflehog(path: str, timeout: int = 1800) -> list[dict[str, object]]:
    """Run trufflehog3 filesystem scan.

    Returns metadata-only dicts — secret values are NEVER included.
    Caller must never log the original secret found on disk.
    """
    result = subprocess.run(
        ["trufflehog3", "filesystem", path, "--json"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode not in (0, 1):
        logger.warning("trufflehog3 exited %d: %s", result.returncode, result.stderr[:300])
        return []

    secrets: list[dict[str, object]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            secrets.append(
                {
                    "rule": entry.get("rule", "unknown"),
                    "path": entry.get("path", ""),
                    "line": entry.get("line", 0),
                }
            )
        except json.JSONDecodeError:
            pass

    logger.info("TruffleHog found %d secrets in %s", len(secrets), path)
    return secrets
