"""YARA malware signature scanner wrapper for side-scanning."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

YARA_RULES_DIR = "/opt/ogum/yara-rules"


def run_yara(path: str, timeout: int = 1800) -> list[dict[str, str]]:
    """Run YARA rules recursively against a mounted path.

    Returns list of matches. Returns empty list if YARA rules directory is absent
    (not installed) rather than raising — YARA is optional in dev environments.
    """
    rules_dir = Path(YARA_RULES_DIR)
    if not rules_dir.exists():
        logger.debug("YARA rules directory %s not found — skipping", YARA_RULES_DIR)
        return []

    result = subprocess.run(
        ["yara", "-r", str(rules_dir), path],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    # yara exits 0 on match, 1 on no match, >1 on error
    if result.returncode > 1:
        logger.warning("YARA exited %d: %s", result.returncode, result.stderr[:300])
        return []

    matches: list[dict[str, str]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2:
            matches.append({"rule": parts[0], "path": parts[1]})

    logger.info("YARA found %d matches in %s", len(matches), path)
    return matches
