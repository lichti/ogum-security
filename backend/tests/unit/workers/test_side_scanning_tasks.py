"""Unit tests for app.workers.tasks.side_scanning module-level helpers."""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from app.workers.tasks import side_scanning


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _sbom_json() -> str:
    return json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "openssl", "version": "3.0.0"}]})


@pytest.mark.unit
class TestGenerateSbom:
    def test_success_on_first_attempt_returns_parsed_json_no_sleep(self, mocker: Any) -> None:
        run = mocker.patch(
            "app.workers.tasks.side_scanning.subprocess.run",
            return_value=_completed(0, stdout=_sbom_json()),
        )
        sleep = mocker.patch("app.workers.tasks.side_scanning.time.sleep")

        result = side_scanning._generate_sbom("snap-1", "http://trivy-server:4954", "job-1")

        assert result["bomFormat"] == "CycloneDX"
        assert run.call_count == 1
        sleep.assert_not_called()

    def test_empty_stdout_retries_then_succeeds(self, mocker: Any) -> None:
        # Simulates EBS Direct API throttling on the immediate second read of a
        # snapshot: first attempt(s) come back exit 1 / empty stdout, a later
        # attempt succeeds once the throttle window has passed.
        run = mocker.patch(
            "app.workers.tasks.side_scanning.subprocess.run",
            side_effect=[
                _completed(1, stdout=""),
                _completed(0, stdout=_sbom_json()),
            ],
        )
        sleep = mocker.patch("app.workers.tasks.side_scanning.time.sleep")

        result = side_scanning._generate_sbom("snap-1", "http://trivy-server:4954", "job-1", max_attempts=3)

        assert result["bomFormat"] == "CycloneDX"
        assert run.call_count == 2
        sleep.assert_called_once_with(5.0)

    def test_exhausts_all_attempts_returns_empty_dict(self, mocker: Any) -> None:
        run = mocker.patch(
            "app.workers.tasks.side_scanning.subprocess.run",
            return_value=_completed(1, stdout=""),
        )
        sleep = mocker.patch("app.workers.tasks.side_scanning.time.sleep")

        result = side_scanning._generate_sbom(
            "snap-1", "http://trivy-server:4954", "job-1", max_attempts=3, backoff_seconds=2.0
        )

        assert result == {}
        assert run.call_count == 3
        # backoff between attempts only (2 sleeps for 3 attempts), increasing linearly
        assert sleep.call_args_list == [mocker.call(2.0), mocker.call(4.0)]

    def test_invalid_json_returns_empty_dict_without_retry(self, mocker: Any) -> None:
        run = mocker.patch(
            "app.workers.tasks.side_scanning.subprocess.run",
            return_value=_completed(0, stdout="not json"),
        )
        sleep = mocker.patch("app.workers.tasks.side_scanning.time.sleep")

        result = side_scanning._generate_sbom("snap-1", "http://trivy-server:4954", "job-1", max_attempts=3)

        assert result == {}
        assert run.call_count == 1
        sleep.assert_not_called()
