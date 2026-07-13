"""
Capture log records emitted during a job's execution into its scan_jobs
document, so the Admin Jobs UI can show what happened without shelling into
the Celery worker's own stdout.
"""

from __future__ import annotations

import logging
from typing import Any

_MAX_LOG_LINES = 500


class JobLogHandler(logging.Handler):
    """Buffers formatted log lines in memory; flush_to_db() persists them.

    Attached to the root logger for the duration of a task so it captures
    both the task's own logging and any library logging that propagates
    through it (Prowler, boto3 at WARNING+, etc.) without every task needing
    its own logger plumbing. Bounded to the last _MAX_LOG_LINES lines so a
    noisy scan can't grow a job document without limit.
    """

    def __init__(self, db: Any, job_id: str, collection: str = "scan_jobs") -> None:
        super().__init__(level=logging.INFO)
        self._db = db
        self._job_id = job_id
        self._collection = collection
        self._lines: list[str] = []
        self.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._lines.append(self.format(record))
            if len(self._lines) > _MAX_LOG_LINES:
                self._lines = self._lines[-_MAX_LOG_LINES:]
        except Exception:
            pass  # a formatting error must never break the task it's observing

    def flush_to_db(self) -> None:
        try:
            self._db.collection(self._collection).update({"_key": self._job_id, "logs": self._lines})
        except Exception:
            pass  # best-effort — missing logs are a UX gap, not a job failure


class capture_job_logs:  # noqa: N801 - context manager, lowercase name matches usage as `with capture_job_logs(...)`
    """Attach a JobLogHandler to the root logger for the `with` block's duration, flushing once on exit."""

    def __init__(self, db: Any, job_id: str, collection: str = "scan_jobs") -> None:
        self._handler = JobLogHandler(db, job_id, collection)

    def __enter__(self) -> JobLogHandler:
        logging.getLogger().addHandler(self._handler)
        return self._handler

    def __exit__(self, *exc_info: object) -> None:
        self._handler.flush_to_db()
        logging.getLogger().removeHandler(self._handler)
