"""Unit tests for JobLogHandler / capture_job_logs — job-scoped log capture."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from app.workers.tasks.job_logging import JobLogHandler, capture_job_logs

_TEST_LOGGER = logging.getLogger("ogum.test.job_logging")
_TEST_LOGGER.setLevel(logging.INFO)  # loggers default to WARNING; .info() calls below need this


@pytest.mark.unit
class TestJobLogHandler:
    def test_emit_formats_and_buffers_lines(self) -> None:
        db = MagicMock()
        handler = JobLogHandler(db, "job-1")
        record = _TEST_LOGGER.makeRecord(
            _TEST_LOGGER.name, logging.INFO, __file__, 1, "scan started", (), None
        )
        handler.emit(record)
        assert len(handler._lines) == 1
        assert "scan started" in handler._lines[0]

    def test_emit_never_raises_on_formatting_error(self) -> None:
        db = MagicMock()
        handler = JobLogHandler(db, "job-1")
        handler.setFormatter(None)  # type: ignore[arg-type]
        broken_record = object()  # not a real LogRecord — format() will blow up
        handler.emit(broken_record)  # type: ignore[arg-type]
        assert handler._lines == []

    def test_buffer_is_bounded(self) -> None:
        db = MagicMock()
        handler = JobLogHandler(db, "job-1")
        for i in range(600):
            record = _TEST_LOGGER.makeRecord(_TEST_LOGGER.name, logging.INFO, __file__, 1, f"line {i}", (), None)
            handler.emit(record)
        assert len(handler._lines) == 500
        assert "line 599" in handler._lines[-1]
        assert "line 0" not in handler._lines[0]

    def test_flush_to_db_writes_key_and_logs(self) -> None:
        db = MagicMock()
        handler = JobLogHandler(db, "job-1", collection="scan_jobs")
        handler._lines = ["a", "b"]
        handler.flush_to_db()
        db.collection.assert_called_once_with("scan_jobs")
        db.collection.return_value.update.assert_called_once_with({"_key": "job-1", "logs": ["a", "b"]})

    def test_flush_to_db_never_raises(self) -> None:
        db = MagicMock()
        db.collection.side_effect = RuntimeError("arango down")
        handler = JobLogHandler(db, "job-1")
        handler.flush_to_db()  # must not raise


@pytest.mark.unit
class TestCaptureJobLogs:
    def test_attaches_and_detaches_from_root_logger(self) -> None:
        db = MagicMock()
        root = logging.getLogger()
        before = list(root.handlers)
        with capture_job_logs(db, "job-1") as handler:
            assert handler in root.handlers
        assert root.handlers == before

    def test_captures_logging_calls_made_inside_the_block(self) -> None:
        db = MagicMock()
        with capture_job_logs(db, "job-1"):
            _TEST_LOGGER.info("inside the block")
        db.collection.return_value.update.assert_called_once()
        (call_args,) = db.collection.return_value.update.call_args.args
        assert any("inside the block" in line for line in call_args["logs"])

    def test_flushes_even_when_block_raises(self) -> None:
        db = MagicMock()
        with pytest.raises(ValueError):
            with capture_job_logs(db, "job-1"):
                _TEST_LOGGER.info("before the error")
                raise ValueError("boom")
        db.collection.return_value.update.assert_called_once()
