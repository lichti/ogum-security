"""
Unit tests for the retry_with_backoff decorator.
No external dependencies — all tests run in-process.
"""
import pytest
from botocore.exceptions import ClientError

from app.workers.tasks.discovery import retry_with_backoff


def _throttle_error(code: str = "Throttling") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": ""}}, "TestOperation")


@pytest.mark.unit
class TestRetryWithBackoff:
    """retry_with_backoff decorator — exponential backoff on AWS throttling."""

    def test_retries_on_throttling_and_eventually_succeeds(self, mocker) -> None:
        mocker.patch("app.workers.tasks.discovery.time.sleep")
        call_count = {"n": 0}

        @retry_with_backoff(max_retries=3, base_delay=0.0)
        def flaky() -> str:
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise _throttle_error()
            return "ok"

        result = flaky()
        assert result == "ok"
        assert call_count["n"] == 3

    def test_sleeps_between_retries(self, mocker) -> None:
        sleep_mock = mocker.patch("app.workers.tasks.discovery.time.sleep")
        call_count = {"n": 0}

        @retry_with_backoff(max_retries=3, base_delay=0.0)
        def flaky() -> str:
            call_count["n"] += 1
            if call_count["n"] < 2:
                raise _throttle_error()
            return "ok"

        flaky()
        assert sleep_mock.called, "must sleep between retries"

    def test_raises_immediately_on_non_retryable_error(self) -> None:
        @retry_with_backoff(max_retries=5, base_delay=0.0)
        def unauthorized() -> None:
            raise _throttle_error("AccessDenied")

        with pytest.raises(ClientError) as exc_info:
            unauthorized()
        assert exc_info.value.response["Error"]["Code"] == "AccessDenied"

    def test_raises_after_max_retries_exhausted(self, mocker) -> None:
        mocker.patch("app.workers.tasks.discovery.time.sleep")

        @retry_with_backoff(max_retries=3, base_delay=0.0)
        def always_throttle() -> None:
            raise _throttle_error()

        with pytest.raises(ClientError) as exc_info:
            always_throttle()
        assert exc_info.value.response["Error"]["Code"] == "Throttling"

    def test_all_retryable_codes_are_caught(self, mocker) -> None:
        mocker.patch("app.workers.tasks.discovery.time.sleep")
        retryable_codes = ["Throttling", "ThrottlingException", "RequestLimitExceeded", "ServiceUnavailable"]

        for code in retryable_codes:
            call_count = {"n": 0}

            @retry_with_backoff(max_retries=2, base_delay=0.0)
            def flaky_once() -> str:
                call_count["n"] += 1
                if call_count["n"] == 1:
                    raise _throttle_error(code)
                return "ok"

            result = flaky_once()
            assert result == "ok", f"should retry on {code}"

    def test_preserves_wrapped_function_name(self) -> None:
        @retry_with_backoff()
        def my_function() -> None:
            pass

        assert my_function.__name__ == "my_function"
