import httpx
import pytest

from beeos_cloud_harness_sdk.retry import (
    STARTUP_BACKOFF,
    TRANSIENT_BACKOFF,
    BackoffPolicy,
    CloudHttpError,
    delay_for_attempt,
    is_transient_error,
    retry_with_backoff,
)


async def _no_sleep(_s: float) -> None:
    return None


def test_policy_numbers_match_typescript_sdk():
    assert (TRANSIENT_BACKOFF.max_attempts, TRANSIENT_BACKOFF.initial_delay_ms, TRANSIENT_BACKOFF.max_delay_ms) == (3, 200, 500)
    assert (STARTUP_BACKOFF.initial_delay_ms, STARTUP_BACKOFF.max_delay_ms, STARTUP_BACKOFF.budget_ms) == (1000, 15000, 120000)
    assert [delay_for_attempt(STARTUP_BACKOFF, n) for n in (1, 2, 3, 5, 6)] == [1000, 2000, 4000, 15000, 15000]


async def test_retries_connect_errors_until_success():
    calls = 0

    async def op(_n: int) -> str:
        nonlocal calls
        calls += 1
        if calls < 3:
            raise httpx.ConnectError("refused")
        return "ok"

    assert await retry_with_backoff(op, TRANSIENT_BACKOFF, sleep=_no_sleep) == "ok"
    assert calls == 3


async def test_does_not_retry_4xx_and_stops_at_max_attempts():
    async def denied(_n: int) -> None:
        raise CloudHttpError("GET", "/x", 403, '{"code":"forbidden"}')

    with pytest.raises(CloudHttpError) as info:
        await retry_with_backoff(denied, TRANSIENT_BACKOFF, sleep=_no_sleep)
    assert info.value.code == "forbidden" and not info.value.transient

    attempts = 0

    async def down(_n: int) -> None:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("refused")

    with pytest.raises(httpx.ConnectError):
        await retry_with_backoff(down, TRANSIENT_BACKOFF, sleep=_no_sleep)
    assert attempts == 3


async def test_startup_policy_survives_a_not_ready_control_plane_within_budget():
    clock = [0.0]
    ready_at = 45.0
    attempts = 0

    async def sleep(seconds: float) -> None:
        clock[0] += seconds

    async def probe(_n: int) -> str:
        nonlocal attempts
        attempts += 1
        if clock[0] < ready_at:
            raise httpx.ConnectError("control plane not ready")
        return "ready"

    assert await retry_with_backoff(probe, STARTUP_BACKOFF, sleep=sleep, now=lambda: clock[0]) == "ready"
    assert attempts > 3


async def test_budget_exhaustion_raises_the_last_error():
    clock = [0.0]

    async def sleep(seconds: float) -> None:
        clock[0] += seconds

    async def never(_n: int) -> None:
        raise httpx.ConnectError("down")

    with pytest.raises(httpx.ConnectError):
        await retry_with_backoff(never, BackoffPolicy(float("inf"), 1000, 15000, 2, 10_000),
                                 sleep=sleep, now=lambda: clock[0])
    assert clock[0] <= 10


def test_transient_classification():
    assert is_transient_error(httpx.ReadTimeout("t"))
    assert is_transient_error(CloudHttpError("GET", "/x", 503, ""))
    assert not is_transient_error(CloudHttpError("GET", "/x", 404, ""))
    assert not is_transient_error(ValueError("bad"))
