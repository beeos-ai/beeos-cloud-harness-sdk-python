"""One retry/backoff vocabulary for every Cloud control-plane call a harness makes.

Hosts never write their own sleep loops: they pick a policy. Names and numbers
mirror the TypeScript SDK (`@beeos-ai/cloud-harness-sdk`, `src/retry.ts`).
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

import httpx

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class BackoffPolicy:
    #: Total attempts including the first. ``math.inf`` retries until ``budget_ms``/cancellation.
    max_attempts: float
    initial_delay_ms: int
    max_delay_ms: int
    factor: float
    #: Total wall-clock budget; the last attempt may start before it, never after.
    budget_ms: int | None = None


#: Brief ALB/Agent-Gateway blips on ordinary calls (3 attempts, 200/500 ms).
TRANSIENT_BACKOFF = BackoffPolicy(3, 200, 500, 2.5)
#: Control plane not ready yet (pod started while Cloud was rolling out): 1 s -> 15 s for up to 2 minutes.
STARTUP_BACKOFF = BackoffPolicy(math.inf, 1_000, 15_000, 2, 120_000)

TRANSIENT_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


def is_transient_status(status: int) -> bool:
    return status in TRANSIENT_STATUSES


_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class CloudHttpError(RuntimeError):
    """Any non-2xx Cloud answer; ``body`` is truncated and never holds credentials."""

    def __init__(self, method: str, path: str, status: int, body: str) -> None:
        super().__init__(f"{method} {path} failed: HTTP {status}{(' ' + body[:240]) if body else ''}")
        self.method = method
        self.path = path
        self.status = status
        self.body = body[:2048]
        self.code = _error_code_of(body)

    @property
    def transient(self) -> bool:
        return is_transient_status(self.status)


def _error_code_of(body: str) -> str | None:
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    err = parsed.get("error")
    code = err.get("code") if isinstance(err, dict) and isinstance(err.get("code"), str) else parsed.get("code")
    return code if isinstance(code, str) and _CODE_RE.match(code) else None


def is_transient_error(error: BaseException) -> bool:
    if isinstance(error, CloudHttpError):
        return error.transient
    if isinstance(error, asyncio.CancelledError):
        return False
    # Refused/reset/DNS/timeout failures from httpx and the OS.
    return isinstance(error, (httpx.TransportError, ConnectionError, TimeoutError))


def delay_for_attempt(policy: BackoffPolicy, attempt: int) -> int:
    return min(policy.max_delay_ms, round(policy.initial_delay_ms * policy.factor ** (attempt - 1)))


async def retry_with_backoff(
    operation: Callable[[int], Awaitable[T]],
    policy: BackoffPolicy,
    *,
    is_retryable: Callable[[BaseException], bool] = is_transient_error,
    on_retry: Callable[[int, int, BaseException], None] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    now: Callable[[], float] = time.monotonic,
) -> T:
    """Run ``operation`` until it succeeds, a non-retryable error occurs, or the policy is exhausted."""
    started = now()
    attempt = 0
    while True:
        attempt += 1
        try:
            return await operation(attempt)
        except Exception as error:  # noqa: BLE001 - policy decides what is retryable
            if not is_retryable(error) or attempt >= policy.max_attempts:
                raise
            delay_ms = delay_for_attempt(policy, attempt)
            if policy.budget_ms is not None and (now() - started) * 1000 + delay_ms > policy.budget_ms:
                raise
            if on_retry is not None:
                on_retry(attempt, delay_ms, error)
            await sleep(delay_ms / 1000)
