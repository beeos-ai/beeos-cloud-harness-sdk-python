"""Synchronous lossless native chat transport for native Harness worker threads."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from . import BeeOSAgentRuntime

CHAT_STORE_ROUTES = {
    "load": "/api/v1/runtime/chat-store/load",
    "append": "/api/v1/runtime/chat-store/append",
    "receipt": "/api/v1/runtime/chat-store/receipt",
}


class ChatStoreOutcomeUnknown(RuntimeError):
    """The original append may have committed; query its original key and digest."""

    code = "outcome_unknown"

    def __init__(self, request: Mapping[str, Any]) -> None:
        super().__init__("central chat append outcome is unknown; query its original receipt")
        self.request = request


class RuntimeChatStore:
    """No automatic replay, no local payload store, and no independent auth identity."""

    def __init__(self, runtime: BeeOSAgentRuntime, execution_grant: str | None = None) -> None:
        self._runtime = runtime
        self._execution_grant = execution_grant

    def for_execution(self, execution_grant: str) -> RuntimeChatStore:
        if not execution_grant:
            raise ValueError("central chat requires an execution grant")
        return RuntimeChatStore(self._runtime, execution_grant)

    def load(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._request("load", body)

    def append(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._commit_result(self._request("append", body), body)

    def receipt(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._commit_result(self._request("receipt", body), body)

    @staticmethod
    def _commit_result(result: dict[str, Any], body: Mapping[str, Any]) -> dict[str, Any]:
        receipt = result.get("receipt")
        if not isinstance(result.get("replay"), bool) or not isinstance(receipt, dict) or not receipt.get("receipt_id") or any(
            receipt.get(key) != body.get(key) for key in
            ("idempotency_key", "payload_sha256", "session_id", "history_generation", "branch_id")
        ):
            raise ChatStoreOutcomeUnknown(body)
        return receipt

    def _request(self, operation: str, body: Mapping[str, Any]) -> dict[str, Any]:
        from . import BeeOSAgentError

        if not self._execution_grant or not self._runtime.token():
            raise ValueError("central chat requires the current runtime lease and execution grant")
        try:
            result = self._runtime.request("message", "POST", CHAT_STORE_ROUTES[operation],
                dict(body), {"X-BeeOS-Execution-Grant": self._execution_grant})
        except BeeOSAgentError as error:
            if operation == "append" and error.status >= 500:
                raise ChatStoreOutcomeUnknown(body) from error
            raise
        except (OSError, ValueError) as error:
            if operation == "append":
                raise ChatStoreOutcomeUnknown(body) from error
            raise
        if not isinstance(result, dict):
            if operation == "append":
                raise ChatStoreOutcomeUnknown(body)
            raise ValueError("central chat returned an invalid response object")
        return result
