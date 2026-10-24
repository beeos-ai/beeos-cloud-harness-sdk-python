"""Original-execution transport to the existing canonical Memory domain."""
from __future__ import annotations

import re
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from . import BeeOSAgentRuntime


class RuntimeMemory:
    def __init__(self, runtime: BeeOSAgentRuntime, execution_grant: str | None = None) -> None:
        self._runtime = runtime
        self._execution_grant = execution_grant

    def for_execution(self, execution_grant: str) -> RuntimeMemory:
        if not execution_grant:
            raise ValueError("native Memory requires a fresh execution grant")
        return RuntimeMemory(self._runtime, execution_grant)

    def call(self, action: str, execution: dict[str, str], tool_call_id: str, arguments: dict[str, Any]) -> dict[str, Any]:
        body = {key: execution.get(key) for key in
                ("operation_id", "request_message_id", "native_request_hash", "attempt_id")}
        if (action not in {"remember", "recall", "revise", "forget"} or not self._execution_grant or not self._runtime.token()
                or any(not isinstance(value, str) or not value for value in body.values())
                or not re.fullmatch(r"[a-f0-9]{64}", body["native_request_hash"])
                or not isinstance(tool_call_id, str) or not tool_call_id.strip() or "\x00" in tool_call_id or len(tool_call_id) > 256):
            raise ValueError("native Memory requires current original authority and the actual tool-call ID")
        result = self._runtime.request("gateway", "POST", "/api/v1/runtime/memory/" + action,
            {**body, "tool_call_id": tool_call_id, "arguments": arguments},
            {"X-BeeOS-Execution-Grant": self._execution_grant})
        if not isinstance(result, dict):
            raise ValueError("native Memory returned no original receipt/page")
        return result
