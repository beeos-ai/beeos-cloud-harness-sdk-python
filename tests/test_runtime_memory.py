import json

import pytest

from beeos_cloud_harness_sdk import BeeOSAgentError, BeeOSAgentRuntime

EXECUTION = {"operation_id": "op", "request_message_id": "request", "native_request_hash": "a" * 64, "attempt_id": "attempt"}


@pytest.mark.parametrize("action,arguments", [
    ("remember", {"content": "value", "kind": "semantic"}),
    ("recall", {"query": "记忆", "limit": 3}),
    ("revise", {"record_id": "record", "expected_revision": 1, "content": "new", "reason": "updated"}),
    ("forget", {"record_ids": ["record"], "reason": "outdated"}),
])
def test_exact_native_tool_call_and_owner_receipt(action, arguments):
    calls = []
    receipt = {"receipt_id": "original", "read_watermark": "actual-scope-watermark"}
    def send(method, url, headers, data):
        calls.append((method, url, headers, json.loads(data)))
        return 200, json.dumps(receipt).encode(), {}
    runtime = BeeOSAgentRuntime("https://gateway.test", "https://message.test", "instance", "agent", "lease", transport=send)
    assert runtime.memory.for_execution("fresh-grant").call(action, EXECUTION, "provider:real/tool/😀", arguments) == receipt
    assert calls[0][1] == "https://gateway.test/api/v1/runtime/memory/" + action
    assert calls[0][3] == {**EXECUTION, "tool_call_id": "provider:real/tool/😀", "arguments": arguments}
    assert calls[0][2]["Authorization"] == "Bearer lease"
    assert calls[0][2]["X-BeeOS-Execution-Grant"] == "fresh-grant"


def test_source_denial_is_visible_without_retry_or_missing_authority_call():
    calls = []
    def send(*args):
        calls.append(args)
        return 503, b'{"error":{"code":"source_unavailable","message":"source unavailable"}}', {}
    runtime = BeeOSAgentRuntime("https://gateway.test", "https://message.test", "instance", "agent", "lease", transport=send)
    with pytest.raises(BeeOSAgentError) as error:
        runtime.memory.for_execution("fresh-grant").call("remember", EXECUTION, "real-call", {"content": "value", "kind": "core"})
    assert error.value.code == "source_unavailable"
    assert len(calls) == 1
    with pytest.raises(ValueError): runtime.memory.call("recall", EXECUTION, "real-call", {"query": "q"})
    assert len(calls) == 1
