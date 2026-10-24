import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from beeos_cloud_harness_sdk import BeeOSAgentRuntime, BeeOSAgentError
from beeos_cloud_harness_sdk.jcs import native_session_request_hash
from beeos_cloud_harness_sdk.registration import RuntimeActiveLease
from beeos_cloud_harness_sdk.runtime_original_intent import RuntimeOriginalIntent


def fixture():
    now = datetime.now(timezone.utc)
    lease = RuntimeActiveLease("instance", "lease", "11", "current-token", (now + timedelta(minutes=2)).isoformat(), handler_identity="handler")
    rpc = {"jsonrpc": "2.0", "method": "session/prompt", "params": {"opaque": "原始\u0000bytes"}}
    digest = native_session_request_hash(rpc)
    locator = {"operation_id": "op", "request_message_id": "request", "native_request_hash": digest}
    envelope = {"request": {"schemaVersion": 2, "authorityRealm": "cloud", "method": "session/prompt", "request": rpc,
        "operationId": "op", "requestMessageId": "request", "requestHash": digest,
        "instanceId": "instance", "leaseId": "lease", "runtimeHandlerIdentity": "handler", "dispatchEpoch": "11",
        "cloudSubject": {"instanceId": "instance"}, "executionDeadlineAt": lease.lease_expires_at},
        "execution_grant": "transient-new-grant", "execution_grant_expires_at": (now + timedelta(seconds=25)).isoformat(),
        "public_request_hash": "a" * 64, "native_request_hash": digest,
        "lease": {"instance_id": "instance", "lease_id": "lease", "handler_identity": "handler", "runtime_epoch": "11"}}
    calls = []
    def send(method, url, headers, data):
        calls.append((method, url, headers, json.loads(data)))
        return 200, json.dumps(envelope).encode(), {}
    runtime = BeeOSAgentRuntime("https://gateway.test", "https://message.test", "instance", "agent", "current-token", transport=send)
    return RuntimeOriginalIntent(runtime), lease, locator, envelope, calls


def test_lease_only_read_retains_original_bytes_and_transient_outer_grant():
    client, lease, locator, envelope, calls = fixture()
    original = copy.deepcopy(envelope)
    assert client.read(lease, locator) == original
    assert calls[0][1] == "https://gateway.test/api/v1/runtime/execution/original-intent"
    assert calls[0][3] == locator
    assert calls[0][2]["Authorization"] == "Bearer current-token"
    assert "X-BeeOS-Execution-Grant" not in calls[0][2]
    assert envelope == original


@pytest.mark.parametrize("case", ["rpc", "lease", "locator", "expiry", "deadline"])
def test_changed_original_or_current_lease_rejects_without_replay(case):
    client, lease, locator, envelope, calls = fixture()
    if case == "rpc": envelope["request"]["request"]["params"]["opaque"] = "changed"
    if case == "lease": envelope["lease"]["runtime_epoch"] = "12"
    if case == "locator": envelope["request"]["operationId"] = "other"
    if case == "expiry": envelope["execution_grant_expires_at"] = "invalid"
    if case == "deadline": envelope["request"]["executionDeadlineAt"] = "invalid"
    with pytest.raises(ValueError): client.read(lease, locator)
    assert len(calls) == 1


def test_bad_current_lease_never_sends_and_owner_rejection_is_visible_once():
    client, lease, locator, _, calls = fixture()
    lease.lease_expires_at = "invalid"
    with pytest.raises(ValueError): client.read(lease, locator)
    assert calls == []
    client, lease, locator, _, calls = fixture()
    def reject(*args):
        calls.append(args)
        return 403, b'{"error":{"code":"original_revoked","message":"source unavailable"}}', {}
    client._runtime._transport = reject
    with pytest.raises(BeeOSAgentError) as error: client.read(lease, locator)
    assert error.value.code == "original_revoked"
    assert len(calls) == 1
