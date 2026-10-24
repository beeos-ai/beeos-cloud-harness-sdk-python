import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError

import pytest

from beeos_cloud_harness_sdk import BeeOSAgentError, BeeOSAgentRuntime
from beeos_cloud_harness_sdk.runtime_chat_store import ChatStoreOutcomeUnknown


def runtime(transport=None, origin="https://state.test"):
    return BeeOSAgentRuntime("https://gateway.test", origin, "i1", "a1", "lease-1", transport=transport)


def test_lossless_payload_current_lease_grant_and_original_receipt_key():
    calls = []
    def send(method, url, headers, data):
        calls.append((method, url, headers, json.loads(data)))
        body = json.loads(data)
        if url.endswith("/load"):
            return 200, b'{"events":[]}', {}
        return 200, json.dumps({"receipt": {"receipt_id": "receipt1", **{key: body[key] for key in
            ("session_id", "history_generation", "branch_id", "idempotency_key", "payload_sha256")}}, "replay": False}).encode(), {}
    client = runtime(send).chat_store.for_execution("grant-1")
    native = {"session_id": "s1", "history_generation": "0", "branch_id": "main", "idempotency_key": "original-key", "payload_sha256": "digest",
              "events": [{"type": "compaction", "opaque": {"toolCallId": "t1"}}]}
    client.load({"sessionId": "s1", "watermark": "8"})
    client.append(native)
    client.receipt(native)
    assert [c[1] for c in calls] == [f"https://state.test/api/v1/runtime/chat-store/{op}" for op in ("load", "append", "receipt")]
    assert calls[1][3] == native
    assert calls[1][2]["Authorization"] == "Bearer lease-1"
    assert calls[1][2]["X-BeeOS-Execution-Grant"] == "grant-1"


@pytest.mark.parametrize("failure", ["network", "503", "malformed", "wrong-shape"])
def test_ambiguous_append_is_never_replayed(failure):
    calls = []
    def send(*args):
        calls.append(args)
        if failure == "network":
            raise URLError("connection reset after write")
        return (503 if failure == "503" else 200), (b"{broken" if failure == "malformed" else b"[]"), {}
    body = {"idempotencyKey": "original-key", "payloadDigest": "digest"}
    with pytest.raises(ChatStoreOutcomeUnknown) as caught:
        runtime(send).chat_store.for_execution("grant-1").append(body)
    assert caught.value.request == body
    assert len(calls) == 1


def test_conflict_does_not_become_unknown_and_missing_authority_never_sends():
    calls = []
    def send(*args):
        calls.append(args)
        return 409, b'{"error":{"code":"writer_fenced","message":"stale writer"}}', {}
    r = runtime(send)
    with pytest.raises(BeeOSAgentError) as caught:
        r.chat_store.for_execution("grant-1").append({})
    assert caught.value.code == "writer_fenced"
    with pytest.raises(ValueError, match="execution grant"):
        r.chat_store.load({})
    assert len(calls) == 1


def test_runtime_auth_does_not_follow_redirect():
    received = []
    class Destination(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(dict(self.headers))
            self.send_response(200)
            self.end_headers()
        def log_message(self, *args):
            pass
    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)
    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{destination.server_port}/stolen")
            self.end_headers()
        def log_message(self, *args):
            pass
    redirect = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    servers = [destination, redirect]
    workers = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for worker in workers:
        worker.start()
    try:
        with pytest.raises(BeeOSAgentError) as caught:
            runtime(origin=f"http://127.0.0.1:{redirect.server_port}").chat_store.for_execution("grant-1").load({})
        assert caught.value.status == 302
        assert received == []
    finally:
        for server, worker in zip(servers, workers):
            server.shutdown()
            server.server_close()
            worker.join()
