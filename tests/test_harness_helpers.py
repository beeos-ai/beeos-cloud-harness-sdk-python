import base64
import json

import httpx
import pytest

from beeos_cloud_harness_sdk.canvas_relay import (
    CANVAS_RELAY_PATH,
    canvas_relay_upgrade_headers,
    canvas_relay_websocket_url,
    encode_canvas_relay_binary,
)
from beeos_cloud_harness_sdk.claims import RuntimeClaimClient
from beeos_cloud_harness_sdk.identity import generate_agent_key_pair
from beeos_cloud_harness_sdk.lease_http import (
    CloudGatewayRuntimeRoutes,
    CloudMessageRoutes,
    RuntimeLeaseCredential,
    RuntimeLeaseHttp,
)
from beeos_cloud_harness_sdk.realtime import mint_runtime_realtime_token
from beeos_cloud_harness_sdk.runtime_delivery_port import create_runtime_delivery_port
from beeos_cloud_harness_sdk.runtime_plane import HarnessProtocolError, RuntimeMessagePlane, put_presigned_upload
from beeos_cloud_harness_sdk.terminal import (
    TerminalAuthLease,
    TerminalBridgeClient,
    terminal_agent_auth_signing_message,
)

CRED = RuntimeLeaseCredential("lease-credential", None, "delivery-key")


def http_for(handler) -> RuntimeLeaseHttp:
    return RuntimeLeaseHttp("https://ms.example", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def test_plane_uses_generated_paths_and_requires_delivery_key():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={"status": "ok"})

    plane = RuntimeMessagePlane(http_for(handler))
    await plane.read_deliveries(CRED, max_count=1, block_ms=0)
    await plane.history_boundary(CRED, "c", "commit", {"schemaVersion": 1})
    assert seen[0] == CloudMessageRoutes.deliveries_read
    assert seen[1] == CloudMessageRoutes.history_boundary("c", "commit")
    bare = RuntimeLeaseCredential("lease-credential")
    with pytest.raises(HarnessProtocolError, match="X-Runtime-Delivery-Key"):
        await plane.project_session_model(bare, "c", {})
    with pytest.raises(HarnessProtocolError, match="X-Runtime-Delivery-Key"):
        await plane.deliver_cron(bare, "c", {})


async def test_presign_rejects_a_foreign_origin():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "Authorization" not in request.headers
        assert request.method == "PUT"
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    response = await put_presigned_upload(
        url="https://uploads.example/obj", allowed_origin="https://uploads.example", body=b"hi", client=client,
    )
    assert response.status_code == 200
    with pytest.raises(HarnessProtocolError):
        await put_presigned_upload(
            url="http://uploads.example/obj", allowed_origin="http://uploads.example", body=b"hi", client=client,
        )


async def test_claim_release_requires_204():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == CloudMessageRoutes.claim_release("op")
        return httpx.Response(204)

    await RuntimeClaimClient(http_for(handler)).release_claim(CRED, {"operationId": "op", "reason": "completed"})

    def bad(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "weird"})

    with pytest.raises(HarnessProtocolError, match="invalid status"):
        await RuntimeClaimClient(http_for(bad)).claim_next(CRED, {})


async def test_terminal_auth_frame_matches_the_go_preimage(tmp_path):
    keys = generate_agent_key_pair(tmp_path / "key.json")
    lease = TerminalAuthLease("inst", "lease-1", "7", "cred", "handler")
    sent = []

    class Socket:
        async def wait_open(self):
            return None

        def send(self, data: str):
            sent.append(data)

        async def recv(self):
            return '{"type":"auth_ok"}'

        def close(self):
            return None

    frame = await TerminalBridgeClient(
        bridge_url="wss://bridge.example",
        keys=keys,
        lease=lease,
        now=lambda: 1_700_000_000,
        nonce=lambda: "nonce-1",
        socket_factory=lambda _url: Socket(),
    ).connect()
    preimage = terminal_agent_auth_signing_message(
        public_key=base64.b64encode(keys.public_key).decode("ascii"),
        timestamp=1_700_000_000,
        nonce="nonce-1",
        runtime_lease_credential="cred",
        handler_identity="handler",
        runtime_epoch="7",
        lease_id="lease-1",
    )
    assert "inst" not in preimage
    assert frame["signature"]
    assert json.loads(sent[0])["service"] == "terminal"
    assert frame["type"] == "agent_auth"
    with pytest.raises(ImportError):
        await TerminalBridgeClient(bridge_url="wss://bridge.example", keys=keys, lease=lease).connect()


def test_canvas_url_keeps_the_relay_prefix(tmp_path):
    assert canvas_relay_websocket_url("https://relay.example/base", agent_id="a", token="t") == (
        "wss://relay.example/base/ws/agent?agentId=a&token=t"
    )
    keys = generate_agent_key_pair(tmp_path / "key.json")
    headers = canvas_relay_upgrade_headers(keys)
    assert set(headers) == {"X-Agent-Public-Key", "X-Agent-Signature", "X-Agent-Timestamp", "X-Agent-Nonce"}
    binary = encode_canvas_relay_binary("c1", b"\x09")
    assert binary[0] == 2 and binary[1:3] == b"c1" and binary[3] == 9
    assert CANVAS_RELAY_PATH == "/ws/agent"


async def test_realtime_token_requires_channels():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/runtime/realtime/token"
        assert json.loads(request.content) == {}
        return httpx.Response(200, json={
            "token": "jwt",
            "centrifugo_url": "wss://centrifugo.example/connection/websocket",
            "channels": ["personal:instance:inst"],
            "principal_id": "inst",
            "expires_at": 9,
        })

    token = await mint_runtime_realtime_token(http_for(handler), CRED)
    assert token.channels == ("personal:instance:inst",)


class _Lease:
    def __init__(self, credential: str):
        self.runtime_lease_credential = credential


class _Authority:
    def __init__(self, lease):
        self._lease = lease

    def current_lease(self):
        return self._lease


async def test_delivery_port_history_boundary_injects_the_lease_and_acks():
    seen = []
    reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal reads
        body = json.loads(request.content) if request.content else None
        seen.append((request.url.path, body))
        if request.url.path.endswith("/history-boundary/prepare"):
            assert body["runtimeLeaseCredential"] == "lease-credential"
            assert body["operationId"] == "op"
            assert body["schemaVersion"] == 1
            return httpx.Response(200, json={"status": "prepared", "boundaryToken": "tok"})
        if request.url.path.endswith("/deliveries/read"):
            reads += 1
            deliveries = [] if reads > 1 else [{
                "deliveryId": "d1", "redelivered": False, "idleMs": 0, "message": {"method": "session/clear"},
            }]
            return httpx.Response(200, json={"status": "deliveries", "deliveries": deliveries})
        if request.url.path.endswith("/deliveries/ack"):
            return httpx.Response(200, json={"status": "acknowledged", "deliveryIds": ["d1"]})
        return httpx.Response(500, json={"status": "no"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def origin():
        return "https://ms.example"

    port = create_runtime_delivery_port(
        service_origin=origin,
        authority=_Authority(_Lease("lease-credential")),
        http_client=client,
    )
    prepared = await port.history_boundary(
        "conv", "prepare", operation_id="op", request_message_id="m", request_hash="ab",
    )
    assert prepared["boundaryToken"] == "tok"
    acked = {}

    async def on_delivery(delivery, consumer):
        acked["id"] = delivery.delivery_id
        await consumer.acknowledge([delivery.delivery_id])

    consumer = port.consume(on_delivery=on_delivery, max_count=1, block_ms=0, idle_delay_s=0.01, renew_interval_s=60)
    consumer.start()
    import asyncio
    for _ in range(100):
        if "id" in acked:
            break
        await asyncio.sleep(0.01)
    else:
        raise AssertionError("delivery was not handled")
    await consumer.stop()
    assert acked["id"] == "d1"
    assert any(path.endswith("/deliveries/ack") for path, _body in seen)
    assert CloudGatewayRuntimeRoutes.input_files_resolve("op").endswith("/input-files/resolve")
