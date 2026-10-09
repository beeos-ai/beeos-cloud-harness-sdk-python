import base64
import json

import httpx
import pytest

from beeos_cloud_harness_sdk.gateway import AgentGatewayClient
from beeos_cloud_harness_sdk.identity import AgentKeyPair, _derive_public
from beeos_cloud_harness_sdk.retry import CloudHttpError, TRANSIENT_BACKOFF, BackoffPolicy

SEED = bytes(range(32))
KEYS = AgentKeyPair(public_key=_derive_public(SEED), private_key=SEED)
FAST = BackoffPolicy(3, 1, 1, 1)


def gateway(handler, retry=FAST) -> AgentGatewayClient:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return AgentGatewayClient("https://gw.example", KEYS, client=client, retry=retry)


async def test_signs_every_request_with_the_four_agent_headers():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"token": "t"})

    assert (await gateway(handler).canvas.token()) == {"token": "t", "relayUrl": "", "expiresAt": 0}
    req = seen[0]
    assert req.url.path == "/api/v1/canvas/token"
    assert base64.b64decode(req.headers["X-Agent-Public-Key"]) == KEYS.public_key
    assert {"x-agent-signature", "x-agent-timestamp", "x-agent-nonce"} <= set(req.headers)
    assert "x-agent-body-sha256" not in req.headers


async def test_get_retries_transient_status_then_succeeds_with_fresh_signature():
    nonces: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonces.append(request.headers["X-Agent-Nonce"])
        return httpx.Response(503) if len(nonces) < 3 else httpx.Response(200, json={"files": []})

    assert await gateway(handler).files.list() == {"files": []}
    assert len(set(nonces)) == 3


async def test_post_is_not_replayed_by_default():
    calls = 0

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, text="busy")

    with pytest.raises(CloudHttpError) as info:
        await gateway(handler).files.presign("a.txt", "text/plain")
    assert calls == 1 and info.value.status == 503


async def test_canvas_token_opts_in_to_transient_retry_and_exhaustion_raises():
    calls = 0

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(502)

    with pytest.raises(CloudHttpError):
        await gateway(handler, retry=TRANSIENT_BACKOFF).canvas.token()
    assert calls == 3


async def test_a2a_rpc_reports_status_instead_of_raising():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.url.raw_path.decode() == "/api/v1/a2a/agent%201/jsonrpc"
        assert body["jsonrpc"] == "2.0" and body["method"] == "message/send"
        return httpx.Response(401, json={"error": {"code": "auth"}})

    result = await gateway(handler).a2a.rpc("agent 1", "message/send", {"x": 1})
    assert result["ok"] is False and result["status"] == 401


async def test_query_is_sent_but_only_the_path_is_signed():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["query"] == "a b" and request.url.params["limit"] == "5"
        return httpx.Response(200, json={"agents": []})

    await gateway(handler).a2a.discover("a b", 5)


async def test_upload_runs_presign_put_confirm():
    order: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        order.append(f"{request.method} {request.url.path}")
        if request.url.path.endswith("/presign"):
            return httpx.Response(200, json={"fileId": "f1", "uploadUrl": "https://gw.example/put/f1"})
        if request.method == "PUT":
            assert request.content == b"hello"
            return httpx.Response(200)
        return httpx.Response(200, json={"fileId": "f1", "fileName": "a.txt", "mimeType": "text/plain"})

    uploaded = await gateway(handler).files.upload("a.txt", "text/plain", b"hello")
    assert uploaded["uri"] == "beeos-file://f1" and uploaded["size"] == 5
    assert order == ["POST /api/v1/agent/files/presign", "PUT /put/f1", "POST /api/v1/agent/files/confirm"]


def test_rejects_credentialed_or_non_http_base_url():
    with pytest.raises(ValueError):
        AgentGatewayClient("https://u:p@gw.example", KEYS)
    with pytest.raises(ValueError):
        AgentGatewayClient("ftp://gw.example", KEYS)


async def test_runtime_routes_satisfy_the_registration_transport_and_409_is_classified():
    from beeos_cloud_harness_sdk.registration import (
        RuntimeRegistrationHandoffRequired,
        classify_registration_conflict,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/runtime/registrations"
        return httpx.Response(409, json={"error": {"message": "active runtime lease requires explicit handoff"}})

    with pytest.raises(CloudHttpError) as info:
        await gateway(handler).runtime.register_runtime({"registrationId": "r"})
    assert isinstance(classify_registration_conflict(str(info.value)), RuntimeRegistrationHandoffRequired)


async def test_automations_routes_query_and_idempotency_key():
    seen: list[tuple[str, str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.raw_path.decode(), request.headers.get("Idempotency-Key")))
        return httpx.Response(200, json={"data": []})

    gw = gateway(handler)
    await gw.automations.list({"limit": 1, "status": ""})
    await gw.automations.run("a/1", {"sourceRunId": "r"}, "key-1")
    await gw.automations.run_detail("a/1", "r 2")
    assert seen == [
        ("GET", "/api/v1/automations?limit=1", None),
        ("POST", "/api/v1/automations/a%2F1/runs", "key-1"),
        ("GET", "/api/v1/automations/a%2F1/runs/r%202", None),
    ]


async def test_report_template_origin_posts_the_template_id():
    seen: list[tuple[str, str, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.raw_path.decode(), request.content))
        return httpx.Response(200, json={})

    await gateway(handler).agents.report_template_origin("agent/1", "tpl-9")
    assert seen == [("POST", "/api/v1/agents/agent%2F1/template-origin", b'{"templateId":"tpl-9"}')]


async def test_connector_call_json_is_never_replayed():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["Accept"] == "application/json"
        return httpx.Response(503)

    with pytest.raises(CloudHttpError):
        await gateway(handler).connectors.call_json({"jsonrpc": "2.0", "method": "tools/call"})
    assert calls == 1


async def test_resource_redeem_returns_the_raw_response_and_encodes_segments():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.raw_path.decode() == "/api/v1/internal/runtime/operations/op%2F1/resources/skill/ref%201/redeem"
        return httpx.Response(200, content=b"\x00\x01")

    response = await gateway(handler).runtime.redeem_resource("op/1", "skill", "ref 1", {"a": 1})
    assert response.content == b"\x00\x01"
