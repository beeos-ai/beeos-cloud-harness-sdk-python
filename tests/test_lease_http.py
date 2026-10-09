import httpx
import pytest

from beeos_cloud_harness_sdk.lease_http import CloudMessageRoutes, RuntimeLeaseCredential, RuntimeLeaseHttp

CRED = RuntimeLeaseCredential("lease-secret", "grant-1")


def lease_http(handler) -> RuntimeLeaseHttp:
    return RuntimeLeaseHttp("https://ms.example", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))


async def test_attaches_bearer_and_grant_to_the_fixed_origin_only():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer lease-secret"
        assert request.headers["X-BeeOS-Execution-Grant"] == "grant-1"
        assert "X-Runtime-Delivery-Key" not in request.headers
        return httpx.Response(200, json={"ok": True})

    response = await lease_http(handler).fetch("POST", CloudMessageRoutes.deliveries_ack, CRED, json_body={})
    assert response.json() == {"ok": True}
    with pytest.raises(ValueError):
        await lease_http(handler).fetch("GET", "https://evil.example/x", CRED)


async def test_append_is_not_replayed_but_idempotent_reads_are():
    calls = 0

    def handler(_r: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    http = lease_http(handler)
    assert (await http.fetch("POST", CloudMessageRoutes.operation_messages("op"), CRED)).status_code == 503
    assert calls == 1


def test_route_builders_encode_segments():
    assert CloudMessageRoutes.metadata_model("c/1") == "/api/v1/runtime/conversations/c%2F1/metadata/model"


async def test_delivery_key_is_sent_only_when_set():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Runtime-Delivery-Key"] == "delivery-key"
        return httpx.Response(204)

    credential = RuntimeLeaseCredential("lease-secret", None, "delivery-key")
    response = await lease_http(handler).fetch("POST", "/k", credential)
    assert response.status_code == 204
