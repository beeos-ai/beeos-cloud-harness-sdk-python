"""Mint the Message Service Centrifugo connection token.

The client must not open its own Centrifugo subscription (the server returns
403). This package does not depend on a Centrifugo client; the caller connects
with the returned ``channels`` and reads connection publications.
"""
from __future__ import annotations

from dataclasses import dataclass

from beeos_cloud_harness_sdk._generated.operations import operation_path
from beeos_cloud_harness_sdk.lease_http import RuntimeLeaseCredential, RuntimeLeaseHttp
from beeos_cloud_harness_sdk.runtime_plane import HarnessProtocolError


@dataclass(frozen=True, slots=True)
class RuntimeRealtimeToken:
    token: str
    centrifugo_url: str
    channels: tuple[str, ...]
    principal_id: str
    expires_at: int


async def mint_runtime_realtime_token(
    http: RuntimeLeaseHttp, credential: RuntimeLeaseCredential,
) -> RuntimeRealtimeToken:
    response = await http.fetch(
        "POST", operation_path("runtimeRealtimeTokenCreate"), credential, json_body={}, retry=True,
    )
    text = response.text
    if response.status_code >= 400:
        raise HarnessProtocolError(f"realtime token failed ({response.status_code})", response.status_code, text)
    try:
        body = response.json()
    except ValueError as exc:
        raise HarnessProtocolError("realtime token response is incomplete") from exc
    if not isinstance(body, dict):
        raise HarnessProtocolError("realtime token response is incomplete")
    token = body.get("token") if isinstance(body.get("token"), str) else ""
    centrifugo_url = body.get("centrifugo_url") if isinstance(body.get("centrifugo_url"), str) else ""
    raw_channels = body.get("channels")
    channels = tuple(item for item in raw_channels if isinstance(item, str)) if isinstance(raw_channels, list) else ()
    if not token or not centrifugo_url or not channels:
        raise HarnessProtocolError("realtime token response is incomplete")
    principal = body.get("principal_id")
    expires = body.get("expires_at")
    return RuntimeRealtimeToken(
        token=token,
        centrifugo_url=centrifugo_url,
        channels=channels,
        principal_id=principal if isinstance(principal, str) else "",
        expires_at=expires if isinstance(expires, int) else 0,
    )
