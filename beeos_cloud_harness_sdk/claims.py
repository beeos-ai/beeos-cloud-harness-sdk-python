"""Invocation claim lifecycle. Message Service does not register these routes yet.

Mirror of ``src/runtime-claim.ts``. Paths are the beeos-types contracts.
"""
from __future__ import annotations

from typing import Any

import httpx

from beeos_cloud_harness_sdk.lease_http import CloudMessageRoutes, RuntimeLeaseCredential, RuntimeLeaseHttp
from beeos_cloud_harness_sdk.runtime_plane import HarnessProtocolError

_NEXT = frozenset({"claimed", "empty", "fenced"})
_EXACT = frozenset({"claimed", "already_claimed", "fenced", "epoch_handoff_required", "terminal"})
_RENEW = frozenset({"renewed", "fenced", "expired", "terminal"})


async def _read_status(response: httpx.Response, what: str) -> dict[str, Any]:
    text = response.text
    if response.status_code >= 400:
        raise HarnessProtocolError(f"{what} failed ({response.status_code})", response.status_code, text)
    try:
        body = response.json()
    except ValueError as exc:
        raise HarnessProtocolError(f"{what} returned an invalid result") from exc
    if not isinstance(body, dict) or not isinstance(body.get("status"), str):
        raise HarnessProtocolError(f"{what} returned an invalid result")
    return body


class RuntimeClaimClient:
    def __init__(self, http: RuntimeLeaseHttp) -> None:
        self._http = http

    async def claim_next(self, credential: RuntimeLeaseCredential, body: dict[str, Any]) -> dict[str, Any]:
        result = await _read_status(
            await self._http.fetch("POST", CloudMessageRoutes.claim_next, credential, json_body=body),
            "claim next",
        )
        if result["status"] not in _NEXT:
            raise HarnessProtocolError("claim next returned an invalid status")
        return result

    async def claim_exact(self, credential: RuntimeLeaseCredential, body: dict[str, Any]) -> dict[str, Any]:
        result = await _read_status(
            await self._http.fetch(
                "POST", CloudMessageRoutes.claim_exact(str(body["operationId"])), credential, json_body=body,
            ),
            "claim exact",
        )
        if result["status"] not in _EXACT:
            raise HarnessProtocolError("claim exact returned an invalid status")
        return result

    async def renew_claim(self, credential: RuntimeLeaseCredential, body: dict[str, Any]) -> dict[str, Any]:
        result = await _read_status(
            await self._http.fetch(
                "POST", CloudMessageRoutes.claim_renew(str(body["operationId"])), credential, json_body=body,
            ),
            "claim renew",
        )
        if result["status"] not in _RENEW:
            raise HarnessProtocolError("claim renew returned an invalid status")
        return result

    async def release_claim(self, credential: RuntimeLeaseCredential, body: dict[str, Any]) -> None:
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.claim_release(str(body["operationId"])), credential, json_body=body,
        )
        if response.status_code != 204:
            raise HarnessProtocolError(
                f"claim release failed ({response.status_code})", response.status_code, response.text,
            )
