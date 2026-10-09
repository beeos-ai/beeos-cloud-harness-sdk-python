"""Lease-authenticated Message Service plane and internal operation files.

Mirror of ``src/runtime-message-plane.ts``. Paths come only from the generated
route table. Import this submodule; the package root stays stdlib-only.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

from beeos_cloud_harness_sdk.lease_http import (
    CloudGatewayRuntimeRoutes,
    CloudMessageRoutes,
    RuntimeLeaseCredential,
    RuntimeLeaseHttp,
)


class HarnessProtocolError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def _require_delivery_key(credential: RuntimeLeaseCredential, route: str) -> None:
    if not credential.scoped_delivery_key:
        raise HarnessProtocolError(f"{route} requires X-Runtime-Delivery-Key")


async def _expect_json(response: httpx.Response, what: str) -> Any:
    text = response.text
    if response.status_code >= 400:
        raise HarnessProtocolError(f"{what} failed ({response.status_code})", response.status_code, text)
    if not text:
        return None
    try:
        return response.json()
    except ValueError:
        return text


class RuntimeMessagePlane:
    """Read, renew, ack, history, and conversation-authority calls on one Message Service origin."""

    def __init__(self, http: RuntimeLeaseHttp) -> None:
        self._http = http

    async def read_deliveries(
        self, credential: RuntimeLeaseCredential, *, max_count: int, block_ms: int,
    ) -> Any:
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.deliveries_read, credential,
            json_body={"schemaVersion": 1, "maxCount": max_count, "blockMs": block_ms},
        )
        return await _expect_json(response, "runtime delivery read")

    async def renew_deliveries(self, credential: RuntimeLeaseCredential, delivery_ids: list[str]) -> Any:
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.deliveries_renew, credential,
            json_body={"schemaVersion": 1, "deliveryIds": list(delivery_ids)},
        )
        return await _expect_json(response, "runtime delivery renew")

    async def ack_deliveries(self, credential: RuntimeLeaseCredential, delivery_ids: list[str]) -> Any:
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.deliveries_ack, credential,
            json_body={"schemaVersion": 1, "deliveryIds": list(delivery_ids)},
        )
        return await _expect_json(response, "runtime delivery ack")

    async def operation_history(self, credential: RuntimeLeaseCredential, operation_id: str) -> Any:
        response = await self._http.fetch(
            "GET", CloudMessageRoutes.operation_history(operation_id), credential,
        )
        return await _expect_json(response, "operation history")

    async def append_operation_message(
        self, credential: RuntimeLeaseCredential, operation_id: str, *, type: str, payload: Any,
    ) -> Any:
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.operation_messages(operation_id), credential,
            json_body={"schemaVersion": 1, "type": type, "payload": payload},
        )
        return await _expect_json(response, "operation message append")

    async def history_boundary(
        self, credential: RuntimeLeaseCredential, conversation_id: str, action: str, body: Any,
    ) -> Any:
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.history_boundary(conversation_id, action), credential,
            json_body=body, retry=True,
        )
        return await _expect_json(response, "history boundary")

    async def project_session_model(
        self, credential: RuntimeLeaseCredential, conversation_id: str, body: Any,
    ) -> Any:
        _require_delivery_key(credential, "session model")
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.metadata_model(conversation_id), credential,
            json_body=body, retry=True,
        )
        return await _expect_json(response, "session model")

    async def deliver_cron(
        self, credential: RuntimeLeaseCredential, conversation_id: str, body: Any,
    ) -> Any:
        _require_delivery_key(credential, "cron delivery")
        response = await self._http.fetch(
            "POST", CloudMessageRoutes.cron_delivery(conversation_id), credential,
            json_body=body, retry=True,
        )
        return await _expect_json(response, "cron delivery")


class RuntimeOperationFiles:
    """Input resolve and output presign/confirm. The origin is the Agent Gateway."""

    def __init__(self, http: RuntimeLeaseHttp) -> None:
        self._http = http

    async def resolve_input(self, credential: RuntimeLeaseCredential, operation_id: str, body: Any) -> Any:
        response = await self._http.fetch(
            "POST", CloudGatewayRuntimeRoutes.input_files_resolve(operation_id), credential,
            json_body=body, retry=True,
        )
        return await _expect_json(response, "input file resolve")

    async def presign_output(self, credential: RuntimeLeaseCredential, operation_id: str, body: Any) -> Any:
        response = await self._http.fetch(
            "POST", CloudGatewayRuntimeRoutes.output_files(operation_id, "presign"), credential,
            json_body=body, retry=True,
        )
        return await _expect_json(response, "output file presign")

    async def confirm_output(self, credential: RuntimeLeaseCredential, operation_id: str, body: Any) -> Any:
        response = await self._http.fetch(
            "POST", CloudGatewayRuntimeRoutes.output_files(operation_id, "confirm"), credential,
            json_body=body, retry=True,
        )
        return await _expect_json(response, "output file confirm")


async def put_presigned_upload(
    *,
    url: str,
    allowed_origin: str,
    body: bytes,
    method: str = "PUT",
    required_headers: Mapping[str, str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> httpx.Response:
    """PUT bytes to a presigned upload URL. The lease is not attached."""
    target = urlsplit(url)
    allowed = urlsplit(allowed_origin)
    if (
        target.scheme != "https"
        or target.username
        or target.password
        or f"{target.scheme}://{target.netloc}" != f"{allowed.scheme}://{allowed.netloc}"
    ):
        raise HarnessProtocolError("presigned upload origin is not the allowed https origin")
    headers = dict(required_headers or {})

    async def send(http: httpx.AsyncClient) -> httpx.Response:
        return await http.request(method, url, content=body, headers=headers)

    if client is not None:
        return await send(client)
    async with httpx.AsyncClient(follow_redirects=False) as http:
        return await send(http)
