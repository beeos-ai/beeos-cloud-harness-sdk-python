"""Lease-authenticated HTTP to the Cloud data plane (Message Service and the Gateway's
internal runtime routes). The runtime lease credential is the only authority; it is
attached here and nowhere else, always to a fixed origin.

Mirror of the TypeScript SDK ``RuntimeLeaseHttp`` (``src/runtime-lease-http.ts``).
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from beeos_cloud_harness_sdk._generated.operations import operation_path
from beeos_cloud_harness_sdk.retry import (
    TRANSIENT_BACKOFF,
    BackoffPolicy,
    is_transient_error,
    retry_with_backoff,
)

_LEASE_TRANSIENT: Final = frozenset({502, 503, 504})


_HISTORY_BOUNDARY_OPERATIONS: Final = {
    "prepare": "runtimeHistoryBoundaryPrepare",
    "resetting": "runtimeHistoryBoundaryResetting",
    "reset_done": "runtimeHistoryBoundaryResetDone",
    "commit": "runtimeHistoryBoundaryCommit",
    "abort": "runtimeHistoryBoundaryAbort",
    "reconcile": "runtimeHistoryBoundaryReconcile",
}


class CloudMessageRoutes:
    """Lease-authenticated Message Service routes; every path comes from the generated route table."""

    deliveries_read: Final = operation_path("runtimeDeliveriesRead")
    deliveries_renew: Final = operation_path("runtimeDeliveriesRenew")
    deliveries_ack: Final = operation_path("runtimeDeliveriesAck")
    conversations: Final = operation_path("runtimeConversationSync")

    @staticmethod
    def operation_history(operation_id: str) -> str:
        return operation_path("runtimeOperationHistoryGet", operationId=operation_id)

    @staticmethod
    def operation_messages(operation_id: str) -> str:
        return operation_path("runtimeOperationMessageAppend", operationId=operation_id)

    @staticmethod
    def history_boundary(conversation_id: str, action: str) -> str:
        return operation_path(_HISTORY_BOUNDARY_OPERATIONS[action], conversationId=conversation_id)

    @staticmethod
    def metadata_model(conversation_id: str) -> str:
        return operation_path("runtimeConversationMetadataModel", conversationId=conversation_id)

    @staticmethod
    def cron_delivery(conversation_id: str) -> str:
        return operation_path("runtimeConversationCronDelivery", conversationId=conversation_id)

    claim_next: Final = operation_path("runtimeClaimNext")

    @staticmethod
    def claim_exact(operation_id: str) -> str:
        return operation_path("runtimeClaimExact", operationId=operation_id)

    @staticmethod
    def claim_renew(operation_id: str) -> str:
        return operation_path("runtimeClaimRenew", operationId=operation_id)

    @staticmethod
    def claim_release(operation_id: str) -> str:
        return operation_path("runtimeClaimRelease", operationId=operation_id)


class CloudGatewayRuntimeRoutes:
    @staticmethod
    def output_files(operation_id: str, stage: str) -> str:
        if stage not in ("presign", "confirm"):
            raise ValueError("output-files stage must be presign or confirm")
        return operation_path(
            "runtimeOutputFilePresign" if stage == "presign" else "runtimeOutputFileConfirm", operationId=operation_id)

    @staticmethod
    def input_files_resolve(operation_id: str) -> str:
        return operation_path("runtimeInputFilesResolve", operationId=operation_id)


@dataclass(frozen=True, slots=True)
class RuntimeLeaseCredential:
    runtime_lease_credential: str
    #: Per-operation execution grant when the route requires one.
    execution_grant: str | None = None
    #: Message Service shared delivery key (``X-Runtime-Delivery-Key``).
    scoped_delivery_key: str | None = None


class RuntimeLeaseHttp:
    def __init__(
        self,
        origin: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
        retry: BackoffPolicy | None = None,
    ) -> None:
        parts = urlsplit(origin)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("runtime lease origin must be http(s) without credentials")
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self._client = client
        self._timeout = timeout
        self._retry = retry

    async def fetch(
        self,
        method: str,
        target: str,
        credential: RuntimeLeaseCredential,
        *,
        json_body: Any = None,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
        retry: bool | BackoffPolicy = False,
    ) -> httpx.Response:
        """``retry=True`` marks the call idempotent (reads, metadata projection). By default an
        uncertain append/ack is never replayed: the caller reconciles it."""
        url = f"{self.origin}{target}" if target.startswith("/") else target
        if urlsplit(url).netloc != urlsplit(self.origin).netloc:
            raise ValueError("runtime lease credential cannot be sent to another origin")
        hdrs = {**(headers or {}), "Authorization": f"Bearer {credential.runtime_lease_credential}"}
        if credential.execution_grant:
            hdrs["X-BeeOS-Execution-Grant"] = credential.execution_grant
        if credential.scoped_delivery_key:
            hdrs["X-Runtime-Delivery-Key"] = credential.scoped_delivery_key
        wait = timeout or self._timeout

        async def send(_n: int) -> httpx.Response:
            async def once(http: httpx.AsyncClient) -> httpx.Response:
                return await http.request(method.upper(), url, json=json_body, content=content,
                                          headers=hdrs, timeout=wait)

            if self._client is not None:
                response = await once(self._client)
            else:
                async with httpx.AsyncClient(follow_redirects=False) as http:
                    response = await once(http)
            if policy is not None and response.status_code in _LEASE_TRANSIENT:
                raise _TransientLeaseAnswer(response)
            return response

        policy = TRANSIENT_BACKOFF if retry is True else (retry or self._retry or None)
        if policy is None:
            return await send(1)
        try:
            return await retry_with_backoff(
                send, policy, is_retryable=lambda e: isinstance(e, _TransientLeaseAnswer) or is_transient_error(e))
        except _TransientLeaseAnswer as exhausted:
            return exhausted.response


class _TransientLeaseAnswer(Exception):
    def __init__(self, response: httpx.Response) -> None:
        super().__init__(f"transient HTTP {response.status_code}")
        self.response = response
