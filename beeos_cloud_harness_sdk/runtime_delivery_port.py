"""Runtime delivery port for a harness that does not hand-write Message Service HTTP.

``create_runtime_delivery_port`` matches the Hermes composition kwargs
(``service_origin``, ``authority``, ``http_client``). It is not a
``MessageClient`` personal-inbox session. The consume loop reads and renews;
the handler acknowledges.
"""
from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from beeos_cloud_harness_sdk.lease_http import CloudMessageRoutes, RuntimeLeaseCredential, RuntimeLeaseHttp
from beeos_cloud_harness_sdk.runtime_plane import HarnessProtocolError, RuntimeMessagePlane

_BOUNDARY_FIELDS = {
    "operation_id": "operationId",
    "request_message_id": "requestMessageId",
    "request_hash": "requestHash",
    "boundary_token": "boundaryToken",
    "effect_receipt": "effectReceipt",
    "run_convergence": "runConvergence",
    "active_run_registration_id": "activeRunRegistrationId",
}


@dataclass(frozen=True, slots=True)
class RuntimeMethodDelivery:
    delivery_id: str
    redelivered: bool
    idle_ms: int
    message: Any
    execution_grant: str | None = None


def _attr(obj: Any, *names: str) -> Any:
    if isinstance(obj, Mapping):
        for name in names:
            if name in obj and obj[name] not in (None, ""):
                return obj[name]
        return None
    for name in names:
        value = getattr(obj, name, None)
        if value not in (None, ""):
            return value
    return None


def _credential_from(lease: Any, scoped_delivery_key: str | None) -> RuntimeLeaseCredential:
    credential = _attr(lease, "runtime_lease_credential", "runtimeLeaseCredential")
    if not isinstance(credential, str) or not credential:
        raise HarnessProtocolError("runtime lease credential is missing")
    grant = _attr(lease, "execution_grant", "executionGrant")
    key = _attr(lease, "scoped_delivery_key", "scopedDeliveryKey") or scoped_delivery_key
    return RuntimeLeaseCredential(
        credential,
        grant if isinstance(grant, str) else None,
        key if isinstance(key, str) else None,
    )


def _boundary_body(credential: str, body: Mapping[str, Any] | None, fields: Mapping[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"schemaVersion": 1}
    if body is not None:
        payload.update(dict(body))
    for key, value in fields.items():
        mapped = _BOUNDARY_FIELDS.get(key)
        if mapped is None:
            raise HarnessProtocolError(f"unknown history boundary field {key}")
        payload[mapped] = value
    payload["runtimeLeaseCredential"] = credential
    return payload


class RuntimeDeliveryConsumer:
    def __init__(
        self,
        port: RuntimeDeliveryPort,
        *,
        on_delivery: Callable[..., Any],
        on_error: Callable[[BaseException], None] | None,
        max_count: int,
        block_ms: int,
        idle_delay_s: float,
        renew_interval_s: float,
    ) -> None:
        self._port = port
        self._on_delivery = on_delivery
        self._on_error = on_error
        self._max_count = max_count
        self._block_ms = block_ms
        self._idle_delay_s = idle_delay_s
        self._renew_interval_s = renew_interval_s
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._handlers: set[asyncio.Task[None]] = set()
        self._inflight: set[str] = set()

    def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def history_boundary(self, conversation_id: str, action: str, body: Mapping[str, Any] | None = None, **fields: Any) -> Any:
        return await self._port.history_boundary(conversation_id, action, body, **fields)

    async def acknowledge(self, delivery_ids: list[str]) -> Any:
        return await self._port.acknowledge(delivery_ids)

    async def history(self, operation_id: str) -> dict[str, Any]:
        return await self._port.history(operation_id)

    async def append(self, operation_id: str, type: str, payload: Any, execution_grant: str | None = None) -> Any:
        return await self._port.append(operation_id, type, payload, execution_grant)

    async def _run(self) -> None:
        renew = asyncio.create_task(self._renew_loop())
        try:
            while not self._stop.is_set():
                if self._port.current_lease() is None:
                    await self._idle()
                    continue
                try:
                    deliveries = await self._port.read(max_count=self._max_count, block_ms=self._block_ms)
                except Exception as exc:  # protocol and transport errors stay visible
                    self._fail(exc)
                    await self._idle()
                    continue
                started = 0
                for delivery in deliveries:
                    if delivery.delivery_id in self._inflight or self._stop.is_set():
                        continue
                    self._inflight.add(delivery.delivery_id)
                    task = asyncio.create_task(self._handle(delivery))
                    self._handlers.add(task)
                    task.add_done_callback(self._handlers.discard)
                    started += 1
                # An immediate empty or already-owned read must not spin. A blocking
                # read (block_ms > 0) already waited inside the server.
                if started == 0:
                    await self._idle()
        finally:
            renew.cancel()
            try:
                await renew
            except asyncio.CancelledError:
                pass
            if self._handlers:
                await asyncio.gather(*list(self._handlers), return_exceptions=True)

    async def _handle(self, delivery: RuntimeMethodDelivery) -> None:
        try:
            result = self._on_delivery(delivery, self)
            if inspect.isawaitable(result):
                await result
        except Exception as exc:
            self._fail(exc)
        finally:
            self._inflight.discard(delivery.delivery_id)

    async def _renew_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._renew_interval_s)
                return
            except asyncio.TimeoutError:
                pass
            ids = list(self._inflight)
            if not ids or self._port.current_lease() is None:
                continue
            try:
                renewed = await self._port.renew(ids)
            except Exception as exc:
                self._fail(exc)
                continue
            lost = set(renewed.get("notPending") or [])
            self._inflight.difference_update(lost)

    async def _idle(self) -> None:
        try:
            await asyncio.wait_for(self._stop.wait(), timeout=self._idle_delay_s)
        except asyncio.TimeoutError:
            pass

    def _fail(self, exc: BaseException) -> None:
        if self._on_error is not None:
            self._on_error(exc)


class RuntimeDeliveryPort:
    def __init__(
        self,
        *,
        service_origin: str | Callable[[], str | Awaitable[str]],
        authority: Any,
        http_client: httpx.AsyncClient | None = None,
        scoped_delivery_key: str | None = None,
    ) -> None:
        self._service_origin = service_origin
        self._authority = authority
        self._http_client = http_client
        self._scoped_delivery_key = scoped_delivery_key

    def current_lease(self) -> Any:
        method = getattr(self._authority, "current_lease", None)
        if method is None:
            method = getattr(self._authority, "currentLease", None)
        return method() if callable(method) else method

    def consume(
        self,
        *,
        on_delivery: Callable[..., Any],
        on_error: Callable[[BaseException], None] | None = None,
        max_count: int = 32,
        block_ms: int = 5000,
        idle_delay_s: float = 0.5,
        renew_interval_s: float = 20.0,
    ) -> RuntimeDeliveryConsumer:
        return RuntimeDeliveryConsumer(
            self,
            on_delivery=on_delivery,
            on_error=on_error,
            max_count=max_count,
            block_ms=block_ms,
            idle_delay_s=idle_delay_s,
            renew_interval_s=renew_interval_s,
        )

    async def read(self, *, max_count: int, block_ms: int) -> list[RuntimeMethodDelivery]:
        body = await (await self._plane()).read_deliveries(self._credential(), max_count=max_count, block_ms=block_ms)
        if not isinstance(body, dict) or body.get("status") != "deliveries" or not isinstance(body.get("deliveries"), list):
            raise HarnessProtocolError("Cloud Message Service returned invalid runtime deliveries")
        if len(body["deliveries"]) > max_count:
            raise HarnessProtocolError("Cloud Message Service returned invalid runtime deliveries")
        parsed = [_delivery(item) for item in body["deliveries"]]
        if len({item.delivery_id for item in parsed}) != len(parsed):
            raise HarnessProtocolError("Cloud Message Service returned duplicate runtime delivery ids")
        return parsed

    async def renew(self, delivery_ids: list[str]) -> dict[str, Any]:
        body = await (await self._plane()).renew_deliveries(self._credential(), delivery_ids)
        if (
            not isinstance(body, dict)
            or body.get("status") != "renewed"
            or not isinstance(body.get("renewed"), list)
            or not isinstance(body.get("notPending"), list)
        ):
            raise HarnessProtocolError("Cloud Message Service returned invalid runtime delivery renewal")
        return body

    async def acknowledge(self, delivery_ids: list[str]) -> Any:
        body = await (await self._plane()).ack_deliveries(self._credential(), delivery_ids)
        got = body.get("deliveryIds") if isinstance(body, dict) else None
        if (
            not isinstance(body, dict)
            or body.get("status") != "acknowledged"
            or not isinstance(got, list)
            or sorted(got) != sorted(delivery_ids)
        ):
            raise HarnessProtocolError("Cloud Message Service returned invalid runtime delivery acknowledgement")
        return body

    async def history(self, operation_id: str) -> dict[str, Any]:
        http = await self._http()
        response = await http.fetch("GET", CloudMessageRoutes.operation_history(operation_id), self._credential())
        if response.status_code == 404:
            return {"status": "not_found"}
        if response.status_code == 410:
            return {"status": "expired"}
        if response.status_code >= 400:
            raise HarnessProtocolError(
                f"operation history failed ({response.status_code})", response.status_code, response.text,
            )
        return {"status": "found", "snapshot": response.json()}

    async def append(self, operation_id: str, type: str, payload: Any, execution_grant: str | None = None) -> Any:
        credential = self._credential()
        if execution_grant:
            credential = RuntimeLeaseCredential(
                credential.runtime_lease_credential, execution_grant, credential.scoped_delivery_key,
            )
        return await (await self._plane()).append_operation_message(
            credential, operation_id, type=type, payload=payload,
        )

    async def history_boundary(
        self, conversation_id: str, action: str, body: Mapping[str, Any] | None = None, **fields: Any,
    ) -> Any:
        credential = self._credential()
        payload = _boundary_body(credential.runtime_lease_credential, body, fields)
        return await (await self._plane()).history_boundary(credential, conversation_id, action, payload)

    async def project_session_model(self, conversation_id: str, body: Any) -> Any:
        return await (await self._plane()).project_session_model(self._credential(), conversation_id, body)

    async def deliver_cron(self, conversation_id: str, body: Any) -> Any:
        return await (await self._plane()).deliver_cron(self._credential(), conversation_id, body)

    def _credential(self) -> RuntimeLeaseCredential:
        lease = self.current_lease()
        if lease is None:
            raise HarnessProtocolError("runtime delivery lease is unavailable")
        return _credential_from(lease, self._scoped_delivery_key)

    async def _origin(self) -> str:
        origin = self._service_origin() if callable(self._service_origin) else self._service_origin
        if inspect.isawaitable(origin):
            origin = await origin
        if not isinstance(origin, str) or not origin:
            raise HarnessProtocolError("runtime delivery service origin is missing")
        return origin

    async def _http(self) -> RuntimeLeaseHttp:
        return RuntimeLeaseHttp(await self._origin(), client=self._http_client)

    async def _plane(self) -> RuntimeMessagePlane:
        return RuntimeMessagePlane(await self._http())


def create_runtime_delivery_port(
    *,
    service_origin: str | Callable[[], str | Awaitable[str]],
    authority: Any,
    http_client: httpx.AsyncClient | None = None,
    scoped_delivery_key: str | None = None,
) -> RuntimeDeliveryPort:
    return RuntimeDeliveryPort(
        service_origin=service_origin,
        authority=authority,
        http_client=http_client,
        scoped_delivery_key=scoped_delivery_key,
    )


def _delivery(item: Any) -> RuntimeMethodDelivery:
    if not isinstance(item, dict) or not isinstance(item.get("deliveryId"), str):
        raise HarnessProtocolError("Cloud Message Service returned invalid runtime deliveries")
    message = item.get("message")
    grant = item.get("executionGrant")
    idle = item.get("idleMs")
    return RuntimeMethodDelivery(
        delivery_id=item["deliveryId"],
        redelivered=bool(item.get("redelivered")),
        idle_ms=idle if isinstance(idle, int) else 0,
        message=message,
        execution_grant=grant if isinstance(grant, str) else None,
    )
