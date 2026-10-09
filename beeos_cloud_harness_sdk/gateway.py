"""Agent Gateway client: the only place a Python harness learns Gateway routes, signs
requests, or decides what is worth retrying.

Mirror of the TypeScript SDK ``AgentGatewayClient`` (``src/gateway-client.ts``): same
resources, same routes, same retry policy.

Event-loop note: Hermes may run async tools on a disposable worker loop
(``model_tools._run_async``). A long-lived ``httpx.AsyncClient`` created on the serve
loop then fails with "bound to a different event loop", so when no client is injected
every request uses a request-scoped client. An injected client is assumed to share the
caller's loop.
"""
from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from typing import Any, Final
from urllib.parse import quote, unquote, urlencode, urlsplit

import httpx

from beeos_cloud_harness_sdk._generated.operations import operation_path
from beeos_cloud_harness_sdk.identity import AgentKeyPair, agent_auth_headers
from beeos_cloud_harness_sdk.retry import (
    TRANSIENT_BACKOFF,
    TRANSIENT_STATUSES,
    BackoffPolicy,
    CloudHttpError,
    is_transient_error,
    retry_with_backoff,
)

_UNSET: Final = object()
_JSON = {"Content-Type": "application/json"}


class _TransientAnswer(Exception):
    """Carries the last transient answer out of the retry loop so exhaustion still returns a Response."""

    def __init__(self, response: httpx.Response) -> None:
        super().__init__(f"transient HTTP {response.status_code}")
        self.response = response


def _compact(body: Any) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class AgentGatewayClient:
    def __init__(
        self,
        base_url: str,
        keys: AgentKeyPair,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
        retry: BackoffPolicy | None = TRANSIENT_BACKOFF,
        on_retry: Callable[[str, str, int, int, BaseException], None] | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValueError("Agent Gateway base URL must be http(s) without credentials")
        self.base_url = f"{parts.scheme}://{parts.netloc}"
        self.keys = keys
        self._client = client
        self._timeout = timeout
        self._retry = retry
        self._on_retry = on_retry
        self.files = GatewayFiles(self)
        self.canvas = GatewayCanvas(self)
        self.agents = GatewayAgents(self)
        self.channels = GatewayChannels(self)
        self.a2a = GatewayA2a(self)
        self.events = GatewayEvents(self)
        self.bridge = GatewayBridge(self)
        self.connectors = GatewayConnectors(self)
        self.automations = GatewayAutomations(self)
        self.runtime = GatewayRuntime(self)

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    @asynccontextmanager
    async def _http(self, timeout: float) -> AsyncIterator[httpx.AsyncClient]:
        if self._client is not None:
            yield self._client
            return
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as ephemeral:
            yield ephemeral

    def _signed(self, method: str, path: str, body: bytes | None, headers: Mapping[str, str] | None
                ) -> tuple[str, dict[str, str]]:
        if not path.startswith("/"):
            raise ValueError("Agent Gateway paths must start with '/'")
        path_only, _, query = path.partition("?")
        signed = agent_auth_headers(method, unquote(path_only), self.keys, body)
        merged = {**(headers or {}), **signed}
        if body is not None and "Content-Type" not in merged:
            merged["Content-Type"] = "application/json"
        return f"{self.base_url}{path_only}{'?' + query if query else ''}", merged

    async def fetch(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
        retry: BackoffPolicy | None | object = _UNSET,
        idempotent: bool = False,
        timeout: float | None = None,
    ) -> httpx.Response:
        """Signed request. Network errors and transient statuses are retried for GET (or ``idempotent``)."""
        method = method.upper()
        data = _compact(body)
        policy = self._retry if retry is _UNSET else retry
        may_retry = policy is not None and (method in ("GET", "HEAD") or idempotent or retry is not _UNSET)

        async def attempt(_n: int) -> httpx.Response:
            # Re-sign every attempt: timestamp/nonce must be fresh.
            url, hdrs = self._signed(method, path, data, headers)
            async with self._http(timeout or self._timeout) as http:
                response = await http.request(method, url, content=data, headers=hdrs,
                                              timeout=timeout or self._timeout)
            if may_retry and response.status_code in TRANSIENT_STATUSES:
                raise _TransientAnswer(response)
            return response

        try:
            if not may_retry:
                return await attempt(1)
            assert isinstance(policy, BackoffPolicy)
            return await retry_with_backoff(
                attempt, policy,
                is_retryable=lambda e: isinstance(e, _TransientAnswer) or is_transient_error(e),
                on_retry=lambda n, delay, err: self._on_retry(method, path.split("?")[0], n, delay, err)
                if self._on_retry else None,
            )
        except _TransientAnswer as exhausted:
            return exhausted.response

    async def json(self, method: str, path: str, body: Any = None, **kwargs: Any) -> Any:
        """Signed JSON call; raises :class:`CloudHttpError` for any non-2xx answer."""
        headers = {**_JSON, **(kwargs.pop("headers", None) or {})} if body is not None else kwargs.pop("headers", None)
        response = await self.fetch(method, path, body=body, headers=headers, **kwargs)
        text = response.text
        if response.status_code >= 400:
            raise CloudHttpError(method.upper(), path.split("?")[0], response.status_code, text)
        if not text:
            return None
        try:
            return response.json()
        except ValueError:
            return text

    async def bytes(self, method: str, path: str, body: Any = None, **kwargs: Any) -> bytes:
        """Signed call returning raw bytes (skill/template redeem)."""
        response = await self.fetch(method, path, body=body, **kwargs)
        if response.status_code >= 400:
            raise CloudHttpError(method.upper(), path.split("?")[0], response.status_code, response.text)
        return response.content

    def fetch_sync(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 60.0,
    ) -> httpx.Response:
        """Blocking signed request (no retry) for thread-based hosts such as loopback HTTP handlers."""
        url, hdrs = self._signed(method.upper(), path, body, headers)
        with httpx.Client(timeout=timeout, follow_redirects=False) as http:
            return http.request(method.upper(), url, content=body, headers=hdrs)


class GatewayRuntime:
    """Runtime registration routes; ``register_runtime``/``heartbeat_runtime`` satisfy ``RuntimeRegistrationTransport``."""

    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def register_runtime(self, body: Mapping[str, Any]) -> Any:
        return await self._gw.json("POST", operation_path("runtimeRegister"), dict(body), retry=None)

    async def heartbeat_runtime(self, registration_id: str, body: Mapping[str, Any]) -> Any:
        return await self._gw.json(
            "POST", operation_path("runtimeHeartbeat", registrationId=registration_id),
            dict(body), retry=None)

    async def redeem_resource(self, operation_id: str, kind: str, resource_ref: str, body: Mapping[str, Any],
                              timeout: float = 120.0) -> httpx.Response:
        """Redeem an operation resource (``skill``/``mcp``). The caller maps non-2xx and verifies digests."""
        if kind not in ("skill", "mcp"):
            raise ValueError("resource kind must be skill or mcp")
        return await self._gw.fetch(
            "POST",
            operation_path("runtimeResourceRedeem", operationId=operation_id, kind=kind, resourceRef=resource_ref),
            body=dict(body), headers=_JSON, retry=None, timeout=timeout)


class GatewayFiles:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def list(self) -> dict[str, Any]:
        return await self._gw.json("GET", operation_path("agentFilesList")) or {}

    async def presign(self, file_name: str, mime_type: str) -> dict[str, Any]:
        return await self._gw.json("POST", operation_path("agentFilePresign"),
                                   {"fileName": file_name, "mimeType": mime_type})

    async def confirm(self, file_id: str) -> dict[str, Any]:
        return await self._gw.json("POST", operation_path("agentFileConfirm"), {"fileId": file_id}) or {}

    async def resolve(self, file_id: str) -> dict[str, Any]:
        return await self._gw.json("GET", operation_path("agentFileResolve", fileId=file_id))

    async def upload(self, file_name: str, mime_type: str, data: bytes) -> dict[str, Any]:
        """presign -> PUT -> confirm. Returns ``fileId``/``uri``/``fileName``/``mimeType``/``size``."""
        presign = await self.presign(file_name, mime_type)
        file_id, upload_url = str(presign.get("fileId") or ""), str(presign.get("uploadUrl") or "")
        if not file_id or not upload_url:
            raise CloudHttpError("POST", operation_path("agentFilePresign"), 200, "presign missing fileId or uploadUrl")
        async with self._gw._http(self._gw._timeout) as http:
            put = await http.put(upload_url, content=data, headers={"Content-Type": mime_type})
        if put.status_code >= 400:
            raise CloudHttpError("PUT", "object-storage", put.status_code, "")
        confirmed = await self.confirm(file_id)
        resolved = str(confirmed.get("fileId") or file_id)
        return {
            "fileId": resolved,
            "uri": f"beeos-file://{resolved}",
            "fileName": str(confirmed.get("fileName") or file_name),
            "mimeType": str(confirmed.get("mimeType") or mime_type),
            "size": int(confirmed.get("size") or len(data)),
        }

    async def download(self, download_url: str) -> bytes:
        """Fetch a presigned URL from :meth:`resolve`. No Gateway signature is attached."""
        async with self._gw._http(self._gw._timeout) as http:
            response = await http.get(download_url)
        if response.status_code >= 400:
            raise CloudHttpError("GET", "object-storage", response.status_code, "")
        return response.content


class GatewayCanvas:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def token(self) -> dict[str, Any]:
        """``{token, relayUrl, expiresAt}``; unwraps the optional ``data`` envelope."""
        raw = await self._gw.json("POST", operation_path("canvasTokenCreate"), {}, retry=TRANSIENT_BACKOFF)
        body = raw.get("data") if isinstance(raw, dict) and isinstance(raw.get("data"), dict) else raw
        token = str(body.get("token") or "") if isinstance(body, dict) else ""
        if not token:
            raise CloudHttpError("POST", operation_path("canvasTokenCreate"), 200, "canvas token response missing token")
        return {
            "token": token,
            "relayUrl": str(body.get("relay_url") or body.get("relayUrl") or ""),
            "expiresAt": int(body.get("expires_at") or body.get("expiresAt") or 0),
        }

    def relay_headers(self, path: str = "/ws/agent") -> dict[str, str]:
        """Signed headers for the canvas relay WebSocket upgrade."""
        return agent_auth_headers("GET", path, self._gw.keys, None)


class GatewayAgents:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def sync(self, body: Mapping[str, Any] | str) -> Any:
        return await self._gw.json("POST", operation_path("agentSync"), body)

    async def report_template_origin(self, platform_agent_id: str, template_id: str) -> None:
        """Active template-origin report after ``agent.applyTemplate`` is durably projected."""
        await self._gw.json(
            "POST",
            operation_path("agentTemplateOriginReport", agentId=platform_agent_id),
            {"templateId": template_id},
        )


class GatewayChannels:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def create(self, participants: list[str], metadata: Mapping[str, str]) -> dict[str, Any]:
        return await self._gw.json("POST", operation_path("channelCreate"),
                                   {"participants": participants, "metadata": dict(metadata)}) or {}


class GatewayA2a:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def discover(self, query: str | None = None, limit: int = 50) -> Any:
        params: dict[str, str] = {"limit": str(limit)}
        if query:
            params["query"] = query
        return await self._gw.json("GET", f"{operation_path('a2aDiscover')}?{urlencode(params)}")

    async def rpc(self, agent_id: str, method: str, params: Mapping[str, Any],
                  request_id: str | None = None) -> dict[str, Any]:
        """JSON-RPC to a peer agent. Never raises on HTTP/RPC errors: the caller maps ``status``."""
        response = await self._gw.fetch(
            "POST", operation_path("a2aJsonRpc", agentId=agent_id), headers=_JSON,
            body={"jsonrpc": "2.0", "id": request_id or f"harness-{int(time.time() * 1000)}",
                  "method": method, "params": dict(params)})
        text = response.text
        try:
            rpc = json.loads(text)
        except ValueError:
            rpc = {}
        rpc = rpc if isinstance(rpc, dict) else {}
        return {"ok": response.is_success and not rpc.get("error"), "status": response.status_code,
                "body": text, "rpc": rpc}

    async def complete_task(self, task_id: str, result: str, error: str) -> None:
        await self._gw.json("POST", operation_path("a2aTaskComplete", taskId=task_id),
                            {"result": result, "error": error})


class GatewayEvents:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def publish(self, event_type: str, data: Any) -> None:
        await self._gw.json("POST", operation_path("agentEventPublish"), {"type": event_type, "data": data})


class GatewayBridge:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def config(self, region: str | None = None) -> dict[str, str] | None:
        """Bridge discovery; ``None`` when the Gateway is unreachable so the caller can use its cache."""
        try:
            data = await self._gw.json("GET", operation_path("bridgeConfigGet") + (f"?region={quote(region)}" if region else ""))
        except (CloudHttpError, httpx.HTTPError):
            return None
        return {"url": data["url"], **({"region": data["region"]} if data.get("region") else {})} \
            if isinstance(data, dict) and data.get("url") else None


class GatewayConnectors:
    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    async def mcp(self, body: bytes, headers: Mapping[str, str] | None = None) -> httpx.Response:
        return await self._gw.fetch("POST", operation_path("agentConnectorMcp"), body=body, headers=headers, retry=None)

    def mcp_sync(self, body: bytes, headers: Mapping[str, str] | None = None, timeout: float = 60.0) -> httpx.Response:
        return self._gw.fetch_sync("POST", operation_path("agentConnectorMcp"), body=body, headers=headers, timeout=timeout)

    async def call_json(self, rpc: Mapping[str, Any]) -> Any:
        """One JSON-RPC call (e.g. ``tools/call``) answered as JSON; raises on non-2xx."""
        return await self._gw.json("POST", operation_path("agentConnectorMcp"), dict(rpc), headers={"Accept": "application/json"}, retry=None)


class GatewayAutomations:
    """Automations CRUD/run routes. Responses are returned as the Gateway sent them; unwrap ``data`` in the host."""

    def __init__(self, gw: AgentGatewayClient) -> None:
        self._gw = gw

    @staticmethod
    def _query(values: Mapping[str, Any] | None) -> str:
        pairs = {k: str(v) for k, v in (values or {}).items() if v is not None and v != ""}
        return f"?{urlencode(pairs)}" if pairs else ""

    async def list(self, query: Mapping[str, Any] | None = None) -> Any:
        return await self._gw.json("GET", f"{operation_path('automationList')}{self._query(query)}")

    async def create(self, body: Mapping[str, Any]) -> Any:
        return await self._gw.json("POST", operation_path("automationCreate"), dict(body))

    async def create_webhook(self, body: Mapping[str, Any]) -> Any:
        return await self._gw.json("POST", operation_path("automationWebhookCreate"), dict(body))

    async def get(self, automation_id: str) -> Any:
        return await self._gw.json("GET", operation_path("automationGet", automationId=automation_id))

    async def run(self, automation_id: str, body: Mapping[str, Any], idempotency_key: str) -> Any:
        return await self._gw.json("POST", operation_path("automationRunCreate", automationId=automation_id), dict(body),
                                   headers={"Idempotency-Key": idempotency_key})

    async def runs(self, automation_id: str, query: Mapping[str, Any] | None = None) -> Any:
        return await self._gw.json("GET", f"{operation_path('automationRunsList', automationId=automation_id)}{self._query(query)}")

    async def run_detail(self, automation_id: str, run_id: str) -> Any:
        return await self._gw.json(
            "GET", operation_path("automationRunGet", automationId=automation_id, runId=run_id))


__all__ = [
    "AgentGatewayClient", "GatewayRuntime", "GatewayFiles", "GatewayCanvas", "GatewayAgents",
    "GatewayChannels", "GatewayA2a", "GatewayEvents", "GatewayBridge", "GatewayConnectors", "GatewayAutomations",
]
