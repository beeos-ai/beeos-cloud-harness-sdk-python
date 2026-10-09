"""Canvas relay WebSocket URL, upgrade headers, and frames. Socket I/O is injected.

Mirror of ``src/canvas-relay.ts``. Yjs payload bytes stay with the harness.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from beeos_cloud_harness_sdk.identity import AgentKeyPair, agent_auth_headers

CANVAS_RELAY_PATH = "/ws/agent"


def canvas_relay_websocket_url(
    relay_url: str, *, agent_id: str | None = None, token: str | None = None,
) -> str:
    """``{relay}/ws/agent``. An existing path prefix is kept. Never ``/ws/{canvasId}``."""
    base = relay_url.strip().rstrip("/")
    if not base:
        raise ValueError("empty canvas relay url")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    elif not (base.startswith("ws://") or base.startswith("wss://")):
        base = "wss://" + base
    if not base.endswith(CANVAS_RELAY_PATH):
        base = base + CANVAS_RELAY_PATH
    parts = urlsplit(base)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if agent_id:
        query["agentId"] = agent_id
    if token:
        query["token"] = token
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def canvas_relay_upgrade_headers(keys: AgentKeyPair) -> dict[str, str]:
    return agent_auth_headers("GET", CANVAS_RELAY_PATH, keys)


def canvas_relay_join_frame(canvas_id: str) -> str:
    return json.dumps({"type": "join", "canvasId": canvas_id}, separators=(",", ":"))


def canvas_relay_leave_frame(canvas_id: str) -> str:
    return json.dumps({"type": "leave", "canvasId": canvas_id}, separators=(",", ":"))


def encode_canvas_relay_binary(canvas_id: str, payload: bytes) -> bytes:
    encoded = canvas_id.encode("utf-8")
    if not encoded or len(encoded) > 255:
        raise ValueError("canvas id length must be 1..255 bytes")
    return bytes((len(encoded),)) + encoded + payload


class CanvasRelaySocket(Protocol):
    def send(self, data: str | bytes) -> None: ...
    def close(self) -> None: ...
    async def wait_open(self) -> None: ...


class CanvasRelayClient:
    def __init__(
        self,
        *,
        relay_url: str,
        keys: AgentKeyPair,
        agent_id: str | None = None,
        token: str | None = None,
        socket_factory: Callable[[str, dict[str, str]], CanvasRelaySocket] | None = None,
    ) -> None:
        self._relay_url = relay_url
        self._keys = keys
        self._agent_id = agent_id
        self._token = token
        self._socket_factory = socket_factory
        self._socket: CanvasRelaySocket | None = None

    async def connect(self) -> None:
        headers = canvas_relay_upgrade_headers(self._keys)
        url = canvas_relay_websocket_url(self._relay_url, agent_id=self._agent_id, token=self._token)
        if self._socket_factory is None:
            raise ImportError(
                "canvas relay WebSocket requires an injected socket_factory; "
                "beeos-cloud-harness-sdk does not depend on websockets"
            )
        socket = self._socket_factory(url, headers)
        self._socket = socket
        await socket.wait_open()

    def join(self, canvas_id: str) -> None:
        self._send(canvas_relay_join_frame(canvas_id))

    def leave(self, canvas_id: str) -> None:
        self._send(canvas_relay_leave_frame(canvas_id))

    def send_binary(self, canvas_id: str, payload: bytes) -> None:
        self._send(encode_canvas_relay_binary(canvas_id, payload))

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def _send(self, data: str | bytes) -> None:
        if self._socket is None:
            raise RuntimeError("canvas relay is not connected")
        self._socket.send(data)
