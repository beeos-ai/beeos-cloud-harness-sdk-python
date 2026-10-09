"""Terminal bridge ``agent_auth`` frame. Socket I/O is injected.

Mirror of ``src/terminal-bridge.ts``. This package does not depend on a
WebSocket library; ``connect`` without ``socket_factory`` raises ImportError.
"""
from __future__ import annotations

import base64
import json
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from beeos_cloud_harness_sdk.identity import AgentKeyPair, sign_agent_message

_EPOCH = re.compile(r"^[1-9][0-9]*$")


@dataclass(frozen=True, slots=True)
class TerminalAuthLease:
    instance_id: str
    lease_id: str
    runtime_epoch: str
    runtime_lease_credential: str
    handler_identity: str


def terminal_agent_websocket_url(bridge_url: str) -> str:
    base = bridge_url.rstrip("/")
    parts = urlsplit(f"{base}/agent")
    if parts.scheme not in ("ws", "wss"):
        raise ValueError("terminal bridge URL must be ws or wss")
    return f"{base}/agent"


def terminal_agent_auth_signing_message(
    *,
    public_key: str,
    timestamp: int,
    nonce: str,
    runtime_lease_credential: str,
    handler_identity: str,
    runtime_epoch: str,
    lease_id: str,
) -> str:
    """UTF-8 preimage. ``instance_id`` is not included."""
    return (
        f"terminal|{public_key}|{timestamp}|{nonce}|{runtime_lease_credential}|"
        f"{handler_identity}|{runtime_epoch}|{lease_id}"
    )


def create_terminal_agent_auth(
    *,
    lease: TerminalAuthLease,
    keys: AgentKeyPair,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    if not (
        lease.instance_id
        and lease.lease_id
        and lease.handler_identity
        and lease.runtime_lease_credential
        and _EPOCH.fullmatch(lease.runtime_epoch)
        and len(keys.public_key) == 32
    ):
        raise ValueError("invalid Terminal runtime lease authority binding")
    ts = int(time.time()) if timestamp is None else int(timestamp)
    n = nonce if nonce is not None else str(uuid.uuid4())
    public_key = base64.b64encode(keys.public_key).decode("ascii")
    preimage = terminal_agent_auth_signing_message(
        public_key=public_key,
        timestamp=ts,
        nonce=n,
        runtime_lease_credential=lease.runtime_lease_credential,
        handler_identity=lease.handler_identity,
        runtime_epoch=lease.runtime_epoch,
        lease_id=lease.lease_id,
    )
    return {
        "type": "agent_auth",
        "instance_id": lease.instance_id,
        "service": "terminal",
        "public_key": public_key,
        "timestamp": ts,
        "nonce": n,
        "signature": base64.b64encode(sign_agent_message(preimage, keys.private_key)).decode("ascii"),
        "runtimeLeaseCredential": lease.runtime_lease_credential,
        "handlerIdentity": lease.handler_identity,
        "runtimeEpoch": lease.runtime_epoch,
        "leaseId": lease.lease_id,
    }


class TerminalSocket(Protocol):
    def send(self, data: str) -> None: ...
    def close(self) -> None: ...
    async def wait_open(self) -> None: ...
    async def recv(self) -> str: ...


class TerminalBridgeClient:
    def __init__(
        self,
        *,
        bridge_url: str,
        keys: AgentKeyPair,
        lease: TerminalAuthLease,
        now: Callable[[], float] | None = None,
        nonce: Callable[[], str] | None = None,
        socket_factory: Callable[[str], TerminalSocket] | None = None,
    ) -> None:
        self._bridge_url = bridge_url
        self._keys = keys
        self._lease = lease
        self._now = now
        self._nonce = nonce
        self._socket_factory = socket_factory
        self._socket: TerminalSocket | None = None

    async def connect(self) -> dict[str, Any]:
        frame = create_terminal_agent_auth(
            lease=self._lease,
            keys=self._keys,
            timestamp=int(self._now()) if self._now else None,
            nonce=self._nonce() if self._nonce else None,
        )
        if self._socket_factory is None:
            raise ImportError(
                "terminal WebSocket requires an injected socket_factory; "
                "beeos-cloud-harness-sdk does not depend on websockets"
            )
        socket = self._socket_factory(terminal_agent_websocket_url(self._bridge_url))
        self._socket = socket
        await socket.wait_open()
        socket.send(json.dumps(frame, separators=(",", ":")))
        raw = await socket.recv()
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise RuntimeError("Terminal auth response was not JSON") from exc
        if not isinstance(parsed, dict) or parsed.get("type") != "auth_ok":
            kind = parsed.get("type") if isinstance(parsed, dict) else "unknown"
            raise RuntimeError(f"Terminal auth rejected ({kind})")
        return frame

    def send(self, data: str) -> None:
        if self._socket is None:
            raise RuntimeError("Terminal bridge is not connected")
        self._socket.send(data)

    def close(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None
