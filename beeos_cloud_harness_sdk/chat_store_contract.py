"""Wire types/codecs shared with the Honcho State producer (State16)."""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, TypedDict


class StateContext(TypedDict):
    tenant_ref: str
    scope_ref: str
    authorization_revision: int
    erasure_epoch: int
    request_id: str


class ChatWriter(TypedDict):
    writer_id: str
    writer_epoch: str


class NativeCodec(TypedDict):
    name: str
    version: str


class NativeChatEvent(TypedDict):
    event_id: str
    parent_id: str | None
    kind: str
    codec: NativeCodec
    content_b64: str
    sha256: str


class ChatIdentity(TypedDict):
    session_id: str
    history_generation: str
    branch_id: str


class ChatLoadRequest(ChatIdentity):
    context: StateContext
    watermark: str | None
    after: str
    limit: int


class ChatTerminal(TypedDict):
    response_id: str
    status: str
    event_id: str


class ChatAppendRequest(ChatIdentity):
    context: StateContext
    response_id: str
    attempt_id: str
    public_events: list[dict[str, Any]]
    writer: ChatWriter
    expected_watermark: str
    operation_id: str
    idempotency_key: str
    payload_sha256: str
    events: list[NativeChatEvent]
    terminal: ChatTerminal | None


class ChatReceiptRequest(ChatIdentity):
    context: StateContext
    idempotency_key: str
    payload_sha256: str


_DIGEST_FIELDS = ("session_id", "history_generation", "branch_id", "response_id", "attempt_id",
                  "public_events", "writer", "expected_watermark", "operation_id", "idempotency_key", "events", "terminal")


def chat_append_digest(request: dict[str, Any]) -> str:
    payload = {key: request[key] for key in _DIGEST_FIELDS}
    def check(value):
        if isinstance(value, float) or (type(value) is int and abs(value) > 9007199254740991):
            raise ValueError("chat envelope numbers must be JSON-safe integers")
        if isinstance(value, dict):
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(payload)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


def encode_native_chat_event(*, event_id: str, parent_id: str | None, kind: str,
                             codec: NativeCodec, content: bytes) -> NativeChatEvent:
    return {"event_id": event_id, "parent_id": parent_id, "kind": kind, "codec": codec,
            "content_b64": base64.b64encode(content).decode("ascii"), "sha256": hashlib.sha256(content).hexdigest()}


def decode_native_chat_event(event: NativeChatEvent) -> bytes:
    content = base64.b64decode(event["content_b64"], validate=True)
    if base64.b64encode(content).decode("ascii") != event["content_b64"] or hashlib.sha256(content).hexdigest() != event["sha256"]:
        raise ValueError("native event bytes do not match their digest")
    return content
