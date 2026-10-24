"""RFC 8785 / I-JSON canonical JSON + domain-separated runtime hashes.

Parity with ``@beeos-ai/beeos-types`` ``canonicalizeJcs`` / ``runtimeHashPreimage``
and Go ``runtimeauth.RuntimeDomainHash``. Used for RegisterRuntime /
RuntimeHeartbeat identity proofs (``beeos.runtime.registration.v1`` /
``beeos.runtime.heartbeat.v1``).
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

REGISTRATION_HASH_DOMAIN = "beeos.runtime.registration.v1"
HEARTBEAT_HASH_DOMAIN = "beeos.runtime.heartbeat.v1"
NATIVE_SESSION_REQUEST_HASH_DOMAIN = "beeos.runtime.request.v1"
# Types4 RuntimeAgentProjectionHashPayload (@beeos-ai/beeos-types@4.1.0).
AGENT_PROJECTION_HASH_DOMAIN = "beeos.runtime.agent-projection.v1"


def canonicalize_jcs(value: Any) -> str:
    """RFC 8785-compatible canonical JSON for I-JSON values.

    Object keys are sorted lexicographically by UTF-16 code units (matches
    device-agent / beeos-types / Go appendJCS for BMP-only keys used on the
    registration wire).
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int) and not isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("JCS forbids non-finite numbers")
        # Match JSON.stringify / encoding/json for finite floats.
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_key)
        parts: list[str] = []
        for key in keys:
            if not isinstance(key, str):
                raise TypeError(f"JCS object keys must be strings, got {type(key)!r}")
            item = value[key]
            if item is None and key not in value:
                continue
            parts.append(f"{json.dumps(key, ensure_ascii=False)}:{canonicalize_jcs(item)}")
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"JCS cannot encode {type(value)!r}")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def runtime_domain_hash(domain: str, payload: Any) -> str:
    """SHA-256 hex of ``domain + LF + canonicalize_jcs(payload)``."""
    if not domain:
        raise ValueError("runtime hash domain is required")
    preimage = f"{domain}\n{canonicalize_jcs(payload)}"
    return sha256_hex(preimage)


def _utf16_key(key: str) -> list[int]:
    """Sort key as UTF-16 code units (RFC 8785 object key order)."""
    return list(key.encode("utf-16-be"))


def native_session_request_hash(rpc: dict[str, Any]) -> str:
    """Hash a native Session RPC in State's exact safe-integer JSON domain.

    This deliberately uses the existing JCS/hash implementation only after
    rejecting floats and unsafe integers. Python's float formatter is not an
    ECMAScript number formatter and must not sign an approximate native hash.
    """
    if not isinstance(rpc, dict) or rpc.get("jsonrpc") != "2.0" or rpc.get("method") != "session/prompt":
        raise ValueError("native Session RPC is required")
    _require_native_session_json(rpc)
    return runtime_domain_hash(NATIVE_SESSION_REQUEST_HASH_DOMAIN, rpc)


def verify_native_session_request(request: dict[str, Any]) -> str:
    """Verify the retained native carrier's hash; this is not grant verification."""
    if not isinstance(request, dict) or request.get("method") != "session/prompt":
        raise ValueError("native Session carrier is required")
    actual = native_session_request_hash(request.get("request"))
    if request.get("requestHash") != actual:
        raise ValueError("native request hash does not commit the original RPC")
    return actual


def _require_native_session_json(value: Any) -> None:
    if value is None or type(value) is bool:
        return
    if type(value) is int and abs(value) <= 9007199254740991:
        return
    if isinstance(value, str):
        value.encode("utf-8")
        return
    if isinstance(value, list):
        for item in value:
            _require_native_session_json(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            key.encode("utf-8")
            _require_native_session_json(item)
        return
    raise ValueError("native Session RPC requires exact JSON safe-integer units")
