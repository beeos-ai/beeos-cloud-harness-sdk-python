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
