"""Signature interoperability with the Cloud literal runtime-proof protocol.

Independently reconstructs the Cloud signed message
(`beeos-cloud-runtime-identity-v1`, LF-tuple, target before signedAt) and verifies
the producer signature with the public key. The canonical payload hash must
exclude targetInstanceId.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from beeos_cloud_harness_sdk.identity import generate_agent_key_pair
from beeos_cloud_harness_sdk.jcs import (
    HEARTBEAT_HASH_DOMAIN,
    REGISTRATION_HASH_DOMAIN,
    runtime_domain_hash,
)
from beeos_cloud_harness_sdk.registration import (
    RuntimeRegistrationCoordinator,
    RuntimeRegistrationIdentity,
)


def _coordinator(tmp_path: Path, target: str = "inst_123"):
    keys = generate_agent_key_pair(tmp_path / "k.json")
    identity = RuntimeRegistrationIdentity(
        registration_id="reg-1",
        handler_identity="pod-1",
        journal_store_id="journal-1",
        journal_generation="1",
    )
    fixed_now = datetime(2026, 7, 14, 0, 0, 0, tzinfo=timezone.utc)
    return RuntimeRegistrationCoordinator(
        transport=AsyncMock(), keys=keys, identity=identity,
        target_instance_id=target, runtime_methods=("session/clear",), capabilities=("canvas",),
        now=lambda: fixed_now,
    ), keys


def _message(purpose: str, key_id: str, target: str, signed_at: str, nonce: str, payload_hash: str) -> bytes:
    return "\n".join(
        ["beeos-cloud-runtime-identity-v1", purpose, key_id, target, signed_at, nonce, payload_hash]
    ).encode("utf-8")


def _verify(public_key: bytes, signature: str, message: bytes) -> None:
    raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    Ed25519PublicKey.from_public_bytes(public_key).verify(raw, message)


def test_register_signature_matches_cloud_literal_and_excludes_target(tmp_path: Path) -> None:
    coord, keys = _coordinator(tmp_path)
    payload = coord._registration_payload()
    assert "targetInstanceId" not in payload
    body = coord._sign_proof("runtime.register", payload)
    assert body["payloadHash"] == runtime_domain_hash(REGISTRATION_HASH_DOMAIN, payload)
    message = _message("runtime.register", body["instanceIdentityKeyId"], "inst_123",
                       body["signedAt"], body["nonce"], body["payloadHash"])
    _verify(keys.public_key, body["signature"], message)


def test_heartbeat_signature_matches_cloud_literal(tmp_path: Path) -> None:
    coord, keys = _coordinator(tmp_path)
    payload = {"leaseId": "lease-1", "handlerIdentity": "pod-1", "runtimeEpoch": "7"}
    assert "targetInstanceId" not in payload
    body = coord._sign_proof("runtime.heartbeat", payload)
    assert body["payloadHash"] == runtime_domain_hash(HEARTBEAT_HASH_DOMAIN, payload)
    message = _message("runtime.heartbeat", body["instanceIdentityKeyId"], "inst_123",
                       body["signedAt"], body["nonce"], body["payloadHash"])
    _verify(keys.public_key, body["signature"], message)


def test_tampered_target_fails_verification(tmp_path: Path) -> None:
    coord, keys = _coordinator(tmp_path)
    body = coord._sign_proof("runtime.register", coord._registration_payload())
    tampered = _message("runtime.register", body["instanceIdentityKeyId"], "inst_evil",
                        body["signedAt"], body["nonce"], body["payloadHash"])
    with pytest.raises(InvalidSignature):
        _verify(keys.public_key, body["signature"], tampered)
