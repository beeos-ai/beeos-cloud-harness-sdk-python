"""Agent-auth v2 unit tests (parity with claw + parity fixture)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from beeos_cloud_harness_sdk.identity import (
    EMPTY_BODY_SHA256,
    agent_auth_headers,
    body_hash_hex,
    generate_agent_key_pair,
    load_agent_key_pair,
)


def test_empty_body_hash_matches_fixture() -> None:
    assert body_hash_hex(None) == EMPTY_BODY_SHA256
    assert body_hash_hex(b"") == EMPTY_BODY_SHA256
    assert body_hash_hex("") == EMPTY_BODY_SHA256


def test_preimage_uses_double_pipe_body_hash_slot(tmp_path: Path) -> None:
    keys = generate_agent_key_pair(tmp_path / "beeos-hermes-test-key.json")
    headers = agent_auth_headers("POST", "/api/v1/agents/sync", keys, '{"agents":[]}')
    assert set(headers) == {
        "X-Agent-Public-Key",
        "X-Agent-Signature",
        "X-Agent-Timestamp",
        "X-Agent-Nonce",
    }
    assert "X-Agent-Body-SHA256" not in headers
    # body hash of exact utf-8
    assert body_hash_hex('{"agents":[]}') == body_hash_hex(b'{"agents":[]}')
    assert len(base64.b64decode(headers["X-Agent-Signature"])) == 64

    # Fixture parity: METHOD|PATH||bodyHash|timestamp|nonce
    fixture = json.loads(
        (
            Path(__file__).resolve().parent / "fixtures" / "agent_auth_signing_shape.json"
        ).read_text(encoding="utf-8")
    )
    assert fixture["preimage"]["empty_body_sha256"] == EMPTY_BODY_SHA256
    assert fixture["preimage"]["template"] == "METHOD|PATH||bodyHash|timestamp|nonce"
    assert "X-Agent-Body-SHA256" in fixture["request_headers"]["absent"]


def test_load_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "bridge_key.json"
    generated = generate_agent_key_pair(path)
    loaded = load_agent_key_pair(path)
    assert loaded.public_key == generated.public_key
    assert loaded.private_key == generated.private_key
    data = json.loads(path.read_text())
    assert "publicKey" in data and "privateKey" in data
