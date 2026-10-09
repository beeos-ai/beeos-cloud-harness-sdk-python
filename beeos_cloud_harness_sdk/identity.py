"""Agent-auth v2 Ed25519 signing (mirror of the TS SDK ``agent-request-signing`` / ``agent-identity``).

Preimage:
  METHOD|PATH||bodyHash|timestamp|nonce

Headers (exactly four — no X-Agent-Body-SHA256):
  X-Agent-Public-Key, X-Agent-Signature, X-Agent-Timestamp, X-Agent-Nonce
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_private_key,
)

EMPTY_BODY_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

_ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


@dataclass(frozen=True, slots=True)
class AgentKeyPair:
    public_key: bytes
    private_key: bytes


def body_hash_hex(body: bytes | str | None = None) -> str:
    if body is None:
        data = b""
    elif isinstance(body, str):
        data = body.encode("utf-8")
    else:
        data = body
    return hashlib.sha256(data).hexdigest()


def load_agent_key_pair(file_path: str | Path, *, create_if_missing: bool = False) -> AgentKeyPair:
    path = Path(file_path)
    if not path.exists():
        if not create_if_missing:
            raise FileNotFoundError(f"agent key file not found: {path}")
        return generate_agent_key_pair(path)

    raw = path.read_text(encoding="utf-8").strip()
    try:
        data = json.loads(raw)
        if data.get("publicKey") and data.get("privateKey"):
            return AgentKeyPair(
                public_key=base64.b64decode(data["publicKey"]),
                private_key=base64.b64decode(data["privateKey"]),
            )
    except json.JSONDecodeError:
        pass

    private_key = base64.b64decode(raw)
    if len(private_key) != 32:
        raise ValueError(f"invalid key file format at {path}")
    pub = _derive_public(private_key)
    return AgentKeyPair(public_key=pub, private_key=private_key)


def generate_agent_key_pair(save_to: str | Path) -> AgentKeyPair:
    priv = Ed25519PrivateKey.generate()
    private_key = priv.private_bytes_raw()
    public_key = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    path = Path(save_to)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "publicKey": base64.b64encode(public_key).decode("ascii"),
                "privateKey": base64.b64encode(private_key).decode("ascii"),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    return AgentKeyPair(public_key=public_key, private_key=private_key)


def sign_agent_message(message: str, private_key: bytes) -> bytes:
    priv = _private_from_seed(private_key)
    return priv.sign(message.encode("utf-8"))


def agent_auth_headers(
    method: str,
    url_path: str,
    keys: AgentKeyPair,
    body: bytes | str | None = None,
) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = str(uuid.uuid4())
    body_hash = body_hash_hex(body)
    preimage = f"{method.upper()}|{url_path}||{body_hash}|{timestamp}|{nonce}"
    signature = sign_agent_message(preimage, keys.private_key)
    return {
        "X-Agent-Public-Key": base64.b64encode(keys.public_key).decode("ascii"),
        "X-Agent-Signature": base64.b64encode(signature).decode("ascii"),
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
    }


def signing_path_from_url(url: str) -> str:
    """Decoded path matching Go r.URL.Path (WHATWG pathname may be encoded)."""
    parsed = urlparse(url)
    if parsed.query:
        raise ValueError("agent authority routes forbid query parameters")
    return unquote(parsed.path)


def _private_from_seed(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) == 32:
        der = _ED25519_PKCS8_PREFIX + seed
        return load_der_private_key(der, password=None)  # type: ignore[return-value]
    return load_der_private_key(seed, password=None)  # type: ignore[return-value]


def _derive_public(private_seed: bytes) -> bytes:
    priv = _private_from_seed(private_seed)
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
