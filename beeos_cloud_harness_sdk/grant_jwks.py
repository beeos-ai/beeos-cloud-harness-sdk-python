"""Purpose-bound Cloud RS256 verification, matching the maintained Node SDK.

The key URL is Agent Gateway's existing fixed JWKS route. Verification performs
no network requests, persistence, retries, Session reads or native effects.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import time
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .jcs import _require_native_session_json, canonicalize_jcs, runtime_domain_hash, verify_native_session_request

CLOUD_GRANT_JWKS_PATH = "/.well-known/runtime-execution-grant-jwks.json"
CLOUD_GRANT_DOMAIN = {"issuer": "beeos-cloud-gateway", "audience": "beeos-cloud-runtime-command",
                      "purpose": "cloud-runtime-execution-grant", "maxClaimTtlSeconds": 60}
# Go already accepts this skew; guests must not be stricter than the signer.
CLOUD_GRANT_CLOCK_SKEW_SECONDS = 30
_B64 = re.compile(r"[A-Za-z0-9_-]+")
_DIGEST = re.compile(r"[a-f0-9]{64}")


def _decode(value: str) -> bytes:
    if not isinstance(value, str) or not _B64.fullmatch(value):
        raise ValueError("noncanonical base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("noncanonical base64url")
    return decoded


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _safe_integer(value: Any) -> bool:
    return type(value) is int and abs(value) <= 9007199254740991


def _decimal(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value.isascii() and value.isdecimal() and (value == "0" or value[0] != "0")


def _same(left: Any, right: Any) -> bool:
    _require_native_session_json(left)
    _require_native_session_json(right)
    return canonicalize_jcs(left) == canonicalize_jcs(right)


def _lease_identity(lease: Any) -> tuple[str, ...]:
    return tuple(getattr(lease, name, "") for name in ("instance_id", "lease_id", "handler_identity", "runtime_epoch"))


@dataclass(frozen=True)
class VerifiedCentralNativeIntent:
    binding: dict[str, Any]
    params: dict[str, Any]
    claims: dict[str, Any]
    compact_hash: str
    assert_current: Callable[[], None]


class CloudGatewayGrantJwksVerifier:
    def __init__(self, agent_gateway_url: str, *, client: httpx.Client | None = None,
                 ttl_seconds: float = 300, now: Callable[[], float] = time.time):
        origin = urlsplit(agent_gateway_url)
        if (origin.scheme not in {"http", "https"} or not origin.hostname or origin.username or origin.password
                or origin.query or origin.fragment or origin.path not in {"", "/"}
                or not 0 < ttl_seconds <= 300):
            raise ValueError("configured Agent Gateway origin and bounded JWKS cache are required")
        self.keyset_url = str(httpx.URL(agent_gateway_url)).rstrip("/") + CLOUD_GRANT_JWKS_PATH
        self._client, self._ttl, self._now = client, ttl_seconds, now
        self._keys: dict[str, rsa.RSAPublicKey] = {}
        self._expires_at = 0.0
        self.provenance: dict[str, Any] | None = None

    def refresh(self, force: bool = False) -> None:
        if not force and self._keys and self._now() < self._expires_at:
            return
        # A failed explicit refresh must not leave a usable stale trust set.
        self._keys, self._expires_at, self.provenance = {}, 0, None
        if self._client is None:
            with httpx.Client(timeout=10, follow_redirects=False) as client:
                response = client.get(self.keyset_url)
        else:
            response = self._client.get(self.keyset_url, follow_redirects=False, timeout=10)
        response.raise_for_status()
        body = response.json()
        if (str(response.url) != self.keyset_url or not response.headers.get("etag") or not isinstance(body, dict)
                or any(body.get(key) != value for key, value in CLOUD_GRANT_DOMAIN.items())
                or type(body.get("maxClaimTtlSeconds")) is not int or not isinstance(body.get("keys"), list)):
            raise ValueError("Cloud grant JWKS response provenance mismatch")
        keys = {}
        for key in body["keys"]:
            if (not isinstance(key, dict) or key.get("kty") != "RSA" or key.get("alg") != "RS256"
                    or key.get("use") != "sig" or not _text(key.get("kid"))):
                continue
            if key["kid"] in keys:
                raise ValueError("Cloud grant JWKS contains a duplicate kid")
            public = rsa.RSAPublicNumbers(int.from_bytes(_decode(key["e"]), "big"),
                                          int.from_bytes(_decode(key["n"]), "big")).public_key()
            if public.key_size >= 2048:
                keys[key["kid"]] = public
        if not keys:
            raise ValueError("Cloud grant JWKS contains no trusted RS256 keys")
        self._keys, self._expires_at = keys, self._now() + self._ttl
        self.provenance = {"sourceUrl": self.keyset_url, "etag": response.headers["etag"], **CLOUD_GRANT_DOMAIN}

    def verify_and_decode_grant(self, compact_jwt: str) -> dict[str, Any] | None:
        if not isinstance(compact_jwt, str) or not self._keys or self._now() >= self._expires_at:
            return None
        try:
            parts = compact_jwt.split(".")
            if len(parts) != 3:
                return None
            header = json.loads(_decode(parts[0]).decode("utf-8"))
            claims = json.loads(_decode(parts[1]).decode("utf-8"))
            signature = _decode(parts[2])
            if (not isinstance(header, dict) or header.get("alg") != "RS256" or header.get("typ") != "JWT"
                    or not isinstance(header.get("kid"), str) or header["kid"] not in self._keys
                    or not isinstance(claims, dict)):
                return None
            self._keys[header["kid"]].verify(signature, (parts[0] + "." + parts[1]).encode("ascii"),
                                              padding.PKCS1v15(), hashes.SHA256())
            if any(claims.get(field) != CLOUD_GRANT_DOMAIN[name] for field, name in
                   (("iss", "issuer"), ("aud", "audience"), ("purpose", "purpose"))):
                return None
            return {"header": header, "claims": claims, "compactHash": hashlib.sha256(compact_jwt.encode()).hexdigest()}
        except (ValueError, TypeError, KeyError, UnicodeError, InvalidSignature):
            return None

    def verify_original(self, request: dict[str, Any], execution_grant: str, lease: Any,
                        get_lease: Callable[[], Any | None]) -> VerifiedCentralNativeIntent:
        """Pure parity with Node verifyCentralNativeIntent, including renewal.

        request.executionGrantHash is the historical first compact digest. A
        fresh JWT binds the same full original claims; its compact hash need
        not equal that historical value.
        """
        decoded = self.verify_and_decode_grant(execution_grant)
        if not isinstance(request, dict) or decoded is None:
            raise ValueError("central native original signed intent is invalid")
        r, g = request, decoded["claims"]
        rpc = _object(r.get("request")); p = _object(rpc.get("params")); c = _object(p.get("centralChat"))
        command = _object(r.get("command")); target = _object(command.get("context"))
        conversation = _object(target.get("conversation")); context = _object(c.get("context")); writer = _object(c.get("writer"))
        pin, persona = _object(c.get("config_pin")), c.get("persona_ref")
        credential_ref = pin.get("credential_set_ref")
        instance, lease_id, handler, epoch = identity = _lease_identity(lease)
        def current():
            active = get_lease()
            try:
                expiry = datetime.fromisoformat(active.lease_expires_at.replace("Z", "+00:00"))
                valid = expiry.tzinfo is not None and expiry.timestamp() > self._now()
            except (AttributeError, TypeError, ValueError):
                valid = False
            if not active or not all(identity) or _lease_identity(active) != identity or not valid:
                raise ValueError("central native execution is fenced")
        now = int(self._now())
        fields = ("operationId", "requestMessageId", "instanceId", "leaseId", "dispatchEpoch", "requestHash", "paramsHash", "commandHash", "idempotencyKeyHash")
        invalid = (r.get("schemaVersion") != 2 or r.get("method") != "session/prompt" or "centralChat" not in p
            or not _text(p.get("runtimeRunId")) or p.get("taskId") != r.get("operationId")
            or p.get("taskRequestMessageId") != r.get("requestMessageId")
            or not isinstance(r.get("executionGrantHash"), str) or not _DIGEST.fullmatch(r["executionGrantHash"])
            or r.get("authorityRealm") != "cloud" or _object(r.get("cloudSubject")).get("instanceId") != instance
            or not _same(r.get("cloudSubject"), g.get("cloudSubject")) or r.get("instanceId") != instance
            or r.get("leaseId") != lease_id or r.get("runtimeHandlerIdentity") != handler or r.get("dispatchEpoch") != epoch
            or g.get("authorityRealm") != "cloud" or g.get("method") != "session/prompt" or g.get("scope") != "conversation"
            or g.get("executionMode") != "start" or g.get("platformConversationId") != c.get("session_id")
            or g.get("historyGeneration") != c.get("history_generation") or g.get("platformAgentId") != p.get("platformAgentId")
            or not _text(g.get("runtimeAgentUid")) or p.get("conversationId") != c.get("session_id")
            or target.get("scope") != "conversation" or conversation.get("runtimeConversationUid") != c.get("session_id")
            or conversation.get("runtimeSessionKey") != c.get("session_id") or target.get("historyGeneration") != c.get("history_generation")
            or target.get("operationId") != r.get("operationId") or target.get("runtimeInstanceUid") != r.get("instanceId")
            or target.get("dispatchEpoch") != r.get("dispatchEpoch") or target.get("paramsHash") != r.get("paramsHash")
            or not _same(g.get("command"), command) or not _safe_integer(g.get("iat")) or not _safe_integer(g.get("exp"))
            or g["iat"] > now + CLOUD_GRANT_CLOCK_SKEW_SECONDS or g["exp"] + CLOUD_GRANT_CLOCK_SKEW_SECONDS < now
            or g["exp"] <= g["iat"] or g["exp"] - g["iat"] > 60
            or g.get("sub") != handler or g.get("handlerIdentity") != handler
            or any(not _text(r.get(key)) or g.get(key) != r.get(key) for key in fields)
            or rpc.get("jsonrpc") != "2.0" or rpc.get("method") != "session/prompt" or command.get("name") != "session.prompt"
            or verify_native_session_request(r) != r.get("requestHash")
            or runtime_domain_hash("beeos.runtime.params.v1", {"method": r["method"], "params": p}) != r.get("paramsHash")
            or runtime_domain_hash("beeos.runtime.command.v1", {"command": command}) != r.get("commandHash")
            or not all(_text(value) for value in (c.get("session_id"), c.get("history_generation"), c.get("branch_id"),
                c.get("response_id"), c.get("attempt_id"), context.get("tenant_ref"), context.get("scope_ref"), context.get("request_id"),
                writer.get("writer_id"), writer.get("writer_epoch")))
            or not _safe_integer(context.get("authorization_revision")) or context["authorization_revision"] < 1
            or not _safe_integer(context.get("erasure_epoch")) or context["erasure_epoch"] < 0
            or not _decimal(c.get("history_generation")) or not _decimal(writer.get("writer_epoch")) or writer["writer_epoch"] == "0"
            or set(c) != {"context", "session_id", "history_generation", "branch_id", "writer", "response_id", "attempt_id",
                          "watermark", "config_pin", "persona_ref"}
            or not _decimal(c.get("watermark"))
            or set(pin) != {"agent_id", "revision", "content_sha256", "credential_set_ref"}
            or pin.get("agent_id") != p.get("platformAgentId") or not _text(pin.get("revision"))
            or not isinstance(pin.get("content_sha256"), str) or not _DIGEST.fullmatch(pin["content_sha256"])
            or (credential_ref is not None and (not isinstance(credential_ref, dict) or set(credential_ref) != {"set_id", "version"}
                or not _text(credential_ref.get("set_id")) or not _safe_integer(credential_ref.get("version")) or credential_ref["version"] < 1))
            or (persona is not None and (not isinstance(persona, dict) or set(persona) != {"persona_id", "revision"}
                                        or not all(_text(value) for value in persona.values())))
            or "execution_grant" in c or "executionGrant" in c)
        if invalid:
            raise ValueError("central native original signed intent is invalid")
        current()
        binding = {key: copy.deepcopy(c[key]) for key in ("session_id", "history_generation", "branch_id", "response_id", "attempt_id", "context", "writer")}
        binding["operation_id"] = r["operationId"]
        return VerifiedCentralNativeIntent(binding, copy.deepcopy(p), copy.deepcopy(g), decoded["compactHash"], current)
