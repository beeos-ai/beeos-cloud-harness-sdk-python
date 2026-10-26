"""Real RSA signatures plus current-original Cloud intent and renewal checks."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from beeos_cloud_harness_sdk.grant_jwks import (CloudGatewayGrantJwksVerifier, CLOUD_GRANT_DOMAIN,
                                               CLOUD_GRANT_JWKS_PATH, GRANT_REASONS)
from beeos_cloud_harness_sdk.jcs import native_session_request_hash, runtime_domain_hash


def encode(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def fixture(key):
    clock = [2000000000.0]
    expiry = datetime.fromtimestamp(clock[0] + 120, timezone.utc).isoformat()
    lease = SimpleNamespace(instance_id="sandbox", lease_id="lease", handler_identity="handler", runtime_epoch="11", lease_expires_at=expiry)
    params = {"platformAgentId": "agent", "conversationId": "session", "parts": [{"type": "text", "text": "原始 input"}],
        "runtimeRunId": "actual-distinct-native-run", "taskId": "operation", "taskRequestMessageId": "request",
        "centralChat": {"session_id": "session", "history_generation": "1", "branch_id": "main", "response_id": "response", "attempt_id": "attempt",
            "context": {"tenant_ref": "tenant", "scope_ref": "history", "authorization_revision": 1, "erasure_epoch": 0, "request_id": "q"},
            "writer": {"writer_id": "actual-allocation", "writer_epoch": "23"}, "watermark": "0",
            "config_pin": {"agent_id": "agent", "revision": "config", "content_sha256": "c" * 64, "credential_set_ref": None},
            "persona_ref": None}}
    rpc = {"jsonrpc": "2.0", "id": "rpc", "method": "session/prompt", "params": params}
    params_hash = runtime_domain_hash("beeos.runtime.params.v1", {"method": "session/prompt", "params": params})
    command = {"name": "session.prompt", "context": {"scope": "conversation", "operationId": "operation", "runtimeInstanceUid": "sandbox",
        "dispatchEpoch": "11", "historyGeneration": "1", "paramsHash": params_hash,
        "conversation": {"runtimeConversationUid": "session", "runtimeSessionKey": "session"}}, "params": {}}
    request = {"schemaVersion": 2, "authorityRealm": "cloud", "cloudSubject": {"organizationId": "tenant", "appId": "app", "instanceId": "sandbox"},
        "instanceId": "sandbox", "leaseId": "lease", "runtimeHandlerIdentity": "handler", "dispatchEpoch": "11", "method": "session/prompt",
        "operationId": "operation", "requestMessageId": "request", "request": rpc, "command": command, "paramsHash": params_hash,
        "requestHash": native_session_request_hash(rpc), "commandHash": runtime_domain_hash("beeos.runtime.command.v1", {"command": command}),
        "idempotencyKeyHash": "a" * 64, "executionGrantHash": hashlib.sha256(b"historical-first-compact").hexdigest()}
    claims = {**copy.deepcopy(request), "iss": CLOUD_GRANT_DOMAIN["issuer"], "aud": CLOUD_GRANT_DOMAIN["audience"], "purpose": CLOUD_GRANT_DOMAIN["purpose"],
        "sub": "handler", "handlerIdentity": "handler", "scope": "conversation", "executionMode": "start", "platformConversationId": "session",
        "historyGeneration": "1", "platformAgentId": "agent", "runtimeAgentUid": "actual-native-uid", "iat": int(clock[0]), "exp": int(clock[0]) + 30}
    numbers = key.public_key().public_numbers()
    public = {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "actual-key",
        "e": encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        "n": encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))}
    jwks = {**CLOUD_GRANT_DOMAIN, "keys": [public]}
    calls, status, location = [], [200], [None]
    def send(incoming):
        calls.append(incoming)
        return httpx.Response(status[0], json=jwks, headers={"ETag": '"actual-keyset"', **({"Location": location[0]} if location[0] else {})})
    client = httpx.Client(transport=httpx.MockTransport(send))
    verifier = CloudGatewayGrantJwksVerifier("https://gateway.test", client=client, now=lambda: clock[0])
    def sign(changed=None, header=None, signing_key=None):
        a, b = encode(header or {"alg": "RS256", "typ": "JWT", "kid": "actual-key"}), encode(claims if changed is None else changed)
        signature = (signing_key or key).sign((a + "." + b).encode(), padding.PKCS1v15(), hashes.SHA256())
        return a + "." + b + "." + encode(signature)
    return SimpleNamespace(verifier=verifier, request=request, claims=claims, lease=lease, jwks=jwks, sign=sign, clock=clock, calls=calls, status=status, location=location)


def test_actual_rsa_original_and_renewed_grants_keep_first_compact_hash_and_actual_writer(key):
    f = fixture(key); f.verifier.refresh()
    original = copy.deepcopy(f.request)
    actual = f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)
    assert actual.binding["writer"] == {"writer_id": "actual-allocation", "writer_epoch": "23"}
    assert actual.binding["operation_id"] == "operation" and actual.params == f.request["request"]["params"]
    actual.assert_current()
    f.claims.update(iat=int(f.clock[0]) + 1, exp=int(f.clock[0]) + 31)
    f.clock[0] += 1
    renewed = f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)
    assert renewed.binding == actual.binding and renewed.compact_hash != actual.compact_hash
    assert renewed.compact_hash != f.request["executionGrantHash"] and f.request == original
    assert len(f.calls) == 1 and f.calls[0].url.path == CLOUD_GRANT_JWKS_PATH
    assert "Authorization" not in f.calls[0].headers
    f.lease.runtime_epoch = "12"
    with pytest.raises(ValueError, match="fenced"): actual.assert_current()


@pytest.mark.parametrize("name,value", [
    ("authorityRealm", "personal"), ("method", "session/set_model"), ("scope", "agent"), ("executionMode", "resume"),
    ("platformConversationId", "foreign"), ("historyGeneration", "2"), ("platformAgentId", "foreign"), ("runtimeAgentUid", ""),
    ("sub", "foreign"), ("handlerIdentity", "foreign"), ("operationId", "foreign"), ("requestMessageId", "foreign"),
    ("instanceId", "foreign"), ("leaseId", "foreign"), ("dispatchEpoch", "7"), ("requestHash", "f" * 64),
    ("paramsHash", "f" * 64), ("commandHash", "f" * 64), ("idempotencyKeyHash", "f" * 64),
    ("iat", 2000000031), ("exp", 1999999969), ("exp", 2000000061), ("iat", True), ("exp", 2000000030.0),
])
def test_signed_but_wrong_original_claims_never_authorize(key, name, value):
    f = fixture(key); f.verifier.refresh(); f.claims[name] = value
    with pytest.raises(ValueError, match="original signed intent"):
        f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)


def test_thirty_second_clock_skew_covers_each_deadline_direction(key):
    f = fixture(key); f.verifier.refresh()
    now = int(f.clock[0])
    # A grant that expired 5s ago is still inside the tolerated skew.
    f.claims.update(iat=now - 35, exp=now - 5)
    f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)
    # Five minutes late is a real expiry, not skew.
    f.claims.update(iat=now - 330, exp=now - 300)
    with pytest.raises(ValueError, match="original signed intent"):
        f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)
    # The guest clock may trail the signer by the same 30s.
    f.claims.update(iat=now + 30, exp=now + 60)
    f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)
    f.claims.update(iat=now + 31, exp=now + 61)
    with pytest.raises(ValueError, match="original signed intent"):
        f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)


@pytest.mark.parametrize("case,expected", [
    ("expired", "grant_expired"), ("iat_future", "grant_iat_future"),
    ("issuer", "grant_issuer_mismatch"), ("audience", "grant_audience_mismatch"),
    ("binding", "grant_binding_mismatch"), ("jwks", "grant_jwks_unavailable"),
    ("signature", "grant_signature_invalid"),
])
def test_rejections_report_a_distinct_reason_on_the_same_value_error(key, case, expected):
    f = fixture(key)
    if case != "jwks":
        f.verifier.refresh()
    now = int(f.clock[0])
    if case == "expired":
        f.claims.update(iat=now - 330, exp=now - 300); token = f.sign()
    elif case == "iat_future":
        f.claims.update(iat=now + 31, exp=now + 61); token = f.sign()
    elif case == "issuer":
        f.claims["iss"] = "foreign"; token = f.sign()
    elif case == "audience":
        f.claims["aud"] = "foreign"; token = f.sign()
    elif case == "binding":
        f.request["command"]["name"] = "agent.run"; token = f.sign()
    elif case == "jwks":
        token = f.sign()
    else:
        token = f.sign(signing_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    assert expected in GRANT_REASONS
    with pytest.raises(ValueError, match=f"original signed intent is invalid: {expected}$"):
        f.verifier.verify_original(f.request, token, f.lease, lambda: f.lease)


@pytest.mark.parametrize("case", ["rpc", "params", "command", "conversation", "embedded-grant", "unsafe-context", "subject", "first-hash", "current-lease", "inline-private", "config-pin", "persona-ref", "run-id", "task-id", "task-request-id"])
def test_changed_carrier_targets_hashes_or_current_fence_reject(key, case):
    f = fixture(key); f.verifier.refresh()
    if case == "rpc": f.request["request"]["params"]["parts"][0]["text"] = "changed"
    elif case == "params": f.request["paramsHash"] = "e" * 64
    elif case == "command": f.request["command"]["name"] = "agent.run"
    elif case == "conversation": f.request["command"]["context"]["conversation"]["runtimeSessionKey"] = "foreign"
    elif case == "embedded-grant": f.request["request"]["params"]["centralChat"]["executionGrant"] = "self-referential"
    elif case == "unsafe-context": f.request["request"]["params"]["centralChat"]["context"]["erasure_epoch"] = True
    elif case == "subject": f.claims["cloudSubject"]["appId"] = "foreign"
    elif case == "first-hash": f.request["executionGrantHash"] = "invalid"
    elif case == "inline-private": f.request["request"]["params"]["centralChat"]["effective_config"] = {"api_key": "must-not-enter-canonical"}
    elif case == "config-pin": f.request["request"]["params"]["centralChat"]["config_pin"]["content_sha256"] = "invalid"
    elif case == "persona-ref": f.request["request"]["params"]["centralChat"]["persona_ref"] = {"revision": "missing-id"}
    elif case == "run-id": f.request["request"]["params"]["runtimeRunId"] = ""
    elif case == "task-id": f.request["request"]["params"]["taskId"] = "foreign-operation"
    elif case == "task-request-id": f.request["request"]["params"]["taskRequestMessageId"] = "foreign-request"
    else: f.lease.lease_expires_at = "invalid"
    with pytest.raises(ValueError): f.verifier.verify_original(f.request, f.sign(), f.lease, lambda: f.lease)


@pytest.mark.parametrize("case", ["signature", "unknown-key", "algorithm", "padding", "wrong-issuer", "wrong-audience", "wrong-purpose"])
def test_real_signature_canonical_jwt_and_cloud_provenance_required(key, case):
    f = fixture(key); f.verifier.refresh()
    if case == "signature":
        token = f.sign(signing_key=rsa.generate_private_key(public_exponent=65537, key_size=2048))
    elif case == "unknown-key": token = f.sign(header={"alg": "RS256", "typ": "JWT", "kid": "unknown"})
    elif case == "algorithm": token = f.sign(header={"alg": "HS256", "typ": "JWT", "kid": "actual-key"})
    elif case == "padding":
        pieces = f.sign().split("."); pieces[0] += "="; token = ".".join(pieces)
    else:
        f.claims[{"wrong-issuer": "iss", "wrong-audience": "aud", "wrong-purpose": "purpose"}[case]] = "foreign"
        token = f.sign()
    assert f.verifier.verify_and_decode_grant(token) is None


def test_bounded_key_cache_no_redirect_or_stale_trust_after_provenance_failure(key):
    f = fixture(key); f.verifier.refresh(); f.verifier.refresh()
    assert len(f.calls) == 1
    f.clock[0] += 301
    assert f.verifier.verify_and_decode_grant(f.sign()) is None
    f.verifier.refresh(); assert len(f.calls) == 2
    f.jwks["purpose"] = "foreign"
    with pytest.raises(ValueError, match="provenance"): f.verifier.refresh(force=True)
    assert f.verifier.verify_and_decode_grant(f.sign()) is None
    f = fixture(key); f.status[0] = 302; f.location[0] = "https://other.test/keys"
    with pytest.raises(httpx.HTTPStatusError): f.verifier.refresh()
    assert len(f.calls) == 1


def test_duplicate_and_weak_keys_or_unbounded_origins_are_rejected(key):
    f = fixture(key); f.jwks["keys"] *= 2
    with pytest.raises(ValueError, match="duplicate"): f.verifier.refresh()
    weak = fixture(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    with pytest.raises(ValueError, match="no trusted"): weak.verifier.refresh()
    for origin in ("https://user:secret@gateway.test", "https://gateway.test/path", "ftp://gateway.test"):
        with pytest.raises(ValueError): CloudGatewayGrantJwksVerifier(origin)
    with pytest.raises(ValueError): CloudGatewayGrantJwksVerifier("https://gateway.test", ttl_seconds=301)
