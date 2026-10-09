"""Unit tests for runtime registration JCS proof + coordinator."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from beeos_cloud_harness_sdk.identity import generate_agent_key_pair
from beeos_cloud_harness_sdk.jcs import (
    REGISTRATION_HASH_DOMAIN,
    canonicalize_jcs,
    runtime_domain_hash,
)
from beeos_cloud_harness_sdk.registration import (
    RUNTIME_CURRENT_MANIFEST_DIGEST,
    RuntimeActiveLease,
    RuntimeRegistrationCoordinator,
    RuntimeRegistrationIdentity,
    classify_registration_conflict,
    load_or_create_identity,
)

METHODS = ("session/clear", "models/list")
CAPS = ("canvas",)


def test_canonicalize_jcs_sorts_keys() -> None:
    raw = {"z": 1, "a": {"x": "<>&", "n": 1e-6}}
    # Numbers may render as 1e-06 or 0.000001 depending on json; just check order.
    out = canonicalize_jcs({"b": 1, "a": 2})
    assert out == '{"a":2,"b":1}'


def test_registration_payload_hash_shape() -> None:
    payload = {
        "capabilities": ["skills"],
        "contractRevision": "2026-07-14.3",
        "handlerIdentity": "runtime:golden-pod",
        "journalGeneration": "1",
        "journalStoreId": "journal-store-golden-v4",
        "manifestDigest": "2746b3d10fd1aed3fa23f717c58dbf7175d04e74274aee8a5a56230f7ce18206",
        "registrationId": "registration-golden-v4",
        "runtimeMethods": ["skills/list"],
        "runtimeRpcProtocolVersion": 1,
    }
    # Golden vector from sdks/beeos-types contracts (v4).
    expected_canonical = (
        '{"capabilities":["skills"],"contractRevision":"2026-07-14.3",'
        '"handlerIdentity":"runtime:golden-pod","journalGeneration":"1",'
        '"journalStoreId":"journal-store-golden-v4",'
        '"manifestDigest":"2746b3d10fd1aed3fa23f717c58dbf7175d04e74274aee8a5a56230f7ce18206",'
        '"registrationId":"registration-golden-v4","runtimeMethods":["skills/list"],'
        '"runtimeRpcProtocolVersion":1}'
    )
    assert canonicalize_jcs(payload) == expected_canonical
    assert (
        runtime_domain_hash(REGISTRATION_HASH_DOMAIN, payload)
        == "5cfbb035925bb82c720f838e9f902bc5f960411a7d9459f899ca849c527e12f1"
    )


def test_load_or_create_identity_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "runtime-registration-identity.json"
    first = load_or_create_identity(path, handler_identity="pod-a")
    second = load_or_create_identity(path, handler_identity="pod-a")
    assert first.registration_id == second.registration_id
    assert first.journal_store_id == second.journal_store_id
    assert first.journal_generation == "1"


def test_classify_handoff() -> None:
    err = classify_registration_conflict(
        "agent gateway POST ... -> 409: active runtime lease requires explicit handoff"
    )
    assert err is not None
    assert type(err).__name__ == "RuntimeRegistrationHandoffRequired"


def test_classify_journal_advance() -> None:
    err = classify_registration_conflict(
        json.dumps(
            {
                "error": {
                    "message": (
                        "journal generation must advance exactly once after "
                        "lease expiry (current=3 expected=4)"
                    )
                }
            }
        )
    )
    assert err is not None
    assert type(err).__name__ == "RuntimeRegistrationJournalAdvanceRequired"
    assert getattr(err, "current") == "3"
    assert getattr(err, "expected") == "4"


def test_classify_intent_conflict_before_generic_409() -> None:
    wrapped = (
        'agent gateway POST /api/v1/runtime/registrations -> 409: '
        '{"error":{"code":"conflict","message":"registration_id intent conflict"}}'
    )
    err = classify_registration_conflict(wrapped)
    assert err is not None
    assert type(err).__name__ == "RuntimeRegistrationIntentConflict"
    # Must not collapse to handoff — retrying the same registrationId never works.
    assert type(err).__name__ != "RuntimeRegistrationHandoffRequired"


@pytest.mark.asyncio
async def test_coordinator_register_and_heartbeat(tmp_path: Path) -> None:
    keys = generate_agent_key_pair(tmp_path / "k.json")
    identity = RuntimeRegistrationIdentity(
        registration_id="reg-1",
        handler_identity="pod-1",
        journal_store_id="journal-1",
        journal_generation="1",
    )

    fixed_now = datetime(2026, 7, 14, 0, 0, 0, tzinfo=timezone.utc)
    transport = AsyncMock()
    transport.register_runtime = AsyncMock(
        return_value={
            "status": "active",
            "instanceId": "inst-1",
            "runtimeEpoch": "7",
            "leaseId": "lease-1",
            "issuedAt": "2026-07-14T00:00:00.000Z",
            "leaseExpiresAt": "2099-01-01T00:00:00.000Z",
            "heartbeatIntervalMs": 50,
            "runtimeLeaseCredential": "cred-1",
            "journalStoreId": "journal-1",
            "journalGeneration": "1",
        }
    )
    transport.heartbeat_runtime = AsyncMock(
        return_value={
            "status": "renewed",
            "leaseExpiresAt": "2099-01-02T00:00:00.000Z",
            "runtimeLeaseCredential": "cred-2",
        }
    )

    coord = RuntimeRegistrationCoordinator(
        transport=transport,
        keys=keys,
        identity=identity,
        target_instance_id="inst_123",
        runtime_methods=METHODS,
        capabilities=CAPS,
        now=lambda: fixed_now,
    )
    lease = await coord.start()
    assert isinstance(lease, RuntimeActiveLease)
    assert lease.lease_id == "lease-1"
    assert coord.is_active is True
    assert transport.register_runtime.await_count == 1

    body = transport.register_runtime.await_args.args[0]
    assert body["registrationId"] == "reg-1"
    assert body["manifestDigest"] == RUNTIME_CURRENT_MANIFEST_DIGEST
    assert body["runtimeRpcProtocolVersion"] == 1
    assert body["signaturePurpose"] == "runtime.register"
    assert body["targetInstanceId"] == "inst_123"
    assert len(body["payloadHash"]) == 64
    assert body["signature"]
    assert body["signedAt"].endswith("Z")

    # Wait for scheduled heartbeat (intervalMs=50).
    import asyncio

    for _ in range(40):
        if transport.heartbeat_runtime.await_count >= 1:
            break
        await asyncio.sleep(0.02)
    assert transport.heartbeat_runtime.await_count >= 1
    hb_body = transport.heartbeat_runtime.await_args.args[1]
    assert hb_body["leaseId"] == "lease-1"
    assert hb_body["signaturePurpose"] == "runtime.heartbeat"
    assert hb_body["targetInstanceId"] == "inst_123"

    coord.stop()
    assert coord.active is None
    assert coord.lease_ready.is_set() is False


@pytest.mark.asyncio
async def test_coordinator_lease_ready_event(tmp_path: Path) -> None:
    keys = generate_agent_key_pair(tmp_path / "k.json")
    identity = RuntimeRegistrationIdentity(
        registration_id="reg-1",
        handler_identity="pod-1",
        journal_store_id="journal-1",
        journal_generation="1",
    )
    transport = AsyncMock()
    transport.register_runtime = AsyncMock(
        return_value={
            "status": "active",
            "instanceId": "inst-1",
            "runtimeEpoch": "7",
            "leaseId": "lease-1",
            "leaseExpiresAt": "2099-01-01T00:00:00.000Z",
            "heartbeatIntervalMs": 60_000,
            "runtimeLeaseCredential": "cred-1",
        }
    )
    transport.heartbeat_runtime = AsyncMock(
        return_value={
            "status": "renewed",
            "leaseExpiresAt": "2099-01-02T00:00:00.000Z",
            "runtimeLeaseCredential": "cred-2",
        }
    )
    coord = RuntimeRegistrationCoordinator(
        transport=transport,
        keys=keys,
        identity=identity,
        target_instance_id="inst_123",
        runtime_methods=METHODS,
        capabilities=CAPS,
    )
    assert coord.lease_ready.is_set() is False
    lease = await coord.start()
    assert lease is not None
    assert coord.lease_ready.is_set() is True
    waited = await coord.wait_until_active(timeout=0.1)
    assert waited is not None
    coord.stop()
    assert coord.lease_ready.is_set() is False


@pytest.mark.asyncio
async def test_coordinator_rolls_lineage_on_intent_conflict(tmp_path: Path) -> None:
    keys = generate_agent_key_pair(tmp_path / "k.json")
    identity_path = tmp_path / "runtime-registration-identity.json"
    identity = RuntimeRegistrationIdentity(
        registration_id="reg-old",
        handler_identity="inst-1",
        journal_store_id="journal-1",
        journal_generation="1",
    )
    calls = {"n": 0}

    async def register(body: Any) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError(
                'agent gateway POST /api/v1/runtime/registrations -> 409: '
                '{"error":{"code":"conflict","message":"registration_id intent conflict"}}'
            )
        assert body["registrationId"] != "reg-old"
        assert body["journalGeneration"] == "2"
        assert body["journalStoreId"] == "journal-1"
        return {
            "status": "active",
            "instanceId": "inst-1",
            "runtimeEpoch": "8",
            "leaseId": "lease-2",
            "leaseExpiresAt": "2099-01-01T00:00:00.000Z",
            "heartbeatIntervalMs": 60_000,
            "runtimeLeaseCredential": "cred-2",
        }

    transport = AsyncMock()
    transport.register_runtime = AsyncMock(side_effect=register)
    transport.heartbeat_runtime = AsyncMock(
        return_value={
            "status": "renewed",
            "leaseExpiresAt": "2099-01-02T00:00:00.000Z",
            "runtimeLeaseCredential": "cred-2",
        }
    )
    coord = RuntimeRegistrationCoordinator(
        transport=transport,
        keys=keys,
        identity=identity,
        target_instance_id="inst_123",
        runtime_methods=METHODS,
        capabilities=CAPS,
        identity_store_path=identity_path,
    )
    first = await coord.start()
    assert first is None
    assert coord.identity.registration_id != "reg-old"
    assert coord.identity.journal_generation == "2"

    import asyncio

    lease = None
    for _ in range(50):
        lease = coord.lease
        if lease is not None:
            break
        await asyncio.sleep(0.05)
    assert lease is not None
    assert lease.lease_id == "lease-2"
    saved = json.loads(identity_path.read_text())
    assert saved["registrationId"] == coord.identity.registration_id
    assert saved["journalGeneration"] == "2"
    coord.stop()


ACTIVE = {
    "status": "active", "instanceId": "inst_123", "runtimeEpoch": "1", "leaseId": "lease-1",
    "leaseExpiresAt": "2099-01-01T00:00:00.000Z", "heartbeatIntervalMs": 100,
    "runtimeLeaseCredential": "cred-1",
}


def _fast_coordinator(tmp_path: Path, transport: Any, **overrides: Any) -> RuntimeRegistrationCoordinator:
    from beeos_cloud_harness_sdk.retry import BackoffPolicy

    return RuntimeRegistrationCoordinator(
        transport=transport,
        keys=generate_agent_key_pair(tmp_path / "k.json"),
        identity=RuntimeRegistrationIdentity("reg-1", "pod-1", "journal-1", "1"),
        target_instance_id="inst_123", runtime_methods=METHODS, capabilities=CAPS,
        fenced_retry=BackoffPolicy(float("inf"), 1, 1, 1), **overrides,
    )


@pytest.mark.asyncio
async def test_fenced_registration_is_recoverable(tmp_path: Path) -> None:
    """Regression: a fenced answer at startup (control plane not ready) used to be permanent."""
    answers = [{"status": "fenced"}, {"status": "fenced"}, ACTIVE]
    transport = AsyncMock()
    transport.register_runtime.side_effect = lambda _body: answers.pop(0)
    transport.heartbeat_runtime.return_value = {"status": "renewed"}
    coord = _fast_coordinator(tmp_path, transport)

    assert await coord.start() is None
    lease = await coord.wait_until_active(timeout=3)
    assert lease is not None and lease.lease_id == "lease-1"
    assert transport.register_runtime.await_count == 3
    coord.stop()


@pytest.mark.asyncio
async def test_register_survives_a_control_plane_that_is_not_ready(tmp_path: Path) -> None:
    import httpx

    answers: list[Any] = [httpx.ConnectError("refused"), httpx.ConnectError("refused"), ACTIVE]

    def register(_body: Any) -> Any:
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    transport = AsyncMock()
    transport.register_runtime.side_effect = register
    transport.heartbeat_runtime.return_value = {"status": "renewed"}
    coord = _fast_coordinator(tmp_path, transport)
    coord._schedule_register = lambda delay, gen: asyncio.get_running_loop().call_soon(  # type: ignore[method-assign]
        lambda: asyncio.ensure_future(coord._register_once(gen)))

    await coord.start()
    assert await coord.wait_until_active(timeout=3) is not None
    coord.stop()


@pytest.mark.asyncio
async def test_heartbeat_tolerates_transient_failures_but_not_a_sustained_outage(tmp_path: Path) -> None:
    import httpx

    transport = AsyncMock()
    transport.register_runtime.return_value = ACTIVE
    transport.heartbeat_runtime.side_effect = httpx.ConnectError("blip")
    coord = _fast_coordinator(tmp_path, transport)
    lease = await coord.start()
    assert lease is not None

    await coord._send_heartbeat(100, coord._generation, lease)
    await coord._send_heartbeat(100, coord._generation, lease)
    assert coord.is_active, "two consecutive transport failures keep the lease"
    await coord._send_heartbeat(100, coord._generation, lease)
    assert not coord.is_active, "third consecutive failure drops it"
    coord.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("trigger", ["expired_response", "expired_heartbeat"])
async def test_expired_registration_advances_same_journal_and_recovers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trigger: str
) -> None:
    keys = generate_agent_key_pair(tmp_path / "key.json")
    identity_path = tmp_path / "registration.json"
    identity = load_or_create_identity(identity_path, handler_identity="desktop-1")
    active = {"status": "active", "instanceId": "inst-1", "runtimeEpoch": "1",
              "leaseId": "lease-1", "runtimeLeaseCredential": "test-credential",
              "leaseExpiresAt": "2099-01-01T00:00:00Z", "heartbeatIntervalMs": 60000}
    first = {**active, "leaseExpiresAt": "2000-01-01T00:00:00Z"} if trigger == "expired_response" else active
    transport = AsyncMock()
    transport.register_runtime.side_effect = [first, {**active, "runtimeEpoch": "2", "leaseId": "lease-2"}]
    transport.heartbeat_runtime.return_value = {"status": "expired"}
    coord = RuntimeRegistrationCoordinator(
        transport=transport, keys=keys, identity=identity, identity_store_path=identity_path,
        target_instance_id="inst-1", runtime_methods=METHODS, capabilities=CAPS,
    )
    scheduled: list[int] = []
    monkeypatch.setattr(coord, "_schedule_register", lambda delay, gen: scheduled.append(gen))
    monkeypatch.setattr(coord, "_schedule_heartbeat", lambda *args: None)
    try:
        lease = await coord.start()
        if trigger == "expired_heartbeat":
            assert lease is not None
            await coord._send_heartbeat(60000, coord._generation, lease)
        else:
            assert lease is None
        assert coord.lease is None
        assert not coord.lease_ready.is_set()
        assert len(scheduled) == 1
        assert coord.identity.registration_id != identity.registration_id
        assert coord.identity.journal_store_id == identity.journal_store_id
        assert int(coord.identity.journal_generation) == int(identity.journal_generation) + 1
        assert load_or_create_identity(identity_path, handler_identity="desktop-1") == coord.identity
        renewed = await coord._register_once(scheduled[0])
        assert renewed is not None and renewed.lease_id == "lease-2"
        assert coord.is_active and coord.lease_ready.is_set()
    finally:
        coord.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("expiry", ["", "invalid", "2099-01-01T00:00:00"])
async def test_invalid_expiry_is_never_published_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, expiry: str
) -> None:
    keys = generate_agent_key_pair(tmp_path / "key.json")
    identity = load_or_create_identity(tmp_path / "registration.json", handler_identity="desktop-1")
    transport = AsyncMock()
    transport.register_runtime.return_value = {
        "status": "active", "instanceId": "inst-1", "leaseId": "lease-1",
        "runtimeLeaseCredential": "test-credential", "leaseExpiresAt": expiry,
    }
    coord = RuntimeRegistrationCoordinator(
        transport=transport, keys=keys, identity=identity,
        target_instance_id="inst-1", runtime_methods=METHODS, capabilities=CAPS,
    )
    monkeypatch.setattr(coord, "_schedule_register", lambda *args: None)
    try:
        assert await coord.start() is None
        assert not coord.is_active and not coord.lease_ready.is_set()
        assert coord.identity == identity
        transport.heartbeat_runtime.assert_not_called()
    finally:
        coord.stop()
