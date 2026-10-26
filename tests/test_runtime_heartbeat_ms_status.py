"""Heartbeat carries the Message Service connection state as signed ``msConnectionStatus``."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from beeos_cloud_harness_sdk.identity import generate_agent_key_pair
from beeos_cloud_harness_sdk.jcs import HEARTBEAT_HASH_DOMAIN, canonicalize_jcs, runtime_domain_hash
from beeos_cloud_harness_sdk.registration import (
    RuntimeActiveLease,
    RuntimeRegistrationCoordinator,
    RuntimeRegistrationIdentity,
)

LEGACY_PAYLOAD = {"leaseId": "lease-1", "handlerIdentity": "pod-1", "runtimeEpoch": "7"}


async def _active_coordinator(tmp_path: Path, **kwargs: Any) -> tuple[RuntimeRegistrationCoordinator, AsyncMock]:
    transport = AsyncMock()
    transport.register_runtime.return_value = {
        "status": "active", "instanceId": "inst-1", "runtimeEpoch": "7", "leaseId": "lease-1",
        "leaseExpiresAt": "2099-01-01T00:00:00.000Z", "heartbeatIntervalMs": 600_000,
        "runtimeLeaseCredential": "cred-1", "journalStoreId": "journal-1", "journalGeneration": "1",
    }
    transport.heartbeat_runtime.return_value = {
        "status": "renewed", "leaseExpiresAt": "2099-01-02T00:00:00.000Z",
        "runtimeLeaseCredential": "cred-2",
    }
    coord = RuntimeRegistrationCoordinator(
        transport=transport,
        keys=generate_agent_key_pair(tmp_path / "k.json"),
        identity=RuntimeRegistrationIdentity(
            registration_id="reg-1", handler_identity="pod-1",
            journal_store_id="journal-1", journal_generation="1",
        ),
        target_instance_id="inst_123",
        runtime_methods=("session/clear",),
        capabilities=("canvas",),
        **kwargs,
    )
    assert await coord.start() is not None
    return coord, transport


async def _heartbeat(coord: RuntimeRegistrationCoordinator, transport: AsyncMock) -> dict[str, Any]:
    lease = coord.lease
    assert lease is not None
    await coord._send_heartbeat(lease.heartbeat_interval_ms, coord._generation, lease)
    return transport.heartbeat_runtime.await_args.args[1]


@pytest.mark.asyncio
async def test_heartbeat_reports_ms_status_and_follows_changes(tmp_path: Path) -> None:
    state = {"status": "connecting"}
    seen: list[RuntimeActiveLease] = []

    def reporter(lease: RuntimeActiveLease) -> str:
        seen.append(lease)
        return state["status"]

    coord, transport = await _active_coordinator(tmp_path, get_ms_connection_status=reporter)
    try:
        reported = []
        for status in ("connecting", "connected", "reconnecting", "disconnected"):
            state["status"] = status
            body = await _heartbeat(coord, transport)
            reported.append(body["msConnectionStatus"])
            signed = {**LEGACY_PAYLOAD, "msConnectionStatus": status}
            assert body["payloadHash"] == runtime_domain_hash(HEARTBEAT_HASH_DOMAIN, signed)
        assert reported == ["connecting", "connected", "reconnecting", "disconnected"]
        assert {lease.lease_id for lease in seen} == {"lease-1"}
    finally:
        coord.stop()


def test_ms_status_canonical_payload_matches_cloud_literal() -> None:
    payload = {**LEGACY_PAYLOAD, "msConnectionStatus": "connected"}
    assert canonicalize_jcs(payload) == (
        '{"handlerIdentity":"pod-1","leaseId":"lease-1",'
        '"msConnectionStatus":"connected","runtimeEpoch":"7"}'
    )
    assert runtime_domain_hash(HEARTBEAT_HASH_DOMAIN, payload) != runtime_domain_hash(
        HEARTBEAT_HASH_DOMAIN, LEGACY_PAYLOAD
    )


@pytest.mark.asyncio
async def test_heartbeat_without_reporter_stays_legacy_three_field(tmp_path: Path) -> None:
    coord, transport = await _active_coordinator(tmp_path)
    try:
        body = await _heartbeat(coord, transport)
        assert "msConnectionStatus" not in body
        assert body["payloadHash"] == runtime_domain_hash(HEARTBEAT_HASH_DOMAIN, LEGACY_PAYLOAD)
    finally:
        coord.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["ConnectionState.CONNECTED", "", "online"])
async def test_unrecognized_ms_status_is_sent_as_unknown(tmp_path: Path, bad: str) -> None:
    coord, transport = await _active_coordinator(tmp_path, get_ms_connection_status=lambda _lease: bad)
    try:
        body = await _heartbeat(coord, transport)
        assert body["msConnectionStatus"] == "unknown"
        assert body["payloadHash"] == runtime_domain_hash(
            HEARTBEAT_HASH_DOMAIN, {**LEGACY_PAYLOAD, "msConnectionStatus": "unknown"}
        )
    finally:
        coord.stop()


@pytest.mark.asyncio
async def test_failing_ms_reporter_does_not_cost_the_lease(tmp_path: Path) -> None:
    def broken(_lease: RuntimeActiveLease) -> str:
        raise RuntimeError("ms client closed")

    coord, transport = await _active_coordinator(tmp_path, get_ms_connection_status=broken)
    try:
        body = await _heartbeat(coord, transport)
        assert body["msConnectionStatus"] == "unknown"
        assert coord.is_active
    finally:
        coord.stop()


@pytest.mark.asyncio
async def test_reporter_assigned_after_construction_is_honored(tmp_path: Path) -> None:
    """Hermes wires ``coordinator.get_ms_connection_status = ...`` after building it."""
    coord, transport = await _active_coordinator(tmp_path)
    try:
        coord.get_ms_connection_status = lambda _lease: "connected"
        body = await _heartbeat(coord, transport)
        assert body["msConnectionStatus"] == "connected"
    finally:
        coord.stop()
