"""Runtime registration + heartbeat — acquire Instance-owned runtime authority.

BeeOS Agent Gateway requires an active runtime_authority lease before
``POST /api/v1/messaging/token`` succeeds. This coordinator mirrors the TypeScript SDK
``RuntimeRegistrationCoordinator`` wire contract and recovery behavior:

  POST /api/v1/runtime/registrations
  POST /api/v1/runtime/registrations/{registrationId}/heartbeat

Identity proof: Ed25519 over ``beeos-cloud-runtime-identity-v1`` LF-tuple with
domain-separated JCS payload hash (``beeos.runtime.registration.v1`` /
``beeos.runtime.heartbeat.v1``). Agent-auth v2 still signs the HTTP body.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, runtime_checkable

from beeos_cloud_harness_sdk.identity import AgentKeyPair, _private_from_seed
from beeos_cloud_harness_sdk.retry import BackoffPolicy, delay_for_attempt, is_transient_error
from beeos_cloud_harness_sdk.jcs import (
    HEARTBEAT_HASH_DOMAIN,
    REGISTRATION_HASH_DOMAIN,
    runtime_domain_hash,
    sha256_hex,
)

logger = logging.getLogger(__name__)

# Frozen Types 4.1 parity digest (backend RuntimeCurrentManifestDigest).
RUNTIME_CURRENT_MANIFEST_DIGEST = (
    "d5db2c5e7c78cee73e5672a3c18a8e56179b28888f6fbb660d98ec021ca9de9b"
)
RUNTIME_RPC_CONTRACT_REVISION = "2026-07-14.3"
RUNTIME_RPC_PROTOCOL_VERSION = 1

IDENTITY_FILE_NAME = "runtime-registration-identity.json"

#: A ``fenced`` answer is recoverable (a capability may become ready later): retry 30 s -> 5 min, forever.
FENCED_RETRY = BackoffPolicy(float("inf"), 30_000, 300_000, 2)
#: Consecutive heartbeat transport failures tolerated before the lease is treated as lost.
HEARTBEAT_TRANSPORT_FAILURE_THRESHOLD = 3

_HANDOFF_RE = re.compile(
    r"active runtime lease requires explicit handoff|waiting for the active runtime lease",
    re.I,
)
_JOURNAL_ADVANCE_RE = re.compile(r"journal generation must advance exactly once", re.I)
_OWNER_RESET_RE = re.compile(r"journal store change requires owner reset authorization", re.I)
# Same registrationId is bound to one canonical intent (methods/capabilities/
# manifest). Advertising new runtimeMethods after an image roll hits this and
# can NEVER succeed by retrying the persisted id — even after lease expiry.
_INTENT_CONFLICT_RE = re.compile(r"registration[_ ]id intent conflict", re.I)


@runtime_checkable
class RuntimeRegistrationTransport(Protocol):
    async def register_runtime(self, body: Mapping[str, Any]) -> Any: ...
    async def heartbeat_runtime(
        self, registration_id: str, body: Mapping[str, Any]
    ) -> Any: ...


@dataclass(frozen=True, slots=True)
class RuntimeRegistrationIdentity:
    registration_id: str
    handler_identity: str
    journal_store_id: str
    journal_generation: str

    def to_dict(self) -> dict[str, str]:
        return {
            "registrationId": self.registration_id,
            "handlerIdentity": self.handler_identity,
            "journalStoreId": self.journal_store_id,
            "journalGeneration": self.journal_generation,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RuntimeRegistrationIdentity:
        return cls(
            registration_id=str(data["registrationId"]),
            handler_identity=str(data["handlerIdentity"]),
            journal_store_id=str(data["journalStoreId"]),
            journal_generation=str(data["journalGeneration"]),
        )


@dataclass
class RuntimeActiveLease:
    instance_id: str
    lease_id: str
    runtime_epoch: str
    runtime_lease_credential: str
    lease_expires_at: str
    heartbeat_interval_ms: int = 15_000
    registration_id: str = ""
    handler_identity: str = ""


class RuntimeRegistrationError(RuntimeError):
    """Base error for registration authority outcomes."""


class RuntimeRegistrationHandoffRequired(RuntimeRegistrationError):
    def __init__(self, retry_after_ms: int = 65_000) -> None:
        super().__init__("active runtime lease requires explicit handoff")
        self.retry_after_ms = retry_after_ms


class RuntimeRegistrationJournalAdvanceRequired(RuntimeRegistrationError):
    def __init__(
        self,
        *,
        current: str | None = None,
        expected: str | None = None,
    ) -> None:
        super().__init__(
            "journal generation must advance exactly once after lease expiry"
        )
        self.current = current
        self.expected = expected


class RuntimeRegistrationOwnerResetRequired(RuntimeRegistrationError):
    def __init__(self) -> None:
        super().__init__(
            "journal store change requires owner reset authorization"
        )


class RuntimeRegistrationIntentConflict(RuntimeRegistrationError):
    """Persisted registrationId no longer matches the advertised intent.

    Control plane binds ``registrationId`` → canonical hash forever. A new
    ``runtimeMethods`` list (e.g. adding ``agent/applyTemplate``) must mint a
    new id and fast-forward ``journalGeneration``; retrying the old id 409s
    forever and is misclassified as handoff if we only look at HTTP 409.
    """

    def __init__(self) -> None:
        super().__init__("registration_id intent conflict")


@dataclass
class RuntimeRegistrationCoordinator:
    """Owns register + heartbeat loop for one process generation."""

    transport: RuntimeRegistrationTransport
    keys: AgentKeyPair
    identity: RuntimeRegistrationIdentity
    target_instance_id: str
    #: Methods/capabilities this harness actually dispatches; the SDK cannot guess them.
    runtime_methods: tuple[str, ...]
    capabilities: tuple[str, ...]
    contract_revision: str = RUNTIME_RPC_CONTRACT_REVISION
    manifest_digest: str = RUNTIME_CURRENT_MANIFEST_DIGEST
    identity_store_path: Path | None = None
    fenced_retry: BackoffPolicy = FENCED_RETRY
    heartbeat_failure_threshold: int = HEARTBEAT_TRANSPORT_FAILURE_THRESHOLD
    now: Any = field(default=None)
    active: RuntimeActiveLease | None = field(default=None, init=False)
    # Set when an active lease is acquired; cleared on loss / stop.
    # agents/sync waits on this instead of blind sleeps during handoff.
    lease_ready: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _task: asyncio.Task[Any] | None = field(default=None, init=False)
    _stopped: bool = field(default=False, init=False)
    _generation: int = field(default=0, init=False)
    _fenced_attempts: int = field(default=0, init=False)
    _heartbeat_failures: int = field(default=0, init=False)
    errors: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.now is None:
            self.now = lambda: datetime.now(timezone.utc)

    @property
    def lease(self) -> RuntimeActiveLease | None:
        active = self.active
        if active is None:
            return None
        try:
            expires = datetime.fromisoformat(
                active.lease_expires_at.replace("Z", "+00:00")
            )
        except ValueError:
            return None
        if expires.tzinfo is None or expires.timestamp() <= self.now().timestamp():
            return None
        return active

    @property
    def is_active(self) -> bool:
        return self.lease is not None

    def _set_active_lease(self, lease: RuntimeActiveLease | None) -> None:
        """Publish or clear the active lease and signal waiters."""
        self.active = lease
        if lease is None:
            self.lease_ready.clear()
        else:
            self.lease_ready.set()

    async def wait_until_active(
        self, timeout: float | None = None
    ) -> RuntimeActiveLease | None:
        """Wait until RegisterRuntime publishes a usable lease (or timeout)."""
        current = self.lease
        if current is not None:
            return current
        if timeout is None:
            await self.lease_ready.wait()
        else:
            try:
                await asyncio.wait_for(self.lease_ready.wait(), timeout=timeout)
            except TimeoutError:
                return self.lease
        return self.lease

    async def start(self) -> RuntimeActiveLease | None:
        gen = self._generation + 1
        self._generation = gen
        self._stopped = False
        self.lease_ready.clear()
        return await self._register_once(gen)

    def stop(self) -> None:
        self._generation += 1
        self._stopped = True
        task = self._task
        self._task = None
        self._set_active_lease(None)
        if task is not None and not task.done():
            task.cancel()

    async def _register_once(self, generation: int) -> RuntimeActiveLease | None:
        if not self._is_current(generation):
            return None
        payload = self._registration_payload()
        body = self._sign_proof("runtime.register", payload)
        try:
            result = await self.transport.register_runtime(body)
        except Exception as exc:  # noqa: BLE001
            if not self._is_current(generation):
                return None
            classified = classify_registration_conflict(str(exc))
            if isinstance(classified, RuntimeRegistrationJournalAdvanceRequired):
                self.errors["register"] = str(classified)
                await self._roll_journal(classified)
                self._schedule_register(5_000, generation)
                return None
            if isinstance(classified, RuntimeRegistrationOwnerResetRequired):
                self.errors["register"] = str(classified)
                logger.error("runtime registration terminal: %s", classified)
                return None
            if isinstance(classified, RuntimeRegistrationIntentConflict):
                self.errors["register"] = str(classified)
                logger.warning(
                    "runtime registration intent conflict; rolling lineage "
                    "registrationId=%s generation=%s",
                    self.identity.registration_id,
                    self.identity.journal_generation,
                )
                await self._roll_intent_lineage()
                # Old lease may still be inside TTL; next attempt then handoff-waits.
                self._schedule_register(1_000, generation)
                return None
            if isinstance(classified, RuntimeRegistrationHandoffRequired):
                self.errors["register"] = str(classified)
                self._schedule_register(classified.retry_after_ms, generation)
                return None
            self.errors["register"] = str(exc)
            logger.warning("runtime register failed: %s", exc)
            self._schedule_register(5_000, generation)
            return None

        if not self._is_current(generation):
            return None
        if not isinstance(result, Mapping):
            self.errors["register"] = "invalid registration result"
            self._schedule_register(5_000, generation)
            return None

        status = str(result.get("status") or "")
        if status != "active":
            self.errors["register"] = f"status={status}"
            if status == "fenced":
                self._fenced_attempts += 1
                retry_ms = delay_for_attempt(self.fenced_retry, self._fenced_attempts)
            else:
                retry_ms = int(result.get("retryAfterMs") or 5_000)
            self._schedule_register(retry_ms, generation)
            return None

        lease = RuntimeActiveLease(
            instance_id=str(result.get("instanceId") or ""),
            lease_id=str(result.get("leaseId") or ""),
            runtime_epoch=str(result.get("runtimeEpoch") or ""),
            runtime_lease_credential=str(
                result.get("runtimeLeaseCredential") or ""
            ),
            lease_expires_at=str(result.get("leaseExpiresAt") or ""),
            heartbeat_interval_ms=int(
                result.get("heartbeatIntervalMs") or 15_000
            ),
            registration_id=self.identity.registration_id,
            handler_identity=self.identity.handler_identity,
        )
        if not lease.lease_id or not lease.runtime_lease_credential:
            self.errors["register"] = "registration active but lease incomplete"
            self._schedule_register(5_000, generation)
            return None

        try:
            expires = datetime.fromisoformat(lease.lease_expires_at.replace("Z", "+00:00"))
            if expires.tzinfo is None:
                raise ValueError("lease expiry must include a timezone")
        except ValueError:
            self.errors["register"] = "registration active but lease expiry invalid"
            self._schedule_register(5_000, generation)
            return None
        if expires.timestamp() <= self.now().timestamp():
            # A replayed response for an old registrationId carries a dead lease:
            # continue the same journal with a new intent instead of reusing it.
            self.errors["register"] = "registration returned an expired lease"
            await self._roll_intent_lineage()
            self._schedule_register(1_000, generation)
            return None

        self._set_active_lease(lease)
        self._fenced_attempts = 0
        self._heartbeat_failures = 0
        self.errors.pop("register", None)
        logger.info(
            "runtime registration active lease=%s epoch=%s",
            lease.lease_id,
            lease.runtime_epoch,
        )
        self._schedule_heartbeat(lease.heartbeat_interval_ms, generation, lease)
        return lease

    async def _send_heartbeat(
        self,
        interval_ms: int,
        generation: int,
        lease: RuntimeActiveLease,
    ) -> None:
        if not self._is_current_lease(generation, lease):
            return
        payload = {
            "leaseId": lease.lease_id,
            "handlerIdentity": self.identity.handler_identity,
            "runtimeEpoch": lease.runtime_epoch,
        }
        body = self._sign_proof("runtime.heartbeat", payload)
        try:
            result = await self.transport.heartbeat_runtime(
                self.identity.registration_id, body
            )
        except Exception as exc:  # noqa: BLE001
            if not self._is_current_lease(generation, lease):
                return
            self.errors["heartbeat"] = str(exc)
            logger.warning("runtime heartbeat failed: %s", exc)
            # Brief ALB/gateway blips keep the lease; an authoritative answer or a
            # sustained outage (threshold consecutive failures) does not.
            self._heartbeat_failures += 1
            if (
                is_transient_error(exc)
                and self._heartbeat_failures < self.heartbeat_failure_threshold
            ):
                self._schedule_heartbeat(interval_ms, generation, lease)
                return
            self._heartbeat_failures = 0
            self._set_active_lease(None)
            self._schedule_register(5_000, generation)
            return

        if not self._is_current_lease(generation, lease):
            return
        if not isinstance(result, Mapping):
            self._set_active_lease(None)
            self._schedule_register(5_000, generation)
            return
        status = str(result.get("status") or "")
        if status != "renewed":
            self.errors["heartbeat"] = f"status={status}"
            self._set_active_lease(None)
            logger.warning("runtime lease lost: heartbeat status=%s", status)
            if status == "expired":
                await self._roll_intent_lineage()
            self._schedule_register(5_000, generation)
            return

        renewed = RuntimeActiveLease(
            instance_id=lease.instance_id,
            lease_id=lease.lease_id,
            runtime_epoch=lease.runtime_epoch,
            runtime_lease_credential=str(
                result.get("runtimeLeaseCredential")
                or lease.runtime_lease_credential
            ),
            lease_expires_at=str(
                result.get("leaseExpiresAt") or lease.lease_expires_at
            ),
            heartbeat_interval_ms=interval_ms,
            registration_id=lease.registration_id,
            handler_identity=lease.handler_identity,
        )
        self._set_active_lease(renewed)
        self._heartbeat_failures = 0
        self.errors.pop("heartbeat", None)
        self._schedule_heartbeat(interval_ms, generation, renewed)

    def _schedule_heartbeat(
        self, interval_ms: int, generation: int, lease: RuntimeActiveLease
    ) -> None:
        if not self._is_current(generation):
            return

        async def _run() -> None:
            await asyncio.sleep(max(0.1, interval_ms / 1000.0))
            await self._send_heartbeat(interval_ms, generation, lease)

        self._task = asyncio.create_task(_run(), name="beeos-runtime-hb")

    def _schedule_register(self, delay_ms: int, generation: int) -> None:
        if not self._is_current(generation):
            return

        async def _run() -> None:
            await asyncio.sleep(max(0.1, delay_ms / 1000.0))
            await self._register_once(generation)

        self._task = asyncio.create_task(
            _run(), name="beeos-runtime-register-retry"
        )

    def _registration_payload(self) -> dict[str, Any]:
        return {
            "registrationId": self.identity.registration_id,
            "handlerIdentity": self.identity.handler_identity,
            "contractRevision": self.contract_revision,
            "manifestDigest": self.manifest_digest,
            "runtimeRpcProtocolVersion": RUNTIME_RPC_PROTOCOL_VERSION,
            "runtimeMethods": list(self.runtime_methods),
            "capabilities": list(self.capabilities),
            "journalStoreId": self.identity.journal_store_id,
            "journalGeneration": self.identity.journal_generation,
        }

    def _sign_proof(
        self, purpose: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        domain = (
            REGISTRATION_HASH_DOMAIN
            if purpose == "runtime.register"
            else HEARTBEAT_HASH_DOMAIN
        )
        payload_hash = runtime_domain_hash(domain, dict(payload))
        signed_at = _utc_now_rfc3339(self.now())
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(18)).decode("ascii").rstrip(
            "="
        )
        key_id = sha256_hex(self.keys.public_key)
        message = "\n".join(
            [
                "beeos-cloud-runtime-identity-v1",
                purpose,
                key_id,
                self.target_instance_id,
                signed_at,
                nonce,
                payload_hash,
            ]
        )
        priv = _private_from_seed(self.keys.private_key)
        signature = base64.urlsafe_b64encode(priv.sign(message.encode("utf-8"))).decode(
            "ascii"
        ).rstrip("=")
        return {
            **dict(payload),
            "signaturePurpose": purpose,
            "instanceIdentityKeyId": key_id,
            "targetInstanceId": self.target_instance_id,
            "nonce": nonce,
            "signedAt": signed_at,
            "payloadHash": payload_hash,
            "signature": signature,
        }

    async def _roll_journal(
        self, err: RuntimeRegistrationJournalAdvanceRequired
    ) -> None:
        current = self.identity
        if err.expected and re.fullmatch(r"[1-9][0-9]*", err.expected):
            next_gen = err.expected
        elif err.current and re.fullmatch(r"[1-9][0-9]*", err.current):
            next_gen = str(int(err.current) + 1)
        else:
            next_gen = str(int(current.journal_generation) + 1)
        rolled = RuntimeRegistrationIdentity(
            registration_id=str(uuid.uuid4()),
            handler_identity=current.handler_identity,
            journal_store_id=current.journal_store_id,
            journal_generation=next_gen,
        )
        self.identity = rolled
        if self.identity_store_path is not None:
            save_identity(self.identity_store_path, rolled)
        logger.info(
            "runtime registration rolled journalGeneration=%s registrationId=%s",
            next_gen,
            rolled.registration_id,
        )

    async def _roll_intent_lineage(self) -> None:
        """Mint a new registrationId and fast-forward journal generation.

        Backend allows successors to skip unused generations after the active
        lease expires (``generation > current.JournalGeneration``). Keep the
        journal store so we do not trip owner-reset.
        """
        current = self.identity
        try:
            next_gen = str(int(current.journal_generation) + 1)
        except (TypeError, ValueError):
            next_gen = "2"
        rolled = RuntimeRegistrationIdentity(
            registration_id=str(uuid.uuid4()),
            handler_identity=current.handler_identity,
            journal_store_id=current.journal_store_id,
            journal_generation=next_gen,
        )
        self.identity = rolled
        if self.identity_store_path is not None:
            save_identity(self.identity_store_path, rolled)
        logger.info(
            "runtime registration intent-roll journalGeneration=%s registrationId=%s",
            next_gen,
            rolled.registration_id,
        )

    def _is_current(self, generation: int) -> bool:
        return not self._stopped and generation == self._generation

    def _is_current_lease(
        self, generation: int, lease: RuntimeActiveLease
    ) -> bool:
        return self._is_current(generation) and self.active is lease


def classify_registration_conflict(
    detail: str,
) -> (
    RuntimeRegistrationHandoffRequired
    | RuntimeRegistrationJournalAdvanceRequired
    | RuntimeRegistrationOwnerResetRequired
    | RuntimeRegistrationIntentConflict
    | None
):
    """Map Agent Gateway 409 / error text to typed registration outcomes."""
    message = detail
    try:
        parsed = json.loads(detail)
        if isinstance(parsed, dict):
            err = parsed.get("error")
            if isinstance(err, dict) and isinstance(err.get("message"), str):
                message = err["message"]
            elif isinstance(parsed.get("message"), str):
                message = parsed["message"]
    except (json.JSONDecodeError, TypeError):
        pass

    if _OWNER_RESET_RE.search(message):
        return RuntimeRegistrationOwnerResetRequired()
    if _INTENT_CONFLICT_RE.search(message):
        return RuntimeRegistrationIntentConflict()
    if _JOURNAL_ADVANCE_RE.search(message):
        current_m = re.search(r"\bcurrent=(\d+)\b", message, re.I)
        expected_m = re.search(r"\bexpected=(\d+)\b", message, re.I)
        return RuntimeRegistrationJournalAdvanceRequired(
            current=current_m.group(1) if current_m else None,
            expected=expected_m.group(1) if expected_m else None,
        )
    if _HANDOFF_RE.search(message) or "conflicts with current state" in message.lower():
        return RuntimeRegistrationHandoffRequired()
    if "409" in message:
        return RuntimeRegistrationHandoffRequired()
    return None


def load_or_create_identity(
    path: Path,
    *,
    handler_identity: str,
) -> RuntimeRegistrationIdentity:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            identity = RuntimeRegistrationIdentity.from_dict(data)
            if identity.handler_identity == handler_identity:
                return identity
            # Handler changed (pod rename) — new registration id, same store.
            rolled = RuntimeRegistrationIdentity(
                registration_id=str(uuid.uuid4()),
                handler_identity=handler_identity,
                journal_store_id=identity.journal_store_id,
                journal_generation=str(int(identity.journal_generation) + 1),
            )
            save_identity(path, rolled)
            return rolled
        except Exception:  # noqa: BLE001
            logger.warning("runtime identity file unreadable; recreating", exc_info=True)

    identity = RuntimeRegistrationIdentity(
        registration_id=str(uuid.uuid4()),
        handler_identity=handler_identity,
        journal_store_id=str(uuid.uuid4()),
        journal_generation="1",
    )
    save_identity(path, identity)
    return identity


def save_identity(path: Path, identity: RuntimeRegistrationIdentity) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(
            {
                "version": 1,
                **identity.to_dict(),
                "updatedAt": _utc_now_rfc3339(datetime.now(timezone.utc)),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    tmp.chmod(0o600)
    tmp.replace(path)


def _utc_now_rfc3339(dt: datetime | None = None) -> str:
    """UTC timestamp for wire fields via stdlib ``datetime.isoformat``.

    Prefer this over a third-party RFC3339 package: CPython's ISO 8601
    output is the platform-standard form and matches Agent Gateway's
    ``time.RFC3339Nano`` parser when the offset is ``Z``.
    """
    when = dt if dt is not None else datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
