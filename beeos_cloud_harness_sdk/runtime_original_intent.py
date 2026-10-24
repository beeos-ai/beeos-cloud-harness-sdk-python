"""Current-lease read/renewal of the owner's immutable original native carrier."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from .jcs import verify_native_session_request

if TYPE_CHECKING:
    from . import BeeOSAgentRuntime
    from .registration import RuntimeActiveLease

RUNTIME_ORIGINAL_INTENT_ROUTE = "/api/v1/runtime/execution/original-intent"
_DIGEST = re.compile(r"[a-f0-9]{64}")


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("original authority timestamp is required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("original authority timestamp requires a timezone")
    return result


class RuntimeOriginalIntent:
    """No body persistence/retry. The native caller verifies the returned JWT."""

    def __init__(self, runtime: BeeOSAgentRuntime) -> None:
        self._runtime = runtime

    def read(self, lease: RuntimeActiveLease, locator: dict[str, str]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        body = {key: locator.get(key) for key in
                ("operation_id", "request_message_id", "native_request_hash")}
        if (not lease.runtime_lease_credential or self._runtime.token() != lease.runtime_lease_credential
                or self._runtime.instance_id != lease.instance_id or _time(lease.lease_expires_at) <= now
                or any(not isinstance(value, str) or not value for value in body.values())
                or not _DIGEST.fullmatch(body["native_request_hash"])):
            raise ValueError("current lease and exact original execution locator are required")
        raw = self._runtime.request("gateway", "POST", RUNTIME_ORIGINAL_INTENT_ROUTE, body)
        if not isinstance(raw, dict) or not isinstance(raw.get("request"), dict) or not isinstance(raw.get("lease"), dict):
            raise ValueError("original execution authority returned an invalid envelope")
        request, actual = raw["request"], raw["lease"]
        expected_lease = {"instance_id": lease.instance_id, "lease_id": lease.lease_id,
                          "handler_identity": lease.handler_identity, "runtime_epoch": lease.runtime_epoch}
        grant_expiry = _time(raw.get("execution_grant_expires_at"))
        subject = request.get("cloudSubject")
        if (not isinstance(raw.get("execution_grant"), str) or not raw["execution_grant"]
                or not isinstance(raw.get("public_request_hash"), str)
                or not _DIGEST.fullmatch(raw["public_request_hash"])
                or raw.get("native_request_hash") != body["native_request_hash"]
                or verify_native_session_request(request) != body["native_request_hash"]
                or request.get("operationId") != body["operation_id"]
                or request.get("requestMessageId") != body["request_message_id"]
                or request.get("schemaVersion") != 2 or request.get("authorityRealm") != "cloud"
                or any(actual.get(key) != value for key, value in expected_lease.items())
                or request.get("instanceId") != lease.instance_id or request.get("leaseId") != lease.lease_id
                or request.get("runtimeHandlerIdentity") != lease.handler_identity
                or request.get("dispatchEpoch") != lease.runtime_epoch
                or not isinstance(subject, dict) or subject.get("instanceId") != lease.instance_id
                or not now < grant_expiry <= _time(lease.lease_expires_at)
                or grant_expiry > _time(request.get("executionDeadlineAt"))):
            raise ValueError("original execution authority changed the retained request or current lease")
        return raw
