"""Production BeeOS Harness SDK for custom agent harnesses (OpenClaw, Hermes, and others)."""
from __future__ import annotations
import json, urllib.error, urllib.parse, urllib.request
from collections.abc import Callable
from typing import Any, get_args

from ._generated.models import RuntimeMessagePatch, RuntimeMethod
from ._generated.operations import OPERATIONS, operation_path

RUNTIME_METHODS: list[str] = list(get_args(RuntimeMethod))

# Cloud chat delivers every user prompt as this runtime method. The bound reply
# row is pre-created by Cloud in `streaming`; the agent converges it.
CHAT_PROMPT_METHOD = "session/prompt"

class BeeOSAgentError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code = status, code

class BeeOSAgentRuntime:
    def __init__(self, agent_gateway_url: str, message_service_url: str, instance_id: str, agent_id: str, token: str | Callable[[], str], framework: str = "custom", transport=None):
        if not all([agent_gateway_url, message_service_url, instance_id, agent_id, token]):
            raise ValueError("agent runtime requires gateway, message service, instance, agent and token")
        self.agent_gateway_url = agent_gateway_url.rstrip("/") + "/"
        self.message_service_url = message_service_url.rstrip("/") + "/"
        self.instance_id = instance_id
        self.agent_id = agent_id
        self._token = token
        self.framework = framework
        self._transport = transport
        self._closed = False
        self.on_chat_message = None
        self.on_chat_cancel = None
        self.on_runtime_method = None
        self.agent = _Agent(self)
        self.messages = _Messages(self)
        self.chat = _Chat(self)
        self.files = _Files(self)
        self.canvas = _Canvas(self)
        self.a2a = _A2a(self)
        self.messaging = _Messaging(self)

    def token(self) -> str:
        return self._token() if callable(self._token) else self._token

    def register(self, *, on_chat_message=None, on_chat_cancel=None, on_runtime_method=None):
        self.on_chat_message = on_chat_message
        self.on_chat_cancel = on_chat_cancel
        self.on_runtime_method = on_runtime_method

    def request(self, base: str, method: str, path: str, json_body=None, headers=None):
        if self._closed:
            raise BeeOSAgentError(409, "runtime_closed", "BeeOSAgentRuntime is closed")
        root = self.agent_gateway_url if base == "gateway" else self.message_service_url
        url = urllib.parse.urljoin(root, path.lstrip("/"))
        key = self.token()
        req_headers = {
            "Authorization": key if " " in key else f"Bearer {key}",
            "Accept": "application/json",
            "X-BeeOS-Instance-ID": self.instance_id,
            "X-BeeOS-Agent-ID": self.agent_id,
        }
        if headers:
            req_headers.update(headers)
        data = None
        if json_body is not None:
            req_headers["Content-Type"] = "application/json"
            data = json.dumps(json_body).encode()
        if self._transport:
            status, raw, _resp = self._transport(method, url, req_headers, data)
            if status >= 400:
                raise BeeOSAgentError(status, "agent_backend_unavailable", raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw))
            if status == 204 or not raw:
                return None
            return json.loads(raw)
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                if resp.status == 204 or not raw:
                    return None
                return json.loads(raw.decode())
        except urllib.error.HTTPError as err:
            payload = err.read().decode()
            code, message = "agent_backend_unavailable", err.reason
            try:
                parsed = json.loads(payload)
                code, message = parsed.get("code", code), parsed.get("message", message)
            except Exception:
                pass
            raise BeeOSAgentError(err.code, code, message) from err

    def _call(self, operation_id: str, json_body=None, headers=None, **path_params):
        method, _path, service = OPERATIONS[operation_id]
        base = "gateway" if service == "agent-gateway" else "message"
        return self.request(base, method, operation_path(operation_id, **path_params), json_body, headers)

    def dispatch_chat_message(self, event: dict):
        if self.on_chat_message:
            return self.on_chat_message(event)

    def dispatch_chat_cancel(self, event: dict):
        if self.on_chat_cancel:
            return self.on_chat_cancel(event)

    def dispatch_runtime_method(self, method: str, params: dict | None = None):
        if method not in RUNTIME_METHODS:
            raise BeeOSAgentError(400, "unsupported_runtime_method", method)
        if method == CHAT_PROMPT_METHOD and not self.on_runtime_method:
            return self.dispatch_session_prompt(params or {})
        if not self.on_runtime_method:
            raise BeeOSAgentError(501, "runtime_method_unhandled", method)
        return self.on_runtime_method(method, params or {})

    def dispatch_session_prompt(self, params: dict):
        """Cloud chat prompt -> the agent's chat handler (same event shape)."""
        prompt = extract_session_prompt(params, self.agent_id)
        if prompt is None:
            raise BeeOSAgentError(400, "invalid_session_prompt", CHAT_PROMPT_METHOD)
        return self.dispatch_chat_message(prompt)

    def consume_envelope(self, envelope: dict):
        kind = envelope.get("type") or (envelope.get("message") or {}).get("type") or ""
        if kind == "chat_cancel":
            content = envelope.get("content") or {}
            return self.dispatch_chat_cancel({
                "conversationId": envelope.get("conversationId") or envelope.get("conversation_id") or "",
                "targetMessageId": envelope.get("replyTo") or envelope.get("reply_to") or content.get("target_message_id") or "",
                "agentId": self.agent_id,
            })
        prompt = extract_chat_prompt(envelope, self.agent_id)
        if not prompt or not prompt.get("messageId") or not prompt.get("channelId"):
            return None
        return self.dispatch_chat_message({
            "conversationId": prompt["channelId"],
            "messageId": prompt["messageId"],
            "agentId": self.agent_id,
            "text": prompt["message"],
            "channelId": prompt["channelId"],
            "sessionKey": prompt.get("sessionKey"),
            "files": prompt.get("files") or [],
        })

    def close(self):
        self._closed = True
        self.on_chat_message = self.on_chat_cancel = self.on_runtime_method = None

def extract_chat_prompt(envelope: dict, local_agent_id: str = "") -> dict | None:
    inner = envelope.get("message") or envelope
    content = inner.get("content") or {}
    if not isinstance(content, dict):
        content = {}
    text = content.get("message") or envelope.get("body") or ""
    if not text and isinstance(content.get("parts"), list):
        text = "\n".join(part.get("text", "") for part in content["parts"] if isinstance(part, dict) and part.get("type") == "text")
    if not text:
        return None
    channel_id = inner.get("conversationId") or envelope.get("conversationId") or envelope.get("conversation_id") or content.get("channel_id")
    context_id = content.get("context_id") or (content.get("metadata") or {}).get("context_id")
    message_id = inner.get("id") or envelope.get("id")
    source = "a2a" if inner.get("type") == "agent_request" or envelope.get("type") == "agent_request" else "invoke"
    session_key = content.get("session_key") or f"agent:{local_agent_id}:{source}:{'ctx-' + context_id if context_id else 'ch-' + channel_id if channel_id else 'anon'}"
    files = [item for item in (content.get("files") or []) if isinstance(item, str)]
    if isinstance(content.get("parts"), list):
        files.extend(part.get("file_url") for part in content["parts"] if isinstance(part, dict) and part.get("file_url"))
    return {"message": text, "files": [item for item in files if item], "channelId": channel_id, "contextId": context_id, "sessionKey": session_key, "messageId": message_id}

def extract_session_prompt(params: dict, local_agent_id: str = "") -> dict | None:
    """Normalize Cloud chat ``session/prompt`` params into a chat event.

    Returns None when the task binding Cloud guarantees is incomplete, so the
    caller fails the operation instead of writing to an unbound reply row.
    """
    if not isinstance(params, dict):
        return None
    conversation_id = str(params.get("conversationId") or "")
    reply_message_id = str(params.get("replyMessageId") or "")
    message_id = str(params.get("taskRequestMessageId") or "")
    run_id = str(params.get("runtimeRunId") or params.get("taskId") or "")
    if not conversation_id or not reply_message_id or not message_id or not run_id:
        return None
    raw_parts = params.get("parts") if isinstance(params.get("parts"), list) else []
    parts = [part for part in raw_parts if isinstance(part, dict)]
    text = "\n".join(str(part.get("text") or "") for part in parts if part.get("type") == "text").strip()
    files = [str(part["blobRef"]) for part in parts if part.get("blobRef")]
    agent_id = str(params.get("platformAgentId") or local_agent_id)
    return {
        "conversationId": conversation_id,
        "channelId": conversation_id,
        "messageId": message_id,
        "replyMessageId": reply_message_id,
        "runtimeRunId": run_id,
        "agentId": agent_id,
        "text": text,
        "files": files,
        "modelOverrideId": str(params.get("modelOverrideId") or "") or None,
        "sessionKey": f"agent:{agent_id}:cloud-chat:ch-{conversation_id}",
    }


class _Chat:
    """Cloud chat reply convergence over the current runtime lease."""

    def __init__(self, runtime: BeeOSAgentRuntime):
        self.runtime = runtime

    def patch_reply(self, conversation_id: str, reply_message_id: str, body: RuntimeMessagePatch, operation_key: str = ""):
        if not conversation_id or not reply_message_id:
            raise BeeOSAgentError(400, "invalid_chat_reply", "chat reply requires conversationId and replyMessageId")
        headers = {"Idempotency-Key": operation_key} if operation_key else None
        return self.runtime._call("runtimeConversationMessagePatch", body, headers, conversationId=conversation_id, messageId=reply_message_id)

    def complete_reply(self, conversation_id: str, reply_message_id: str, text: str, operation_key: str = ""):
        return self.patch_reply(
            conversation_id, reply_message_id,
            {"body": text, "parts": [{"type": "text", "text": text}], "state": "completed", "stop_reason": "end_turn"},
            operation_key)

    def fail_reply(self, conversation_id: str, reply_message_id: str, text: str = "", operation_key: str = ""):
        return self.patch_reply(
            conversation_id, reply_message_id,
            {"body": text, "state": "failed", "stop_reason": "error"},
            operation_key)


class _Agent:
    def __init__(self, runtime: BeeOSAgentRuntime):
        self.runtime = runtime
    def get(self):
        return self.runtime._call("agentGet", agentId=self.runtime.agent_id)
    def update_exposure(self, patch, resource_version):
        return self.runtime._call("agentUpdate", patch, {"If-Match": f'"{resource_version}"'}, agentId=self.runtime.agent_id)
    def sync(self, input):
        return self.runtime._call("agentSync", input)

class _Messages:
    def __init__(self, runtime: BeeOSAgentRuntime):
        self.runtime = runtime
    def send(self, conversation_id, input):
        return self.runtime._call("conversationMessageSend", input, conversationId=conversation_id)
    def reply(self, conversation_id: str, inbound_message_id: str, text: str):
        if not conversation_id or not inbound_message_id:
            raise BeeOSAgentError(400, "invalid_agent_reply", "agent_reply requires conversationId and inbound messageId")
        return self.send(conversation_id, {"type": "agent_reply", "replyTo": inbound_message_id, "reply_to": inbound_message_id, "content": {"text": text}, "sender": self.runtime.instance_id})
    def list(self, conversation_id):
        return self.runtime._call("conversationMessagesList", conversationId=conversation_id)
    def consume_envelope(self, envelope: dict):
        return self.runtime.consume_envelope(envelope)

class _Files:
    def __init__(self, runtime: BeeOSAgentRuntime):
        self.runtime = runtime
    def list(self):
        return self.runtime._call("agentFilesList")
    def presign(self, input):
        return self.runtime._call("agentFilePresign", input)
    def confirm(self, input):
        return self.runtime._call("agentFileConfirm", input)
    def resolve(self, file_id):
        return self.runtime._call("agentFileResolve", fileId=file_id)

class _Canvas:
    def __init__(self, runtime: BeeOSAgentRuntime):
        self.runtime = runtime
    def token(self, input=None):
        return self.runtime._call("canvasTokenCreate", input if input is not None else {})

class _A2a:
    def __init__(self, runtime: BeeOSAgentRuntime):
        self.runtime = runtime
    def discover(self):
        return self.runtime._call("a2aDiscover")
    def call(self, agent_id, input):
        return self.runtime._call("a2aJsonRpc", input, agentId=agent_id)
    def get_task(self, task_id):
        return self.runtime._call("a2aTaskGet", taskId=task_id)

class _Messaging:
    def __init__(self, runtime: BeeOSAgentRuntime):
        self.runtime = runtime
    def token(self, input=None):
        return self.runtime._call("messagingTokenCreate", input if input is not None else {})
