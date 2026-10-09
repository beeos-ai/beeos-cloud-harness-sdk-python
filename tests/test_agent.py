import unittest
from beeos_cloud_harness_sdk import (
    BeeOSAgentRuntime,
    CHAT_PROMPT_METHOD,
    RUNTIME_METHODS,
    extract_chat_prompt,
    extract_session_prompt,
)

class AgentTests(unittest.TestCase):
    def test_envelope_inbound_methods_and_gateway_paths(self):
        calls = []
        def transport(method, url, headers, data):
            calls.append((method, url, data.decode() if data else None))
            if "/messages" in url:
                return 200, b'{"id":"m_reply"}', {}
            return 200, b'{"id":"agt_1"}', {}
        runtime = BeeOSAgentRuntime("https://agent.example/", "https://message.example/", "inst_1", "agt_1", "rt_test", transport=transport)
        seen = []
        runtime.register(on_chat_message=lambda event: seen.append(event["text"]), on_runtime_method=lambda method, params: {"method": method, "params": params})
        runtime.consume_envelope({"type": "chat_message", "id": "m1", "conversationId": "c1", "content": {"message": "hi", "channel_id": "c1"}})
        runtime.consume_envelope({"message": {"type": "chat_message", "id": "m2", "conversationId": "c2", "content": {"message": "nested"}}})
        inbound = runtime.dispatch_runtime_method("models/list", {})
        reply = runtime.messages.reply("c1", "m1", "hello")
        runtime.files.list()
        runtime.a2a.discover()
        self.assertEqual(seen, ["hi", "nested"])
        self.assertEqual(inbound["method"], "models/list")
        self.assertEqual(reply["id"], "m_reply")
        self.assertFalse(any("runtime/rpc" in url for _, url, _ in calls))
        self.assertTrue(any("/api/v1/agent/files" in url for _, url, _ in calls))
        self.assertTrue(any("/api/v1/a2a/discover" in url for _, url, _ in calls))
        self.assertEqual(len(RUNTIME_METHODS), 29)
        prompt = extract_chat_prompt({"type": "chat_message", "id": "m9", "conversationId": "conv", "content": {"message": "invoice"}}, "agt_1")
        self.assertEqual(prompt["message"], "invoice")
        with self.assertRaises(Exception):
            runtime.dispatch_runtime_method("invoke/stream", {})

    def test_cloud_chat_prompt_dispatch_and_reply_convergence(self):
        calls = []
        def transport(method, url, headers, data):
            calls.append((method, url, headers, data.decode() if data else None))
            return 200, b'{"id":"reply_1","state":"completed"}', {}
        runtime = BeeOSAgentRuntime("https://agent.example/", "https://message.example/", "inst_1", "agt_1", "lease_cred", transport=transport)
        seen = []
        runtime.register(on_chat_message=lambda event: seen.append(event))
        params = {
            "conversationId": "conv_1", "replyMessageId": "cloud-chat-reply:task_1",
            "taskRequestMessageId": "req_1", "taskId": "task_1", "runtimeRunId": "task_1",
            "platformAgentId": "agt_1", "inputFingerprint": "f" * 64,
            "parts": [{"type": "text", "text": "ping"}, {"type": "file", "blobRef": "blob_1"}],
            "runtimeLease": {"runtimeEpoch": "3", "leaseId": "l1", "journalStoreId": "j1", "journalGeneration": "1"},
        }
        runtime.dispatch_runtime_method(CHAT_PROMPT_METHOD, params)
        self.assertEqual(seen[0]["text"], "ping")
        self.assertEqual(seen[0]["replyMessageId"], "cloud-chat-reply:task_1")
        self.assertEqual(seen[0]["files"], ["blob_1"])
        runtime.chat.complete_reply("conv_1", "cloud-chat-reply:task_1", "pong", "task_1")
        method, url, headers, data = calls[-1]
        self.assertEqual(method, "PATCH")
        self.assertEqual(url, "https://message.example/api/v1/runtime/conversations/conv_1/messages/cloud-chat-reply%3Atask_1")
        self.assertEqual(headers["Authorization"], "Bearer lease_cred")
        self.assertEqual(headers["Idempotency-Key"], "task_1")
        self.assertIn('"state": "completed"', data)
        self.assertIn('"stop_reason": "end_turn"', data)
        self.assertIsNone(extract_session_prompt({"conversationId": "conv_1"}))

    def test_facade_routes_come_from_the_spec_route_table(self):
        calls = []
        def transport(method, url, headers, data):
            calls.append((method, url))
            return 200, b'{}', {}
        runtime = BeeOSAgentRuntime("https://agent.example/", "https://message.example/", "inst_1", "agt/1", "rt", transport=transport)
        runtime.agent.get()
        runtime.agent.update_exposure({}, "7")
        runtime.agent.sync({})
        runtime.messages.send("c 1", {})
        runtime.messages.list("c1")
        runtime.files.list()
        runtime.files.presign({})
        runtime.files.confirm({})
        runtime.files.resolve("f1")
        runtime.canvas.token()
        runtime.a2a.discover()
        runtime.a2a.call("agt_2", {})
        runtime.a2a.get_task("t1")
        runtime.messaging.token()
        runtime.chat.fail_reply("c1", "r1")
        self.assertEqual(calls, [
            ("GET", "https://agent.example/api/v1/agents/agt%2F1"),
            ("PATCH", "https://agent.example/api/v1/agents/agt%2F1"),
            ("POST", "https://agent.example/api/v1/agents/sync"),
            ("POST", "https://message.example/api/v2/conversations/c%201/messages"),
            ("GET", "https://message.example/api/v2/conversations/c1/messages"),
            ("GET", "https://agent.example/api/v1/agent/files"),
            ("POST", "https://agent.example/api/v1/agent/files/presign"),
            ("POST", "https://agent.example/api/v1/agent/files/confirm"),
            ("GET", "https://agent.example/api/v1/agent/files/f1/resolve"),
            ("POST", "https://agent.example/api/v1/canvas/token"),
            ("GET", "https://agent.example/api/v1/a2a/discover"),
            ("POST", "https://agent.example/api/v1/a2a/agt_2/jsonrpc"),
            ("GET", "https://agent.example/api/v1/a2a/tasks/t1"),
            ("POST", "https://agent.example/api/v1/messaging/token"),
            ("PATCH", "https://message.example/api/v1/runtime/conversations/c1/messages/r1"),
        ])

if __name__ == "__main__":
    unittest.main()
