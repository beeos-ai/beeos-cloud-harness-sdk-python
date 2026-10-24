import unittest

from beeos_cloud_harness_sdk.chat_store_contract import (
    chat_append_digest, decode_native_chat_event, encode_native_chat_event,
)


class ChatStoreContractTest(unittest.TestCase):
    def request(self):
        return {
            "context": {"tenant_ref": "t", "scope_ref": "s", "authorization_revision": 1, "erasure_epoch": 0, "request_id": "q"},
            "session_id": "s1", "history_generation": "1", "branch_id": "main", "response_id": "r1", "attempt_id": "a1",
            "public_events": [{"type": "response.output", "metadata": {"2": "two", "10": "ten", "😀": "astral", "\ue000": "bmp"}, "text": "你好\n"}],
            "writer": {"writer_id": "w1", "writer_epoch": "7"}, "expected_watermark": "0", "operation_id": "op1", "idempotency_key": "k1",
            "events": [{"event_id": "native-1", "parent_id": None, "kind": "tool_result", "codec": {"name": "lossless", "version": "1"},
                        "content_b64": "AP/lt6Xlhbfwn5iA", "sha256": "2ae7304dff009a24a7c5e7fdcbb191169e3fff595c80cb65a3e38df378ca833e"}],
            "terminal": {"response_id": "r1", "status": "completed", "event_id": "native-1"},
        }

    def test_node_state_golden_digest(self):
        body = self.request()
        self.assertEqual(chat_append_digest(body), "88cfad72a4f0d23b8f66c27aa52b6f86a4ea43e7176b24fc73d865c0638627a2")
        body["context"]["request_id"] = "fresh"
        self.assertEqual(chat_append_digest(body), chat_append_digest(self.request()))
        body["attempt_id"] = "another-attempt"
        self.assertNotEqual(chat_append_digest(body), chat_append_digest(self.request()))

    def test_lossless_bytes_and_corruption(self):
        event = self.request()["events"][0]
        self.assertEqual(encode_native_chat_event(event_id=event["event_id"], parent_id=None, kind=event["kind"],
            codec=event["codec"], content=decode_native_chat_event(event)), event)
        with self.assertRaises(ValueError):
            decode_native_chat_event({**event, "sha256": "0" * 64})

    def test_no_inexact_envelope_numbers(self):
        for value in (0.5, 9007199254740992):
            with self.subTest(value=value), self.assertRaises(ValueError):
                chat_append_digest({**self.request(), "public_events": [{"size": value}]})
