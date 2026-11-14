"""
Unit tests for Agent Bridge Security & Cryptographic Handshake
Verifies worker HMAC authentication, replay defense, invalid message rejection, and heartbeat handling.
"""

import asyncio
import json
import time
import unittest

from cloud_app.bridge_manager import BridgeManager
from shared.constants import AgentBridgeStatus
from shared.models import BridgeMessageType
from shared.security import compute_hmac, generate_token


class MockWebSocket:
    def __init__(self, incoming_messages: list):
        self.incoming = asyncio.Queue()
        for msg in incoming_messages:
            self.incoming.put_nowait(json.dumps(msg) if isinstance(msg, dict) else msg)
        self.outgoing = []
        self.closed = False
        self.close_code = None
        self.close_reason = None

    async def accept(self):
        pass

    async def receive_text(self):
        if self.closed:
            raise Exception("WebSocket closed")
        try:
            return await asyncio.wait_for(self.incoming.get(), timeout=2.0)
        except asyncio.TimeoutError:
            raise Exception("No more messages")

    async def send_text(self, text: str):
        self.outgoing.append(json.loads(text))

    async def close(self, code: int = 1000, reason: str = ""):
        self.closed = True
        self.close_code = code
        self.close_reason = reason


class MockTaskStore:
    def __init__(self):
        self.logs = []
        self.permissions = []
        self.statuses = []
        self.dispatches = []

    def get_dispatchable_tasks(self):
        return []

    async def append_logs(self, task_id, stdout_chunk, stderr_chunk, event):
        self.logs.append((task_id, stdout_chunk, stderr_chunk, event))

    async def set_pending_permission(self, task_id, perm_data):
        self.permissions.append((task_id, perm_data))

    async def mark_task_running(self, task_id, worker_id):
        self.statuses.append((task_id, "RUNNING", worker_id))

    async def finalize_task(self, task_id, final_status, exit_code, error):
        self.statuses.append((task_id, final_status, exit_code, error))


class TestBridgeSecurity(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.secret = "test_bridge_secret_key_123"
        self.task_store = MockTaskStore()
        self.bridge = BridgeManager(task_store=self.task_store, secret=self.secret)

    async def test_successful_worker_authentication(self):
        """Verifies valid HMAC signature, fresh timestamp, and unique nonce produces auth_ok."""
        worker_id = "worker_alpha"
        now = time.time()
        nonce = generate_token(16)
        sig = compute_hmac(self.secret, f"{worker_id}:{now}:{nonce}")

        auth_msg = {
            "type": BridgeMessageType.AUTH,
            "payload": {
                "worker_id": worker_id,
                "timestamp": now,
                "nonce": nonce,
                "signature": sig
            }
        }

        ws = MockWebSocket([auth_msg])
        authenticated_id = await self.bridge.authenticate_worker(ws)

        self.assertEqual(authenticated_id, worker_id)
        self.assertFalse(ws.closed)
        self.assertEqual(len(ws.outgoing), 1)
        self.assertEqual(ws.outgoing[0]["type"], BridgeMessageType.AUTH_OK)
        self.assertEqual(ws.outgoing[0]["payload"]["worker_id"], worker_id)

    async def test_invalid_signature_rejection(self):
        """Verifies invalid secret / signature is rejected with auth_fail and closed."""
        worker_id = "worker_alpha"
        now = time.time()
        nonce = generate_token(16)
        bad_sig = "fake_tampered_signature"

        auth_msg = {
            "type": BridgeMessageType.AUTH,
            "payload": {
                "worker_id": worker_id,
                "timestamp": now,
                "nonce": nonce,
                "signature": bad_sig
            }
        }

        ws = MockWebSocket([auth_msg])
        authenticated_id = await self.bridge.authenticate_worker(ws)

        self.assertIsNone(authenticated_id)
        self.assertTrue(ws.closed)
        self.assertEqual(ws.close_code, 1008)
        self.assertEqual(len(ws.outgoing), 1)
        self.assertEqual(ws.outgoing[0]["type"], BridgeMessageType.AUTH_FAIL)
        self.assertIn("Invalid signature", ws.outgoing[0]["payload"]["reason"])

    async def test_replay_attack_prevention(self):
        """Verifies identical nonce sent a second time is rejected as replay."""
        worker_id = "worker_alpha"
        now = time.time()
        nonce = "fixed_nonce_123456"
        sig = compute_hmac(self.secret, f"{worker_id}:{now}:{nonce}")

        auth_msg = {
            "type": BridgeMessageType.AUTH,
            "payload": {
                "worker_id": worker_id,
                "timestamp": now,
                "nonce": nonce,
                "signature": sig
            }
        }

        # First connection with this nonce succeeds
        ws1 = MockWebSocket([auth_msg])
        auth1 = await self.bridge.authenticate_worker(ws1)
        self.assertEqual(auth1, worker_id)

        # Second connection attempting to replay the same nonce fails
        ws2 = MockWebSocket([auth_msg])
        auth2 = await self.bridge.authenticate_worker(ws2)
        self.assertIsNone(auth2)
        self.assertTrue(ws2.closed)
        self.assertEqual(ws2.outgoing[0]["type"], BridgeMessageType.AUTH_FAIL)
        self.assertIn("Replay detected", ws2.outgoing[0]["payload"]["reason"])

    async def test_clock_drift_rejection(self):
        """Verifies stale timestamps exceeding TTL are rejected."""
        worker_id = "worker_alpha"
        stale_time = time.time() - 300.0  # 5 minutes in past
        nonce = generate_token(16)
        sig = compute_hmac(self.secret, f"{worker_id}:{stale_time}:{nonce}")

        auth_msg = {
            "type": BridgeMessageType.AUTH,
            "payload": {
                "worker_id": worker_id,
                "timestamp": stale_time,
                "nonce": nonce,
                "signature": sig
            }
        }

        ws = MockWebSocket([auth_msg])
        auth = await self.bridge.authenticate_worker(ws)
        self.assertIsNone(auth)
        self.assertTrue(ws.closed)
        self.assertEqual(ws.outgoing[0]["type"], BridgeMessageType.AUTH_FAIL)
        self.assertIn("exceeds TTL", ws.outgoing[0]["payload"]["reason"])

    async def test_heartbeat_ack_flow(self):
        """Verifies heartbeat messages are acknowledged and refresh worker liveness."""
        worker_id = "worker_beta"
        now = time.time()
        nonce = generate_token(16)
        sig = compute_hmac(self.secret, f"{worker_id}:{now}:{nonce}")

        auth_msg = {
            "type": BridgeMessageType.AUTH,
            "payload": {"worker_id": worker_id, "timestamp": now, "nonce": nonce, "signature": sig}
        }
        heartbeat_msg = {
            "type": BridgeMessageType.HEARTBEAT,
            "payload": {"worker_id": worker_id, "timestamp": time.time()}
        }

        ws = MockWebSocket([auth_msg, heartbeat_msg])
        
        # Run connection handler briefly
        task = asyncio.create_task(self.bridge.handle_connection(ws))
        await asyncio.sleep(0.1)

        self.assertEqual(self.bridge.status, AgentBridgeStatus.ONLINE)
        # Check outgoing messages: auth_ok followed by heartbeat_ack
        types = [m.get("type") for m in ws.outgoing]
        self.assertIn(BridgeMessageType.AUTH_OK, types)
        self.assertIn(BridgeMessageType.HEARTBEAT_ACK, types)

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    unittest.main()
