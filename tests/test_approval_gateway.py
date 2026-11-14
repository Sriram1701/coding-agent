"""
Unit tests for Mandatory Approval Gateway & Default-Deny Security
Verifies task-level approval, per-action authorization, default-deny enforcement,
and tamper-evident permission audit logging.
"""

import asyncio
from pathlib import Path
import tempfile
import unittest

from cloud_app.bridge_manager import BridgeManager
from cloud_app.task_store import CloudTaskStore
from shared.constants import DecisionType, TaskStatus
from shared.models import BridgeMessageType


class MockApprovalWebSocket:
    def __init__(self):
        self.outgoing = []

    async def send_text(self, text: str):
        import json
        self.outgoing.append(json.loads(text))


class TestApprovalGateway(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_file = Path(self.temp_dir.name) / "test_tasks.json"
        self.task_store = CloudTaskStore(storage_path=self.storage_file)
        self.bridge = BridgeManager(task_store=self.task_store, secret="test_secret")

        # Create active task
        self.task = await self.task_store.submit_task(
            prompt="Write security report",
            workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
            user="alice"
        )
        self.task_id = self.task["id"]
        await self.task_store.approve_task(self.task_id, user="alice")
        await self.task_store.mark_task_running(self.task_id, worker_id="win_worker_1")

    async def asyncTearDown(self):
        self.temp_dir.cleanup()

    async def test_sensitive_action_request_transitions_status(self):
        """Verifies runner requesting permission pauses task into AWAITING_ACTION_APPROVAL."""
        perm_data = {
            "permission_id": "perm_001",
            "tool_call_id": "tc_edit_1",
            "title": "Edit main.py",
            "kind": "edit_file",
            "tool_call": {"file": "main.py", "lines": "1-10"}
        }

        updated = await self.task_store.set_pending_permission(self.task_id, perm_data)
        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], TaskStatus.AWAITING_ACTION_APPROVAL)
        self.assertEqual(updated["pending_permission"]["permission_id"], "perm_001")

    async def test_human_approval_allow_once(self):
        """Verifies allow_once decision resumes task to RUNNING and logs decision with user identity."""
        perm_data = {
            "permission_id": "perm_002",
            "tool_call_id": "tc_cmd_1",
            "title": "Execute git commit",
            "kind": "run_command",
            "tool_call": {"command": "git commit -m 'test'"}
        }
        await self.task_store.set_pending_permission(self.task_id, perm_data)

        # Mock bridge connection
        ws = MockApprovalWebSocket()
        self.bridge._active_websocket = ws
        self.bridge._active_worker_id = "win_worker_1"

        resolved = await self.task_store.resolve_task_permission(
            self.task_id, decision=DecisionType.ALLOW_ONCE, user="alice"
        )
        await self.bridge.forward_permission_decision(self.task_id, "perm_002", DecisionType.ALLOW_ONCE)

        self.assertEqual(resolved["status"], TaskStatus.RUNNING)
        self.assertIsNone(resolved["pending_permission"])

        # Check permission audit trail
        history = resolved["permission_history"]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["permission_id"], "perm_002")
        self.assertEqual(history[0]["decision"], DecisionType.ALLOW_ONCE)
        self.assertEqual(history[0]["decided_by"], "alice")

        # Verify bridge message forwarded to worker
        self.assertEqual(len(ws.outgoing), 1)
        self.assertEqual(ws.outgoing[0]["type"], BridgeMessageType.PERMISSION_DECISION)
        self.assertEqual(ws.outgoing[0]["payload"]["decision"], DecisionType.ALLOW_ONCE)

    async def test_human_rejection_reject_once(self):
        """Verifies reject_once decision denies the action and records denial in audit history."""
        perm_data = {
            "permission_id": "perm_003",
            "tool_call_id": "tc_del_1",
            "title": "Delete config.json",
            "kind": "delete_file",
            "tool_call": {"file": "config.json"}
        }
        await self.task_store.set_pending_permission(self.task_id, perm_data)

        resolved = await self.task_store.resolve_task_permission(
            self.task_id, decision=DecisionType.REJECT_ONCE, user="security_admin"
        )

        self.assertEqual(resolved["status"], TaskStatus.RUNNING)
        self.assertEqual(resolved["permission_history"][-1]["decision"], DecisionType.REJECT_ONCE)
        self.assertEqual(resolved["permission_history"][-1]["decided_by"], "security_admin")

    async def test_default_deny_on_invalid_decision(self):
        """Verifies that non-standard decisions (like bypass, auto, allow_all) are strictly rejected."""
        perm_data = {
            "permission_id": "perm_004",
            "tool_call_id": "tc_write_1",
            "title": "Overwrite database",
            "kind": "write_file",
            "tool_call": {}
        }
        await self.task_store.set_pending_permission(self.task_id, perm_data)

        # Disallowed decisions must raise ValueError
        invalid_decisions = ["allow_all", "bypass", "auto_approve", "yes", "true", ""]
        for bad_dec in invalid_decisions:
            with self.assertRaises(ValueError) as ctx:
                await self.task_store.resolve_task_permission(self.task_id, decision=bad_dec, user="alice")
            self.assertIn("Invalid decision", str(ctx.exception))

    async def test_permission_resolution_guard_when_not_pending(self):
        """Verifies resolving a permission on a task not in AWAITING_ACTION_APPROVAL raises an error."""
        # Task is in RUNNING, no pending permission
        with self.assertRaises(ValueError) as ctx:
            await self.task_store.resolve_task_permission(self.task_id, decision=DecisionType.ALLOW_ONCE, user="alice")
        self.assertIn("not currently awaiting action approval", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
