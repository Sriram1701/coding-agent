"""
Unit tests for Cloud Task Queue, Persistence, and Offline Dispatch
Verifies offline task queuing, reconnection dispatch, rejection, cancellation, and duplicate prevention.
"""

import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest

from cloud_app.bridge_manager import BridgeManager
from cloud_app.task_store import CloudTaskStore
from shared.constants import TaskStatus
from shared.models import BridgeMessageType


class MockDispatchWebSocket:
    def __init__(self):
        self.outgoing = []
        self.closed = False

    async def accept(self):
        pass

    async def send_text(self, text: str):
        self.outgoing.append(json.loads(text))

    async def close(self, code: int = 1000, reason: str = ""):
        self.closed = True


class TestTaskQueueAndDispatch(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_file = Path(self.temp_dir.name) / "test_tasks.json"
        self.task_store = CloudTaskStore(storage_path=self.storage_file)
        self.bridge = BridgeManager(task_store=self.task_store, secret="test_secret")

    async def asyncTearDown(self):
        self.temp_dir.cleanup()

    async def test_offline_task_submission_and_queuing(self):
        """Verifies tasks submitted while worker is offline are stored in PENDING_APPROVAL and QUEUED upon approval."""
        self.assertFalse(self.bridge.is_connected)

        # 1. Submit task
        task = await self.task_store.submit_task(
            prompt="Refactor authentication layer",
            workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
            agent="antigravity",
            user="admin"
        )
        task_id = task["id"]
        self.assertEqual(task["status"], TaskStatus.PENDING_APPROVAL)

        # 2. Approve task while worker is offline
        approved_task = await self.task_store.approve_task(task_id, user="admin")
        self.assertEqual(approved_task["status"], TaskStatus.QUEUED)

        # 3. Verify task is queued in dispatch list
        dispatchable = self.task_store.get_dispatchable_tasks()
        self.assertEqual(len(dispatchable), 1)
        self.assertEqual(dispatchable[0]["id"], task_id)

    async def test_task_dispatch_upon_worker_reconnection(self):
        """Verifies that queued tasks are automatically dispatched when a worker connects."""
        task = await self.task_store.submit_task(
            prompt="Add unit tests",
            workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
            user="admin"
        )
        task_id = task["id"]
        await self.task_store.approve_task(task_id, user="admin")

        # Simulate worker connecting
        ws = MockDispatchWebSocket()
        self.bridge._active_websocket = ws
        self.bridge._active_worker_id = "win_worker_1"

        await self.bridge.dispatch_queued_tasks()

        # Check that TASK_DISPATCH message was sent over WebSocket
        self.assertEqual(len(ws.outgoing), 1)
        dispatch_msg = ws.outgoing[0]
        self.assertEqual(dispatch_msg["type"], BridgeMessageType.TASK_DISPATCH)
        self.assertEqual(dispatch_msg["payload"]["task_id"], task_id)

        # Verify task transitioned to RUNNING
        t = self.task_store.get_task(task_id)
        self.assertEqual(t["status"], TaskStatus.RUNNING)

    async def test_duplicate_approval_prevention(self):
        """Verifies duplicate approvals on already approved or queued tasks are rejected."""
        task = await self.task_store.submit_task(
            prompt="Test prompt",
            workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
            user="admin"
        )
        task_id = task["id"]
        await self.task_store.approve_task(task_id, user="admin")

        # Second approval attempt should raise ValueError
        with self.assertRaises(ValueError) as ctx:
            await self.task_store.approve_task(task_id, user="admin")
        self.assertIn("Only tasks in PENDING_APPROVAL can be approved", str(ctx.exception))

    async def test_task_rejection_lifecycle(self):
        """Verifies rejected tasks cannot be approved or dispatched."""
        task = await self.task_store.submit_task(
            prompt="Malicious or unwanted prompt",
            workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
            user="admin"
        )
        task_id = task["id"]

        rejected = await self.task_store.reject_task(task_id, reason="Security review failed", user="admin")
        self.assertEqual(rejected["status"], TaskStatus.REJECTED)
        self.assertEqual(rejected["error"], "Security review failed")

        # Attempting to approve rejected task fails
        with self.assertRaises(ValueError):
            await self.task_store.approve_task(task_id, user="admin")

        # Must not be dispatchable
        self.assertEqual(len(self.task_store.get_dispatchable_tasks()), 0)

    async def test_task_cancellation_lifecycle(self):
        """Verifies cancelling an active task marks it CANCELLED and sends TASK_CANCEL message."""
        task = await self.task_store.submit_task(
            prompt="Long running job",
            workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
            user="admin"
        )
        task_id = task["id"]
        await self.task_store.approve_task(task_id, user="admin")

        ws = MockDispatchWebSocket()
        self.bridge._active_websocket = ws
        self.bridge._active_worker_id = "win_worker_1"

        await self.task_store.cancel_task(task_id, user="admin")
        await self.bridge.forward_task_cancel(task_id)

        t = self.task_store.get_task(task_id)
        self.assertEqual(t["status"], TaskStatus.CANCELLED)

        # Check cancel message forwarded
        cancels = [m for m in ws.outgoing if m.get("type") == BridgeMessageType.TASK_CANCEL]
        self.assertEqual(len(cancels), 1)
        self.assertEqual(cancels[0]["payload"]["task_id"], task_id)

    def test_default_storage_path(self):
        """Verifies storage_path defaults to data/tasks.json when no env or arg provided."""
        old_env = os.environ.pop("ACH_STORAGE_PATH", None)
        try:
            store = CloudTaskStore()
            expected_default = Path("data/tasks.json").resolve()
            self.assertEqual(store.storage_path, expected_default)
        finally:
            if old_env is not None:
                os.environ["ACH_STORAGE_PATH"] = old_env

    async def test_custom_storage_path_from_env(self):
        """Verifies ACH_STORAGE_PATH environment variable correctly configures storage location."""
        custom_file = Path(self.temp_dir.name) / "custom_dir" / "custom_tasks.json"
        old_env = os.environ.get("ACH_STORAGE_PATH")
        os.environ["ACH_STORAGE_PATH"] = str(custom_file)
        try:
            store = CloudTaskStore()
            self.assertEqual(store.storage_path, custom_file.resolve())

            # Submit task and verify custom file was created
            task = await store.submit_task(
                prompt="Task in custom storage",
                workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
                user="admin"
            )
            self.assertTrue(custom_file.exists())
            self.assertTrue(custom_file.parent.exists())
        finally:
            if old_env is not None:
                os.environ["ACH_STORAGE_PATH"] = old_env
            else:
                os.environ.pop("ACH_STORAGE_PATH", None)

    async def test_task_persistence_after_restart(self):
        """Verifies tasks and approval states survive a server restart when persisted."""
        custom_file = Path(self.temp_dir.name) / "restart_test" / "tasks.json"

        # 1. Instance 1 writes task
        store1 = CloudTaskStore(storage_path=custom_file)
        task = await store1.submit_task(
            prompt="Task to survive restart",
            workspace=r"C:\Users\lovel\Desktop\AI-CODING-HUB",
            user="admin"
        )
        task_id = task["id"]
        await store1.approve_task(task_id, user="admin")
        self.assertEqual(store1.get_task(task_id)["status"], TaskStatus.QUEUED)

        # 2. Instance 2 simulates server reboot
        store2 = CloudTaskStore(storage_path=custom_file)
        reloaded = store2.get_task(task_id)

        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded["id"], task_id)
        self.assertEqual(reloaded["status"], TaskStatus.QUEUED)
        self.assertEqual(reloaded["approved_by"], "admin")
        self.assertIn("Task to survive restart", reloaded["prompt"])
        self.assertEqual(len(store2.get_dispatchable_tasks()), 1)


if __name__ == "__main__":
    unittest.main()
