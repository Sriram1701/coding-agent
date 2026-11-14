"""
AI CODING HUB - Phase 1 ACP Security & Lifecycle Test Suite
Verifies all mandatory security constraints, ACP protocol lifecycle,
human-in-the-loop action approval gating, timeout management, and log preservation.
"""

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

from task_manager import TaskManager, TaskStatus, AUTHORIZED_WORKSPACE


class Phase1ACPSecurityTests(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        # Create an isolated temporary task store for tests
        self.test_data_dir = AUTHORIZED_WORKSPACE / "data" / "test"
        self.test_data_dir.mkdir(parents=True, exist_ok=True)
        self.test_store_file = self.test_data_dir / "test_tasks.json"
        if self.test_store_file.exists():
            self.test_store_file.unlink()

        self.manager = TaskManager(storage_path=self.test_store_file)
        self.acp_invocations = []
        self.acp_executed_actions = []

    async def asyncTearDown(self):
        if self.test_store_file.exists():
            self.test_store_file.unlink()
        try:
            self.test_data_dir.rmdir()
        except Exception:
            pass

    async def test_01_task_submission_creates_pending_approval(self):
        """Condition 1: Task submission must strictly create PENDING_APPROVAL state."""
        task = await self.manager.submit_task(
            prompt="Refactor health route logging",
            workspace=str(AUTHORIZED_WORKSPACE)
        )
        self.assertIn("id", task)
        self.assertEqual(task["status"], TaskStatus.PENDING_APPROVAL)
        self.assertIsNone(task["approved_at"])
        self.assertIsNone(task["executed_at"])
        self.assertIsNone(task["pending_permission"])

    async def test_02_submitting_task_does_not_launch_acp(self):
        """Condition 2: Submitting a task must NEVER launch ACP agent."""
        async def mock_handler(task, manager):
            self.acp_invocations.append(task["id"])

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task(
            prompt="Analyze dependencies",
            workspace=str(AUTHORIZED_WORKSPACE)
        )
        await asyncio.sleep(0.1)

        self.assertEqual(len(self.acp_invocations), 0)
        self.assertEqual(task["status"], TaskStatus.PENDING_APPROVAL)

    async def test_03_rejecting_task_does_not_launch_acp(self):
        """Condition 3: Rejecting a task must NEVER launch ACP agent."""
        async def mock_handler(task, manager):
            self.acp_invocations.append(task["id"])

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task(
            prompt="Delete cache files",
            workspace=str(AUTHORIZED_WORKSPACE)
        )
        rejected = await self.manager.reject_task(task["id"], reason="Unnecessary task")
        self.assertEqual(rejected["status"], TaskStatus.REJECTED)

        await asyncio.sleep(0.1)
        self.assertEqual(len(self.acp_invocations), 0)

    async def test_04_only_approved_task_can_start_agent(self):
        """Condition 4: Only explicit user approval launches the ACP agent."""
        async def mock_handler(task, manager):
            self.acp_invocations.append(task["id"])
            task["stdout"] += ">>> Mock ACP turn completed.\n"

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task(
            prompt="Format Python codebase",
            workspace=str(AUTHORIZED_WORKSPACE)
        )
        self.assertEqual(len(self.acp_invocations), 0)

        approved = await self.manager.approve_task(task["id"])
        self.assertEqual(approved["status"], TaskStatus.APPROVED)
        self.assertIsNotNone(approved["approved_at"])

        await asyncio.sleep(0.15)
        self.assertEqual(len(self.acp_invocations), 1)
        self.assertIn(task["id"], self.acp_invocations)

        final_task = self.manager.get_task(task["id"])
        self.assertEqual(final_task["status"], TaskStatus.COMPLETED)
        self.assertIn("Mock ACP turn completed", final_task["stdout"])

    async def test_05_duplicate_task_approval_prevention(self):
        """Condition 5: Duplicate approval cannot launch duplicate ACP sessions."""
        async def mock_handler(task, manager):
            self.acp_invocations.append(task["id"])
            await asyncio.sleep(0.2)

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task(
            prompt="Run automated security scan",
            workspace=str(AUTHORIZED_WORKSPACE)
        )
        await self.manager.approve_task(task["id"])

        # Immediate second approval attempt must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            await self.manager.approve_task(task["id"])
        self.assertIn("Cannot approve task", str(ctx.exception))

        await asyncio.sleep(0.25)
        self.assertEqual(len(self.acp_invocations), 1)

    async def test_06_workspace_restrictions_and_path_traversal(self):
        """Condition 6: Workspace validation strictly rejects traversal and unauthorized directories."""
        # 1. System directory
        with self.assertRaises(ValueError) as ctx1:
            await self.manager.submit_task("Prompt", "C:\\Windows\\System32")
        self.assertIn("Unauthorized workspace", str(ctx1.exception))

        # 2. Path traversal
        with self.assertRaises(ValueError) as ctx2:
            await self.manager.submit_task("Prompt", str(AUTHORIZED_WORKSPACE / ".." / "OtherProject"))
        self.assertIn("Unauthorized workspace", str(ctx2.exception))

        # 3. Empty workspace
        with self.assertRaises(ValueError) as ctx3:
            await self.manager.submit_task("Prompt", "   ")
        self.assertIn("Workspace path cannot be empty", str(ctx3.exception))

        # 4. Valid workspace succeeds
        valid_task = await self.manager.submit_task("Valid task", str(AUTHORIZED_WORKSPACE))
        self.assertEqual(valid_task["workspace"], str(AUTHORIZED_WORKSPACE))

    async def test_07_sensitive_action_triggers_awaiting_action_approval(self):
        """Condition 7: Sensitive action request transitions task to AWAITING_ACTION_APPROVAL."""
        action_requested_event = asyncio.Event()

        async def mock_handler(task, manager):
            # Simulate ACP sending session/request_permission for file edit
            perm_future = asyncio.get_event_loop().create_future()
            manager._pending_permission_futures[task["id"]] = perm_future

            tool_call = {
                "toolCallId": "call_write_101",
                "title": "Edit main.py",
                "kind": "edit",
                "parameters": {"path": "main.py", "diff": "+ import sys"}
            }

            async with manager._lock:
                task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                task["pending_permission"] = {
                    "permission_id": 101,
                    "tool_call_id": "call_write_101",
                    "title": "Edit main.py",
                    "kind": "edit",
                    "tool_call": tool_call,
                    "options": [
                        {"optionId": "allow_once", "name": "Allow once"},
                        {"optionId": "reject_once", "name": "Deny"}
                    ],
                    "requested_at": datetime.now(timezone.utc).isoformat()
                }
                task["stdout"] += "\n>>> [PERMISSION REQUIRED] Action: Edit main.py\n"
                manager._persist_tasks()

            action_requested_event.set()
            decision = await perm_future
            self.acp_executed_actions.append(decision)

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Add route", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])

        await asyncio.wait_for(action_requested_event.wait(), timeout=2.0)

        current = self.manager.get_task(task["id"])
        self.assertEqual(current["status"], TaskStatus.AWAITING_ACTION_APPROVAL)
        self.assertIsNotNone(current["pending_permission"])
        self.assertEqual(current["pending_permission"]["title"], "Edit main.py")
        self.assertEqual(current["pending_permission"]["kind"], "edit")

    async def test_08_no_action_executes_before_explicit_user_approval(self):
        """Condition 8: Sensitive action remains strictly paused until human authorizes."""
        action_requested_event = asyncio.Event()

        async def mock_handler(task, manager):
            perm_future = asyncio.get_event_loop().create_future()
            manager._pending_permission_futures[task["id"]] = perm_future
            async with manager._lock:
                task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                task["pending_permission"] = {
                    "permission_id": 102,
                    "tool_call_id": "call_cmd_102",
                    "title": "Run Terminal Command: pytest",
                    "kind": "execute",
                    "tool_call": {"command": "pytest"},
                    "options": [{"optionId": "allow_once", "name": "Allow once"}]
                }
            action_requested_event.set()
            decision = await perm_future
            self.acp_executed_actions.append(decision)

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Run tests", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])

        await asyncio.wait_for(action_requested_event.wait(), timeout=2.0)
        await asyncio.sleep(0.15)

        # Confirm nothing executed yet
        self.assertEqual(len(self.acp_executed_actions), 0)
        self.assertEqual(self.manager.get_task(task["id"])["status"], TaskStatus.AWAITING_ACTION_APPROVAL)

    async def test_09_action_approval_allow_once(self):
        """Condition 9: Approving an action with 'allow_once' resumes execution and records audit log."""
        action_requested_event = asyncio.Event()

        async def mock_handler(task, manager):
            perm_future = asyncio.get_event_loop().create_future()
            manager._pending_permission_futures[task["id"]] = perm_future
            async with manager._lock:
                task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                task["pending_permission"] = {
                    "permission_id": 103,
                    "tool_call_id": "call_write_103",
                    "title": "Create config.json",
                    "kind": "create",
                    "tool_call": {"path": "config.json"}
                }
            action_requested_event.set()
            decision = await perm_future
            self.acp_executed_actions.append(decision)
            task["stdout"] += f">>> Action outcome: {decision}\n"

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Create config", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(action_requested_event.wait(), timeout=2.0)

        # Human approves via API
        resolved = await self.manager.resolve_task_permission(task["id"], "allow_once")
        self.assertEqual(resolved["status"], TaskStatus.RUNNING)
        self.assertIsNone(resolved["pending_permission"])

        await asyncio.sleep(0.15)
        self.assertEqual(self.acp_executed_actions, ["allow_once"])

        final = self.manager.get_task(task["id"])
        self.assertEqual(final["status"], TaskStatus.COMPLETED)
        self.assertEqual(len(final["permission_history"]), 1)
        self.assertEqual(final["permission_history"][0]["decision"], "allow_once")
        self.assertEqual(final["permission_history"][0]["title"], "Create config.json")
        self.assertIn("[ACTION DECISION] APPROVED (Allow Once)", final["stdout"])

    async def test_10_action_rejection_reject_once(self):
        """Condition 10: Rejecting an action with 'reject_once' passes rejection and prevents operation."""
        action_requested_event = asyncio.Event()

        async def mock_handler(task, manager):
            perm_future = asyncio.get_event_loop().create_future()
            manager._pending_permission_futures[task["id"]] = perm_future
            async with manager._lock:
                task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                task["pending_permission"] = {
                    "permission_id": 104,
                    "tool_call_id": "call_rm_104",
                    "title": "Delete database file",
                    "kind": "delete",
                    "tool_call": {"path": "data.db"}
                }
            action_requested_event.set()
            decision = await perm_future
            self.acp_executed_actions.append(decision)
            task["stdout"] += f">>> Agent received refusal: {decision}\n"

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Clean files", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(action_requested_event.wait(), timeout=2.0)

        # Human rejects via API
        resolved = await self.manager.resolve_task_permission(task["id"], "reject_once")
        self.assertEqual(resolved["status"], TaskStatus.RUNNING)
        self.assertIsNone(resolved["pending_permission"])

        await asyncio.sleep(0.15)
        self.assertEqual(self.acp_executed_actions, ["reject_once"])

        final = self.manager.get_task(task["id"])
        self.assertEqual(len(final["permission_history"]), 1)
        self.assertEqual(final["permission_history"][0]["decision"], "reject_once")
        self.assertIn("[ACTION DECISION] REJECTED (Deny)", final["stdout"])

    async def test_11_invalid_permission_decision_denied_by_default(self):
        """Condition 11: Invalid permission decisions are rejected immediately (Default DENY)."""
        action_requested_event = asyncio.Event()

        async def mock_handler(task, manager):
            perm_future = asyncio.get_event_loop().create_future()
            manager._pending_permission_futures[task["id"]] = perm_future
            async with manager._lock:
                task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                task["pending_permission"] = {
                    "permission_id": 105,
                    "tool_call_id": "call_105",
                    "title": "Edit script",
                    "kind": "edit"
                }
            action_requested_event.set()
            decision = await perm_future
            self.acp_executed_actions.append(decision)

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Edit script", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(action_requested_event.wait(), timeout=2.0)

        # Invalid decisions must raise ValueError
        with self.assertRaises(ValueError) as ctx1:
            await self.manager.resolve_task_permission(task["id"], "allow_always")
        self.assertIn("Invalid decision", str(ctx1.exception))

        with self.assertRaises(ValueError) as ctx2:
            await self.manager.resolve_task_permission(task["id"], "bypass")
        self.assertIn("Invalid decision", str(ctx2.exception))

        # Action is still blocked and pending
        self.assertEqual(len(self.acp_executed_actions), 0)
        self.assertEqual(self.manager.get_task(task["id"])["status"], TaskStatus.AWAITING_ACTION_APPROVAL)

    async def test_12_duplicate_and_stale_action_approval_rejected(self):
        """Condition 12: Duplicate or stale permission resolutions are rejected with ValueError."""
        action_requested_event = asyncio.Event()

        async def mock_handler(task, manager):
            perm_future = asyncio.get_event_loop().create_future()
            manager._pending_permission_futures[task["id"]] = perm_future
            async with manager._lock:
                task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                task["pending_permission"] = {
                    "permission_id": 106,
                    "tool_call_id": "call_106",
                    "title": "Install package",
                    "kind": "execute"
                }
            action_requested_event.set()
            await perm_future

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Install deps", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(action_requested_event.wait(), timeout=2.0)

        # First resolution succeeds
        await self.manager.resolve_task_permission(task["id"], "allow_once")

        # Second immediate resolution must fail as task is no longer in AWAITING_ACTION_APPROVAL
        with self.assertRaises(ValueError) as ctx:
            await self.manager.resolve_task_permission(task["id"], "allow_once")
        self.assertIn("not currently awaiting action approval", str(ctx.exception))

    async def test_13_task_cancellation_cleans_pending_permission_and_terminates(self):
        """Condition 13: Cancelling a task while awaiting permission cleanly cancels future and halts."""
        action_requested_event = asyncio.Event()

        async def mock_handler(task, manager):
            perm_future = asyncio.get_event_loop().create_future()
            manager._pending_permission_futures[task["id"]] = perm_future
            async with manager._lock:
                task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                task["pending_permission"] = {
                    "permission_id": 107,
                    "tool_call_id": "call_107",
                    "title": "Overwrite file",
                    "kind": "edit"
                }
            action_requested_event.set()
            decision = await perm_future
            self.acp_executed_actions.append(decision)

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Cancel test", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(action_requested_event.wait(), timeout=2.0)

        cancelled = await self.manager.cancel_task(task["id"])
        self.assertEqual(cancelled["status"], TaskStatus.CANCELLED)
        self.assertIsNone(cancelled["pending_permission"])

        await asyncio.sleep(0.15)
        self.assertEqual(self.acp_executed_actions, ["cancel"])
        self.assertIn("[TASK CANCELLED] User cancelled the task", cancelled["stdout"])

    async def test_14_partial_logs_survive_errors_and_inactivity(self):
        """Condition 14: Partial stdout logs survive errors and are preserved in storage."""
        async def failing_acp_handler(task, manager):
            task["stdout"] += "[Step 1] Initializing codebase scan...\n"
            task["stdout"] += "[Step 2] Found 3 endpoints to review.\n"
            await asyncio.sleep(0.05)
            raise TimeoutError("Task inactive for 90s with no agent output.")

        self.manager.set_acp_mock_handler(failing_acp_handler)

        task = await self.manager.submit_task("Failing job", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.sleep(0.15)

        saved = self.manager.get_task(task["id"])
        self.assertEqual(saved["status"], TaskStatus.FAILED)
        self.assertIn("[Step 1] Initializing codebase scan", saved["stdout"])
        self.assertIn("[Step 2] Found 3 endpoints to review", saved["stdout"])
        self.assertIn("[ACP ERROR] Task inactive for 90s", saved["stdout"])

    async def test_15_taskkill_success_cleans_process_tree(self):
        """Condition 15: taskkill success guarantees complete tree cleanup and reports success."""
        mock_proc = MockSubprocess(pid=50001)
        killed_pids = []

        async def mock_taskkill(pid):
            killed_pids.append(pid)
            mock_proc.terminate()
            return 0

        self.manager.set_taskkill_executor(mock_taskkill)
        action_ready = asyncio.Event()

        async def long_acp_handler(task, manager):
            manager._active_processes[task["id"]] = mock_proc
            manager._active_session_ids[task["id"]] = "ses_test_15"
            action_ready.set()
            await asyncio.sleep(10.0)

        self.manager.set_acp_mock_handler(long_acp_handler)

        task = await self.manager.submit_task("Cancel tree test", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(action_ready.wait(), timeout=2.0)

        # Cancel task
        cancelled = await self.manager.cancel_task(task["id"])
        self.assertEqual(cancelled["status"], TaskStatus.CANCELLED)

        # Confirm taskkill was executed for the process PID
        self.assertIn(50001, killed_pids)
        self.assertEqual(mock_proc.returncode, -15)

        # Confirm stdout contains tree termination confirmation
        self.assertIn("Terminated process tree", cancelled["stdout"])
        self.assertNotIn("FAILED", cancelled["stdout"])
        self.assertNotIn(task["id"], self.manager._active_processes)

    async def test_16_taskkill_failure_triggers_fallback_and_reports_failed(self):
        """Condition 16: taskkill failure triggers root-only fallback and reports cleanup as FAILED."""
        mock_proc = MockSubprocess(pid=50002)

        async def failing_taskkill(pid):
            raise OSError("taskkill executable failed")

        self.manager.set_taskkill_executor(failing_taskkill)
        action_ready = asyncio.Event()

        async def mock_handler(task, manager):
            manager._active_processes[task["id"]] = mock_proc
            action_ready.set()
            await asyncio.sleep(10.0)

        self.manager.set_acp_mock_handler(mock_handler)

        task = await self.manager.submit_task("Taskkill fail test", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(action_ready.wait(), timeout=2.0)

        cancelled = await self.manager.cancel_task(task["id"])
        self.assertEqual(cancelled["status"], TaskStatus.CANCELLED)

        # Root process was terminated via fallback
        self.assertTrue(mock_proc.terminate_called)
        self.assertEqual(mock_proc.returncode, -15)

        # Must report cleanup as FAILED (cannot guarantee child tree cleanup)
        self.assertIn("PROCESS CLEANUP FAILED", cancelled["stdout"])
        self.assertIn("Complete child process-tree termination could not be guaranteed", cancelled["stdout"])
        self.assertNotIn("Terminated process tree (PID", cancelled["stdout"])

    async def test_17_fallback_timeout_escalates_to_kill(self):
        """Condition 17: If proc.terminate() hangs, fallback safely escalates to proc.kill()."""
        # Process hangs on terminate, but exits on kill
        mock_proc = MockSubprocess(pid=50003, hang_terminate=True)

        async def failing_taskkill(pid):
            raise OSError("taskkill unavailable")

        self.manager.set_taskkill_executor(failing_taskkill)

        result = await self.manager.terminate_process_tree(mock_proc)

        # Escalation verified
        self.assertTrue(mock_proc.terminate_called)
        self.assertTrue(mock_proc.kill_called)
        self.assertEqual(mock_proc.returncode, -9)
        self.assertFalse(result.tree_terminated)
        self.assertEqual(result.method, "fallback_root_only")

    async def test_18_duplicate_concurrent_cleanup(self):
        """Condition 18: Concurrent cleanup calls on same process do not execute duplicate taskkill and return identical results."""
        mock_proc = MockSubprocess(pid=50004)
        call_count = 0

        async def slow_mock_taskkill(pid):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)
            mock_proc.terminate()
            return 0

        self.manager.set_taskkill_executor(slow_mock_taskkill)

        # Launch concurrent cleanup calls on the exact same process
        res1, res2 = await asyncio.gather(
            self.manager.terminate_process_tree(mock_proc),
            self.manager.terminate_process_tree(mock_proc)
        )

        self.assertEqual(call_count, 1)
        self.assertTrue(res1.success)
        self.assertTrue(res2.success)
        self.assertTrue(res1.tree_terminated)
        self.assertTrue(res2.tree_terminated)
        self.assertEqual(res1.method, "taskkill_tree")
        self.assertEqual(res2.method, "taskkill_tree")
        self.assertEqual(res1.pid, res2.pid)

    async def test_19_pid_reuse_protection(self):
        """Condition 19: Terminating a process does not block future processes reusing the same PID."""
        mock_proc_1 = MockSubprocess(pid=50005)
        mock_proc_2 = MockSubprocess(pid=50005) # Same PID reused!
        killed_pids = []

        async def mock_taskkill(pid):
            killed_pids.append(pid)
            return 0

        self.manager.set_taskkill_executor(mock_taskkill)

        # First process cleanup
        res1 = await self.manager.terminate_process_tree(mock_proc_1)
        self.assertTrue(res1.tree_terminated)
        self.assertEqual(len(killed_pids), 1)

        # Second process reusing same PID MUST NOT be skipped
        res2 = await self.manager.terminate_process_tree(mock_proc_2)
        self.assertTrue(res2.tree_terminated)
        self.assertEqual(len(killed_pids), 2)

    async def test_20_cleanup_failure_reporting_when_root_fails_to_exit(self):
        """Condition 20: When both taskkill and fallback fail, cleanup failure is explicitly reported."""
        # Process hangs completely and ignores both terminate and kill
        mock_proc = MockSubprocess(pid=50006, hang_terminate=True, hang_kill=True)

        async def failing_taskkill(pid):
            raise OSError("taskkill corrupted")

        self.manager.set_taskkill_executor(failing_taskkill)

        result = await self.manager.terminate_process_tree(mock_proc)

        self.assertFalse(result.success)
        self.assertFalse(result.tree_terminated)
        self.assertEqual(result.method, "failed")
        self.assertIn("Fallback escalation failed to terminate root PID", result.error)

    async def test_21_cancellation_finally_race(self):
        """Condition 21: Cancellation and pipeline finally cleanup race cleanly without crashing."""
        mock_proc = MockSubprocess(pid=50007)

        async def mock_taskkill(pid):
            mock_proc.terminate()
            return 0

        self.manager.set_taskkill_executor(mock_taskkill)
        ready_event = asyncio.Event()

        async def quick_acp_handler(task, manager):
            manager._active_processes[task["id"]] = mock_proc
            ready_event.set()
            await asyncio.sleep(0.01)

        self.manager.set_acp_mock_handler(quick_acp_handler)

        task = await self.manager.submit_task("Race test", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(ready_event.wait(), timeout=2.0)

        # Race cancellation
        try:
            await self.manager.cancel_task(task["id"])
        except ValueError:
            # If pipeline finally finished slightly earlier, cancel_task rejects gracefully
            pass

        await asyncio.sleep(0.1)
        self.assertNotIn(task["id"], self.manager._active_processes)

    async def test_22_inactivity_timeout_cleans_process_tree(self):
        """Condition 22: Inactivity timeout triggers tree cleanup in pipeline finally."""
        mock_proc = MockSubprocess(pid=50008)
        killed_pids = []

        async def mock_taskkill(pid):
            killed_pids.append(pid)
            mock_proc.terminate()
            return 0

        self.manager.set_taskkill_executor(mock_taskkill)

        async def inactive_acp_handler(task, manager):
            manager._active_processes[task["id"]] = mock_proc
            raise TimeoutError("Task inactive for 90s with no agent output.")

        self.manager.set_acp_mock_handler(inactive_acp_handler)

        task = await self.manager.submit_task("Inactive job", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.sleep(0.15)

        saved = self.manager.get_task(task["id"])
        self.assertEqual(saved["status"], TaskStatus.FAILED)
        self.assertIn("Task inactive for 90s", saved["error"])
        self.assertIn(50008, killed_pids)
        self.assertNotIn(task["id"], self.manager._active_processes)
        self.assertIn("Terminated process tree (PID: 50008) on failure/timeout", saved["stdout"])

    async def test_23_already_exited_process_skipped(self):
        """Condition 23: Already-exited processes are safely skipped without redundant termination."""
        mock_proc = MockSubprocess(pid=50009, returncode=0)
        call_count = 0

        async def mock_taskkill(pid):
            nonlocal call_count
            call_count += 1
            return 0

        self.manager.set_taskkill_executor(mock_taskkill)
        result = await self.manager.terminate_process_tree(mock_proc)

        self.assertTrue(result.success)
        self.assertFalse(result.tree_terminated)
        self.assertEqual(result.method, "already_exited")
        self.assertEqual(call_count, 0)
        self.assertFalse(mock_proc.terminate_called)
        self.assertTrue(bool(result))

    async def test_24_concurrent_cleanup_failure_propagates_to_waiters(self):
        """Condition 24: If primary cleanup fails, concurrent waiting callers also receive failure result."""
        mock_proc = MockSubprocess(pid=50010, hang_terminate=True, hang_kill=True)
        call_count = 0

        async def failing_slow_taskkill(pid):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)
            raise OSError("taskkill failed completely")

        self.manager.set_taskkill_executor(failing_slow_taskkill)

        res1, res2 = await asyncio.gather(
            self.manager.terminate_process_tree(mock_proc),
            self.manager.terminate_process_tree(mock_proc)
        )

        self.assertEqual(call_count, 1)
        self.assertFalse(res1.success)
        self.assertFalse(res2.success)
        self.assertFalse(res1.tree_terminated)
        self.assertFalse(res2.tree_terminated)
        self.assertEqual(res1.method, "failed")
        self.assertEqual(res2.method, "failed")

    async def test_25_taskkill_exit_code_128_reports_already_exited_or_untracked(self):
        """Condition 25: Exit code 128 reports already_exited_or_untracked with tree_terminated=False."""
        mock_proc = MockSubprocess(pid=50011)

        async def mock_taskkill_128(pid):
            # Process was not found (already exited or untracked)
            return 128

        self.manager.set_taskkill_executor(mock_taskkill_128)
        result = await self.manager.terminate_process_tree(mock_proc)

        self.assertTrue(result.success)
        self.assertFalse(result.tree_terminated)
        self.assertEqual(result.method, "already_exited_or_untracked")
        self.assertEqual(result.pid, 50011)
        self.assertIn("128", result.error or "")
        self.assertTrue(bool(result))

    async def test_26_already_exited_logging_in_cancel_and_pipeline(self):
        """Condition 26: Already-exited processes log accurately without claiming tree termination."""
        # Test in cancel_task:
        mock_proc_cancel = MockSubprocess(pid=50012, returncode=0)
        ready_event = asyncio.Event()

        async def dead_proc_handler(task, manager):
            manager._active_processes[task["id"]] = mock_proc_cancel
            ready_event.set()
            await asyncio.sleep(10.0)

        self.manager.set_acp_mock_handler(dead_proc_handler)
        task = await self.manager.submit_task("Already exited cancel", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task["id"])
        await asyncio.wait_for(ready_event.wait(), timeout=2.0)

        cancelled = await self.manager.cancel_task(task["id"])
        self.assertIn("was already exited (or untracked). No active process tree found to terminate.", cancelled["stdout"])
        self.assertNotIn("Terminated process tree", cancelled["stdout"])

        # Test in pipeline finally with exit code 128:
        mock_proc_fail = MockSubprocess(pid=50013)
        async def mock_taskkill_128(pid):
            return 128

        self.manager.set_taskkill_executor(mock_taskkill_128)

        async def error_handler(task, manager):
            manager._active_processes[task["id"]] = mock_proc_fail
            raise RuntimeError("Task crashed unexpectedly")

        self.manager.set_acp_mock_handler(error_handler)
        task2 = await self.manager.submit_task("Already exited pipeline", str(AUTHORIZED_WORKSPACE))
        await self.manager.approve_task(task2["id"])
        await asyncio.sleep(0.15)

        saved = self.manager.get_task(task2["id"])
        self.assertIn("was already exited (or untracked). No active process tree found to terminate.", saved["stdout"])
        self.assertNotIn("Terminated process tree", saved["stdout"])

    async def test_27_concurrent_cleanup_waiter_cancellation_safe(self):
        """Condition 27: Cancelling a secondary waiter does not abort primary cleanup or leave dangling state."""
        mock_proc = MockSubprocess(pid=50014)
        started_event = asyncio.Event()

        async def slow_taskkill(pid):
            started_event.set()
            await asyncio.sleep(0.1)
            mock_proc.terminate()
            return 0

        self.manager.set_taskkill_executor(slow_taskkill)

        # Start primary cleanup in background
        primary_task = asyncio.create_task(self.manager.terminate_process_tree(mock_proc))
        await started_event.wait()

        # Start secondary waiting caller
        secondary_task = asyncio.create_task(self.manager.terminate_process_tree(mock_proc))
        await asyncio.sleep(0.01)

        # Cancel secondary waiter
        secondary_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await secondary_task

        # Primary cleanup should still complete successfully
        primary_res = await primary_task
        self.assertTrue(primary_res.success)
        self.assertTrue(primary_res.tree_terminated)
        self.assertEqual(len(self.manager._in_flight_cleanups), 0)

    async def test_28_antigravity_only_configuration_rejects_other_agents(self):
        """Condition 28: System is strictly locked to Antigravity ACP; all other agents are rejected."""
        # 1. Default submission assigns agent=antigravity
        task = await self.manager.submit_task("Antigravity task", str(AUTHORIZED_WORKSPACE))
        self.assertEqual(task["agent"], "antigravity")

        # 2. Submitting with agent="vscode" is rejected with ValueError
        with self.assertRaises(ValueError) as ctx1:
            await self.manager.submit_task("VS Code task", str(AUTHORIZED_WORKSPACE), agent="vscode")
        self.assertIn("Agent 'vscode' is disabled", str(ctx1.exception))
        self.assertIn("strictly configured for Antigravity ACP only", str(ctx1.exception))

        # 3. Submitting with any other agent is rejected with ValueError
        with self.assertRaises(ValueError) as ctx2:
            await self.manager.submit_task("Copilot task", str(AUTHORIZED_WORKSPACE), agent="copilot")
        self.assertIn("Agent 'copilot' is disabled", str(ctx2.exception))

        # 4. Status reflects Antigravity as the sole active agent and VS Code bridge as disabled
        status = self.manager.get_agent_status()
        self.assertEqual(status["configured_agent"], "Antigravity ACP (Sole Active Agent)")
        self.assertEqual(status["vscode_bridge_status"], "Disabled")
        self.assertEqual(status["vscode_agent_selection"], "Disabled")
        self.assertEqual(status["protocol"], "Agent Client Protocol (ACP)")


class MockSubprocess:
    def __init__(self, pid=99999, returncode=None, hang_terminate=False, hang_kill=False):
        self.pid = pid
        self.returncode = returncode
        self.terminate_called = False
        self.kill_called = False
        self.hang_terminate = hang_terminate
        self.hang_kill = hang_kill

        async def _drain(self_arg=None):
            pass

        self.stdin = type("MockStdin", (), {
            "write": lambda self_arg, b: None,
            "drain": _drain
        })()

    def terminate(self):
        self.terminate_called = True
        if not self.hang_terminate:
            self.returncode = -15

    def kill(self):
        self.kill_called = True
        if not self.hang_kill:
            self.returncode = -9

    async def wait(self):
        if self.returncode is not None:
            return self.returncode
        if self.hang_terminate and not self.kill_called:
            # Simulate hung process that ignores SIGTERM
            await asyncio.sleep(3.0)
            return self.returncode
        if self.hang_kill:
            # Simulate kernel-stuck process
            await asyncio.sleep(3.0)
            return self.returncode
        if self.kill_called and self.returncode is None:
            self.returncode = -9
        elif self.terminate_called and self.returncode is None:
            self.returncode = -15
        return self.returncode


if __name__ == "__main__":
    unittest.main()
