"""
Unit tests for Local Worker Workspace Isolation & Windows Process Cleanup
Verifies directory confinement, taskkill exit code 128 handling, concurrent cleanup synchronization,
and fallback escalation diagnostics.
"""

import asyncio
from pathlib import Path
import unittest

from local_worker.acp_runner import AUTHORIZED_WORKSPACE, validate_workspace
from local_worker.process_cleanup import ProcessCleanupManager, ProcessCleanupResult


class MockSubprocess:
    def __init__(self, pid: int = 12345, returncode: int = None):
        self.pid = pid
        self.returncode = returncode
        self.terminate_called = False
        self.kill_called = False
        self.wait_called = False

    def terminate(self):
        self.terminate_called = True

    def kill(self):
        self.kill_called = True

    async def wait(self):
        self.wait_called = True
        return self.returncode


class TestWorkerAndCleanup(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.cleanup = ProcessCleanupManager()

    def test_workspace_isolation_and_confinement(self):
        """Verifies workspace paths are strictly confined to the authorized workspace."""
        # Exact match
        resolved = validate_workspace(str(AUTHORIZED_WORKSPACE))
        self.assertEqual(resolved, AUTHORIZED_WORKSPACE)

        # Valid subfolder
        subfolder = AUTHORIZED_WORKSPACE / "sub" / "project"
        resolved_sub = validate_workspace(str(subfolder))
        self.assertTrue(resolved_sub == AUTHORIZED_WORKSPACE or resolved_sub.is_relative_to(AUTHORIZED_WORKSPACE))

        # Rejects empty or whitespace
        with self.assertRaises(ValueError):
            validate_workspace("")
        with self.assertRaises(ValueError):
            validate_workspace("   ")

        # Rejects path traversal / external drives
        with self.assertRaises(ValueError):
            validate_workspace(r"C:\Windows\System32")
        with self.assertRaises(ValueError):
            validate_workspace(r"C:\Users\lovel\Desktop")
        with self.assertRaises(ValueError):
            validate_workspace(r"C:\Users\lovel\Desktop\OtherRepo")

    def test_process_cleanup_result_boolean_evaluation(self):
        """Verifies ProcessCleanupResult.__bool__ accurately reflects complete tree termination."""
        # 1. Complete tree termination -> True
        res_tree = ProcessCleanupResult(success=True, tree_terminated=True, method="taskkill_tree", pid=100)
        self.assertTrue(bool(res_tree))

        # 2. Already exited process -> True
        res_dead = ProcessCleanupResult(success=True, tree_terminated=False, method="already_exited", pid=100)
        self.assertTrue(bool(res_dead))

        # 3. Exit code 128 (already exited or untracked) -> True
        res_128 = ProcessCleanupResult(success=True, tree_terminated=False, method="already_exited_or_untracked", pid=100)
        self.assertTrue(bool(res_128))

        # 4. Fallback root-only termination -> False (child survival possible!)
        res_fallback = ProcessCleanupResult(success=False, tree_terminated=False, method="fallback_root_only", pid=100)
        self.assertFalse(bool(res_fallback))

        # 5. Total failure -> False
        res_fail = ProcessCleanupResult(success=False, tree_terminated=False, method="failed", pid=100)
        self.assertFalse(bool(res_fail))

    async def test_taskkill_exit_code_128_handling(self):
        """Verifies taskkill exit code 128 is mapped to already_exited_or_untracked with tree_terminated=False."""
        proc = MockSubprocess(pid=9999, returncode=None)

        async def mock_taskkill_128(pid):
            proc.returncode = 128
            return 128

        self.cleanup.set_taskkill_executor(mock_taskkill_128)
        res = await self.cleanup.terminate_process_tree(proc)

        self.assertTrue(res.success)
        self.assertFalse(res.tree_terminated)
        self.assertEqual(res.method, "already_exited_or_untracked")
        self.assertEqual(res.pid, 9999)

    async def test_concurrent_cleanup_synchronization(self):
        """Verifies concurrent cleanup calls on the same process object are synchronized to a single execution."""
        proc = MockSubprocess(pid=8888, returncode=None)
        execution_count = 0

        async def slow_mock_taskkill(pid):
            nonlocal execution_count
            execution_count += 1
            await asyncio.sleep(0.05)
            proc.returncode = 0
            return 0

        self.cleanup.set_taskkill_executor(slow_mock_taskkill)

        # Launch two cleanup coroutines concurrently for the exact same process
        res1, res2 = await asyncio.gather(
            self.cleanup.terminate_process_tree(proc),
            self.cleanup.terminate_process_tree(proc)
        )

        # Both callers receive the successful tree cleanup result
        self.assertTrue(res1.success)
        self.assertTrue(res1.tree_terminated)
        self.assertTrue(res2.success)
        self.assertTrue(res2.tree_terminated)

        # Mock executor was only executed ONCE
        self.assertEqual(execution_count, 1)

    async def test_fallback_escalation_diagnostics(self):
        """Verifies that taskkill failure triggers terminate -> kill and reports fallback_root_only."""
        proc = MockSubprocess(pid=7777, returncode=None)

        async def failing_mock_taskkill(pid):
            return 1  # taskkill fails with exit code 1

        self.cleanup.set_taskkill_executor(failing_mock_taskkill)

        # Simulate root process exiting during fallback kill
        def simulate_kill():
            proc.returncode = -9

        original_kill = proc.kill
        proc.kill = lambda: (original_kill(), simulate_kill())

        res = await self.cleanup.terminate_process_tree(proc)

        # Must report fallback_root_only because complete child-tree cannot be guaranteed
        self.assertFalse(res.success)
        self.assertFalse(res.tree_terminated)
        self.assertEqual(res.method, "fallback_root_only")
        self.assertIn("Root process terminated via fallback", res.error)


if __name__ == "__main__":
    unittest.main()
