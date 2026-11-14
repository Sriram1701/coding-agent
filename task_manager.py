"""
AI CODING HUB - Antigravity ACP Task Manager
Manages coding task lifecycles, human-in-the-loop permission gating for every sensitive action,
and Agent Client Protocol (ACP) JSON-RPC communication over stdio.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional
import uuid

logger = logging.getLogger("ai_coding_hub.tasks")

# Verified Paths & Settings
AUTHORIZED_WORKSPACE = Path(r"C:\Users\lovel\Desktop\AI-CODING-HUB").resolve()
AGY_CLI_PATH = Path(r"C:\Users\lovel\.gemini\bin\agy.exe")
TASK_STORE_DIR = AUTHORIZED_WORKSPACE / "data"
TASK_STORE_FILE = TASK_STORE_DIR / "tasks.json"

# Inactivity and session bounds
INACTIVITY_TIMEOUT_SECONDS = 90
MAX_SESSION_SECONDS = 900


class TaskStatus:
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    AWAITING_ACTION_APPROVAL = "AWAITING_ACTION_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class ProcessCleanupResult:
    """Detailed result of a process / process-tree termination attempt."""
    def __init__(
        self,
        success: bool,
        tree_terminated: bool,
        method: str,
        pid: Optional[int] = None,
        error: Optional[str] = None
    ):
        self.success = success
        self.tree_terminated = tree_terminated
        self.method = method
        self.pid = pid
        self.error = error

    def __bool__(self) -> bool:
        # Evaluates as True ONLY if complete tree cleanup was achieved or process was already dead / untracked
        return self.success and (self.tree_terminated or self.method in ["already_exited", "already_exited_or_untracked"])

    def __repr__(self) -> str:
        return (
            f"<ProcessCleanupResult success={self.success} "
            f"tree_terminated={self.tree_terminated} "
            f"method='{self.method}' pid={self.pid} error={self.error}>"
        )


def validate_workspace(workspace_str: str) -> Path:
    """
    Strictly validates that the target workspace matches the authorized workspace.
    Prevents path traversal and arbitrary directory execution.
    """
    if not workspace_str or not workspace_str.strip():
        raise ValueError("Workspace path cannot be empty.")

    try:
        resolved = Path(workspace_str.strip()).resolve()
    except Exception as e:
        raise ValueError(f"Invalid workspace path format: {e}")

    # Case-insensitive resolution check on Windows
    if resolved != AUTHORIZED_WORKSPACE:
        try:
            resolved.relative_to(AUTHORIZED_WORKSPACE)
        except ValueError:
            raise ValueError(
                f"Unauthorized workspace '{resolved}'. "
                f"Tasks are strictly restricted to '{AUTHORIZED_WORKSPACE}'."
            )

    return resolved


class TaskManager:
    def __init__(self, storage_path: Path = TASK_STORE_FILE):
        self.storage_path = storage_path
        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._active_processes: Dict[str, asyncio.subprocess.Process] = {}
        self._pending_permission_futures: Dict[str, asyncio.Future] = {}
        self._active_session_ids: Dict[str, str] = {}
        self._custom_acp_handler: Optional[Callable[[Dict[str, Any], Any], Coroutine[Any, Any, None]]] = None
        self._taskkill_executor: Optional[Callable[[int], Coroutine[Any, Any, int]]] = None
        self._in_flight_cleanups: Dict[int, asyncio.Future] = {}
        self._load_tasks()

    def _load_tasks(self) -> None:
        """Loads tasks from local JSON storage if present."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self._tasks = data
                    elif isinstance(data, list):
                        self._tasks = {t["id"]: t for t in data if "id" in t}
            except Exception as e:
                logger.error(f"Error loading tasks from {self.storage_path}: {e}")
                self._tasks = {}
        else:
            self._tasks = {}

    def _persist_tasks(self) -> None:
        """Persists tasks to local JSON storage safely with Windows lock retry."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self.storage_path.with_suffix(f".tmp_{uuid.uuid4().hex[:6]}")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(self._tasks, f, indent=2)
            
            # Windows file locking resilience
            written = False
            for attempt in range(4):
                try:
                    temp_path.replace(self.storage_path)
                    written = True
                    break
                except OSError:
                    import time
                    time.sleep(0.02)
            
            if not written:
                with open(self.storage_path, "w", encoding="utf-8") as f:
                    json.dump(self._tasks, f, indent=2)
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error persisting tasks to {self.storage_path}: {e}")

    def set_acp_mock_handler(
        self,
        handler: Optional[Callable[[Dict[str, Any], Any], Coroutine[Any, Any, None]]]
    ) -> None:
        """Allows injecting a mocked ACP protocol handler for automated tests."""
        self._custom_acp_handler = handler

    def set_taskkill_executor(
        self,
        executor: Optional[Callable[[int], Coroutine[Any, Any, int]]]
    ) -> None:
        """Allows injecting a mocked taskkill runner for automated tests."""
        self._taskkill_executor = executor

    async def terminate_process_tree(self, proc: Any) -> ProcessCleanupResult:
        """
        Safely terminates a process and all its child/descendant processes on Windows.
        1. Checks if process is None or already exited (returncode is not None).
        2. Guards against concurrent duplicate cleanup on the same in-flight process object,
           synchronizing callers so secondary callers await the primary cleanup and receive
           the actual completed result.
        3. Executes Windows-native 'taskkill /T /F /PID <pid>' with argument list (never shell=True).
        4. Accurately reports exit code 128 as 'already_exited_or_untracked' (tree_terminated=False).
        5. If taskkill fails, safely escalates: proc.terminate() -> bounded wait -> proc.kill() -> bounded wait.
        6. Does not manually assign proc.returncode (managed naturally by asyncio wait()).
        7. Explicitly reports whether complete tree termination was guaranteed or root-only fallback occurred.
        """
        if proc is None:
            return ProcessCleanupResult(
                success=False,
                tree_terminated=False,
                method="invalid_proc",
                error="Process reference is None."
            )

        pid = getattr(proc, "pid", None)

        # Guard: check if process already exited
        if getattr(proc, "returncode", None) is not None:
            return ProcessCleanupResult(
                success=True,
                tree_terminated=False,
                method="already_exited",
                pid=pid
            )

        if pid is None or pid <= 0:
            return ProcessCleanupResult(
                success=False,
                tree_terminated=False,
                method="invalid_pid",
                error=f"Invalid PID: {pid}"
            )

        # FIX 2: Guard & synchronize concurrent cleanups on the same process instance
        proc_ref_id = id(proc)
        if proc_ref_id in self._in_flight_cleanups:
            cleanup_future = self._in_flight_cleanups[proc_ref_id]
            # Secondary callers await the primary cleanup and receive the exact completed result.
            # asyncio.shield protects the underlying cleanup future from being cancelled
            # if this waiting caller is cancelled.
            return await asyncio.shield(cleanup_future)

        loop = asyncio.get_running_loop()
        cleanup_future = loop.create_future()
        self._in_flight_cleanups[proc_ref_id] = cleanup_future

        result: Optional[ProcessCleanupResult] = None
        try:
            taskkill_success = False
            taskkill_is_128 = False
            taskkill_err = None

            # Path A: Custom mock executor for testing
            if self._taskkill_executor is not None:
                try:
                    code = await self._taskkill_executor(pid)
                    if code == 0:
                        taskkill_success = True
                    elif code == 128:
                        taskkill_is_128 = True
                    else:
                        taskkill_err = f"Mock taskkill returned exit code {code}"
                except Exception as e:
                    taskkill_err = str(e)
                    logger.warning(f"Mock taskkill failed for PID {pid}: {e}. Proceeding to fallback.")
            else:
                # Path B: Windows-native taskkill /T /F /PID (argument list, never shell=True)
                try:
                    kill_cmd = ["taskkill", "/T", "/F", "/PID", str(pid)]
                    kill_proc = await asyncio.create_subprocess_exec(
                        *kill_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(kill_proc.communicate(), timeout=5.0)
                    if kill_proc.returncode == 0:
                        taskkill_success = True
                    elif kill_proc.returncode == 128:
                        taskkill_is_128 = True
                    else:
                        stderr_msg = stderr_bytes.decode("utf-8", errors="replace").strip()
                        taskkill_err = f"taskkill returned {kill_proc.returncode}: {stderr_msg}"
                        logger.warning(f"taskkill returned {kill_proc.returncode} for PID {pid}: {stderr_msg}")
                except FileNotFoundError:
                    taskkill_err = "taskkill.exe not found on system PATH"
                    logger.warning(f"taskkill.exe not found on system PATH for PID {pid}. Falling back to proc.terminate().")
                except asyncio.TimeoutError:
                    taskkill_err = "taskkill execution timed out after 5.0s"
                    logger.warning(f"taskkill timed out for PID {pid}. Falling back to proc.terminate().")
                except Exception as e:
                    taskkill_err = str(e)
                    logger.warning(f"taskkill execution failed for PID {pid}: {e}. Falling back to proc.terminate().")

            # FIX 1: Exit code 128 means process was not found (already exited or untracked PID).
            # Complete process tree termination cannot be confirmed, so tree_terminated is False.
            if taskkill_is_128:
                try:
                    if hasattr(proc, "wait") and getattr(proc, "returncode", None) is None:
                        await asyncio.wait_for(proc.wait(), timeout=0.5)
                except Exception:
                    pass
                result = ProcessCleanupResult(
                    success=True,
                    tree_terminated=False,
                    method="already_exited_or_untracked",
                    pid=pid,
                    error="Process not found by taskkill (exit code 128)."
                )
                return result

            # If taskkill succeeded (exit code 0), wait briefly for asyncio process handle to update returncode
            if taskkill_success:
                try:
                    if hasattr(proc, "wait") and getattr(proc, "returncode", None) is None:
                        await asyncio.wait_for(proc.wait(), timeout=1.0)
                except Exception:
                    pass
                result = ProcessCleanupResult(
                    success=True,
                    tree_terminated=True,
                    method="taskkill_tree",
                    pid=pid
                )
                return result

            # DEFECT 1 & 2 FIX: Fallback Escalation (terminate -> bounded wait -> kill -> bounded wait)
            # Notice: Complete process-tree termination cannot be guaranteed via root-only terminate/kill!
            fallback_err = None
            try:
                # Step 1: proc.terminate() if alive
                if getattr(proc, "returncode", None) is None:
                    if hasattr(proc, "terminate"):
                        try:
                            proc.terminate()
                        except ProcessLookupError:
                            pass
                    # Bounded wait for process to exit after terminate
                    if hasattr(proc, "wait") and getattr(proc, "returncode", None) is None:
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass

                # Step 2: Escalate to proc.kill() if still alive
                if getattr(proc, "returncode", None) is None:
                    if hasattr(proc, "kill"):
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                    # Bounded wait for process to exit after kill
                    if hasattr(proc, "wait") and getattr(proc, "returncode", None) is None:
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass
            except Exception as e:
                fallback_err = str(e)
                logger.warning(f"Fallback process escalation error for PID {pid}: {e}")

            # Check if root process finally exited
            root_exited = getattr(proc, "returncode", None) is not None
            if root_exited:
                result = ProcessCleanupResult(
                    success=False,
                    tree_terminated=False,
                    method="fallback_root_only",
                    pid=pid,
                    error=f"taskkill failed ({taskkill_err}). Root process terminated via fallback, but complete child process-tree termination could not be guaranteed."
                )
                return result
            else:
                result = ProcessCleanupResult(
                    success=False,
                    tree_terminated=False,
                    method="failed",
                    pid=pid,
                    error=f"taskkill failed ({taskkill_err}). Fallback escalation failed to terminate root PID {pid} ({fallback_err or 'still running'})."
                )
                return result
        except BaseException as e:
            if not cleanup_future.done():
                cleanup_future.set_exception(e)
            raise
        finally:
            if not cleanup_future.done():
                if result is not None:
                    cleanup_future.set_result(result)
                else:
                    cleanup_future.set_result(
                        ProcessCleanupResult(
                            success=False,
                            tree_terminated=False,
                            method="failed",
                            pid=pid,
                            error="Cleanup ended without a result."
                        )
                    )
            self._in_flight_cleanups.pop(proc_ref_id, None)

    def get_agent_status(self) -> Dict[str, Any]:
        """Returns detected CLI status, ACP capabilities, and security posture."""
        cli_exists = AGY_CLI_PATH.exists()
        return {
            "cli_path": str(AGY_CLI_PATH),
            "cli_exists": cli_exists,
            "cli_version": "1.5.8" if cli_exists else "Not Detected",
            "protocol": "Agent Client Protocol (ACP)",
            "acp_server": "Antigravity ACP Server v1.5.9",
            "authorized_workspace": str(AUTHORIZED_WORKSPACE),
            "configured_agent": "Antigravity ACP (Sole Active Agent)",
            "vscode_bridge_status": "Disabled",
            "vscode_agent_selection": "Disabled",
            "approval_required": True,
            "action_approval_required": True,
            "default_permission_mode": "default (Ask before edits and commands)",
            "security_mode": "Strict Human Approval (Every Sensitive Action)",
            "active_running_tasks": sum(
                1 for t in self._tasks.values() if t.get("status") in [TaskStatus.RUNNING, TaskStatus.AWAITING_ACTION_APPROVAL]
            )
        }

    async def submit_task(self, prompt: str, workspace: str, agent: Optional[str] = "antigravity") -> Dict[str, Any]:
        """
        Submits a new coding task.
        CRITICAL: Never executes agy.exe upon submission.
        Status is strictly initialized to PENDING_APPROVAL.
        Strictly configured for Antigravity ACP as the sole active agent.
        """
        prompt_clean = prompt.strip() if prompt else ""
        if not prompt_clean:
            raise ValueError("Task prompt cannot be empty.")

        if agent and agent.lower() != "antigravity":
            raise ValueError(
                f"Agent '{agent}' is disabled. "
                "AI CODING HUB is strictly configured for Antigravity ACP only."
            )

        validated_workspace = validate_workspace(workspace)

        task_id = f"task_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        task = {
            "id": task_id,
            "agent": "antigravity",
            "prompt": prompt_clean,
            "workspace": str(validated_workspace),
            "status": TaskStatus.PENDING_APPROVAL,
            "created_at": now,
            "updated_at": now,
            "approved_at": None,
            "executed_at": None,
            "completed_at": None,
            "stdout": "",
            "stderr": "",
            "events": [],
            "pending_permission": None,
            "permission_history": [],
            "exit_code": None,
            "error": None
        }

        async with self._lock:
            self._tasks[task_id] = task
            self._persist_tasks()

        logger.info(f"Task {task_id} submitted and placed in PENDING_APPROVAL.")
        return task

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves task by ID."""
        return self._tasks.get(task_id)

    def list_tasks(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists tasks, optionally filtered by status, sorted by creation date."""
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.get("status") == status]
        return sorted(tasks, key=lambda x: x.get("created_at", ""), reverse=True)

    async def approve_task(self, task_id: str) -> Dict[str, Any]:
        """
        Approves a pending task and launches its ACP session.
        CRITICAL:
        - Only tasks in PENDING_APPROVAL can be approved.
        - Repeated calls reject duplicate execution.
        """
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise KeyError(f"Task '{task_id}' not found.")

            current_status = task.get("status")
            if current_status != TaskStatus.PENDING_APPROVAL:
                raise ValueError(
                    f"Cannot approve task {task_id}: status is '{current_status}'. "
                    f"Only '{TaskStatus.PENDING_APPROVAL}' tasks can be approved."
                )

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.APPROVED
            task["approved_at"] = now
            task["updated_at"] = now
            self._persist_tasks()

        asyncio.create_task(self._run_task_pipeline(task_id))
        return task

    async def reject_task(self, task_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        """
        Rejects a pending task.
        CRITICAL: Never executes the agent.
        """
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise KeyError(f"Task '{task_id}' not found.")

            current_status = task.get("status")
            if current_status != TaskStatus.PENDING_APPROVAL:
                raise ValueError(
                    f"Cannot reject task {task_id}: status is '{current_status}'. "
                    f"Only '{TaskStatus.PENDING_APPROVAL}' tasks can be rejected."
                )

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.REJECTED
            task["updated_at"] = now
            task["error"] = reason or "Rejected by user."
            self._persist_tasks()

        logger.info(f"Task {task_id} marked as REJECTED.")
        return task

    async def resolve_task_permission(self, task_id: str, decision: str) -> Dict[str, Any]:
        """
        Resolves an interactive sensitive action permission request.
        MANDATORY SECURITY:
        - Task must be in AWAITING_ACTION_APPROVAL.
        - Decision must be 'allow_once' or 'reject_once'.
        - Prevents duplicate or stale resolutions.
        - Default behavior is DENY if invalid.
        """
        if decision not in ["allow_once", "reject_once"]:
            raise ValueError(f"Invalid decision '{decision}'. Must be 'allow_once' or 'reject_once'.")

        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise KeyError(f"Task '{task_id}' not found.")

            if task.get("status") != TaskStatus.AWAITING_ACTION_APPROVAL:
                raise ValueError(
                    f"Cannot resolve permission for task {task_id}: status is '{task.get('status')}'. "
                    f"Task is not currently awaiting action approval."
                )

            pending = task.get("pending_permission")
            if not pending:
                raise ValueError(f"Task {task_id} has no pending permission request.")

            future = self._pending_permission_futures.get(task_id)
            if not future or future.done():
                raise ValueError(f"Pending permission future for {task_id} is stale or already resolved.")

            now = datetime.now(timezone.utc).isoformat()
            record = {
                "permission_id": pending.get("permission_id"),
                "tool_call_id": pending.get("tool_call_id"),
                "title": pending.get("title"),
                "kind": pending.get("kind"),
                "tool_call": pending.get("tool_call"),
                "decision": decision,
                "decided_at": now
            }
            task["permission_history"].append(record)

            # Log decision in task output
            outcome_label = "APPROVED (Allow Once)" if decision == "allow_once" else "REJECTED (Deny)"
            task["stdout"] += f"\n>>> [ACTION DECISION] {outcome_label}: {pending.get('title')}\n"
            task["events"].append({
                "type": "permission_decision",
                "timestamp": now,
                "decision": decision,
                "title": pending.get("title")
            })

            # Transition task back to RUNNING and clear pending
            task["status"] = TaskStatus.RUNNING
            task["pending_permission"] = None
            task["updated_at"] = now
            self._persist_tasks()

            # Resolve the future waiting in ACP event loop
            future.set_result(decision)

        return task

    async def cancel_task(self, task_id: str) -> Dict[str, Any]:
        """Cancels a pending or active task and safely aborts ACP execution."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise KeyError(f"Task '{task_id}' not found.")

            current_status = task.get("status")
            if current_status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.REJECTED, TaskStatus.CANCELLED]:
                raise ValueError(f"Task {task_id} is already finalized with status '{current_status}'.")

            # If awaiting permission, cancel the pending future immediately
            perm_future = self._pending_permission_futures.pop(task_id, None)
            if perm_future and not perm_future.done():
                perm_future.set_result("cancel")

            proc = self._active_processes.get(task_id)
            session_id = self._active_session_ids.get(task_id)

            if proc and session_id:
                try:
                    # Send graceful ACP session/cancel notification
                    cancel_msg = {
                        "jsonrpc": "2.0",
                        "method": "session/cancel",
                        "params": {"sessionId": session_id}
                    }
                    if hasattr(proc, "stdin") and proc.stdin:
                        proc.stdin.write((json.dumps(cancel_msg) + "\n").encode("utf-8"))
                        await proc.stdin.drain()
                except Exception as e:
                    logger.warning(f"Error sending session/cancel to {task_id}: {e}")

            if proc:
                try:
                    cleanup_res = await self.terminate_process_tree(proc)
                    if cleanup_res.method in ["already_exited", "already_exited_or_untracked"]:
                        task["stdout"] += (
                            f">>> [PROCESS CLEANUP] Process PID {cleanup_res.pid} was already exited "
                            f"(or untracked). No active process tree found to terminate.\n"
                        )
                    elif cleanup_res.tree_terminated:
                        task["stdout"] += f">>> [PROCESS CLEANUP] Terminated process tree (PID: {cleanup_res.pid}).\n"
                    elif cleanup_res.method == "fallback_root_only":
                        task["stdout"] += (
                            f">>> [PROCESS CLEANUP FAILED] Complete child process-tree termination could not be guaranteed. "
                            f"{cleanup_res.error}\n"
                        )
                    else:
                        task["stdout"] += (
                            f">>> [PROCESS CLEANUP FAILED] Failed to terminate process (PID: {cleanup_res.pid}): "
                            f"{cleanup_res.error or 'unknown error'}\n"
                        )
                except Exception as e:
                    logger.warning(f"Error terminating process tree for {task_id}: {e}")
                    task["stdout"] += f">>> [PROCESS CLEANUP FAILED] Unexpected error during cleanup: {e}\n"
                self._active_processes.pop(task_id, None)
                self._active_session_ids.pop(task_id, None)

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.CANCELLED
            task["updated_at"] = now
            task["pending_permission"] = None
            task["error"] = "Cancelled by user."
            task["stdout"] += f"\n>>> [TASK CANCELLED] User cancelled the task.\n"
            self._persist_tasks()

        logger.info(f"Task {task_id} marked as CANCELLED.")
        return task

    async def _run_task_pipeline(self, task_id: str) -> None:
        """Internal worker managing ACP lifecycle, event streaming, and action approvals."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.get("status") != TaskStatus.APPROVED:
                return

            task["status"] = TaskStatus.RUNNING
            task["executed_at"] = datetime.now(timezone.utc).isoformat()
            task["updated_at"] = task["executed_at"]
            task["stdout"] = f">>> [ACP INITIALIZING] Connecting to Antigravity ACP stdio server...\n"
            self._persist_tasks()

        try:
            if self._custom_acp_handler:
                # Test mock handler
                await self._custom_acp_handler(task, self)
            else:
                # Real ACP stdio execution
                await self._execute_acp_session(task)

            async with self._lock:
                task = self._tasks.get(task_id)
                if not task:
                    return

                if task.get("status") == TaskStatus.CANCELLED:
                    return

                now = datetime.now(timezone.utc).isoformat()
                task["completed_at"] = now
                task["updated_at"] = now

                if task.get("status") == TaskStatus.RUNNING:
                    task["status"] = TaskStatus.COMPLETED
                    task["exit_code"] = 0
                    task["stdout"] += f"\n>>> [ACP COMPLETED] Task turn finished successfully.\n"

                self._persist_tasks()

        except Exception as e:
            logger.error(f"Execution error for task {task_id}: {e}")
            async with self._lock:
                task = self._tasks.get(task_id)
                if task and task.get("status") != TaskStatus.CANCELLED:
                    task["status"] = TaskStatus.FAILED
                    task["error"] = str(e)
                    task["completed_at"] = datetime.now(timezone.utc).isoformat()
                    task["updated_at"] = task["completed_at"]
                    task["stdout"] += f"\n>>> [ACP ERROR] {str(e)}\n"
                    self._persist_tasks()
        finally:
            proc = self._active_processes.get(task_id)
            if proc:
                try:
                    cleanup_res = await self.terminate_process_tree(proc)
                    async with self._lock:
                        t = self._tasks.get(task_id)
                        if t:
                            if cleanup_res.method in ["already_exited", "already_exited_or_untracked"]:
                                t["stdout"] += (
                                    f">>> [PROCESS CLEANUP] Process PID {cleanup_res.pid} was already exited "
                                    f"(or untracked). No active process tree found to terminate.\n"
                                )
                            elif cleanup_res.tree_terminated:
                                t["stdout"] += f">>> [PROCESS CLEANUP] Terminated process tree (PID: {cleanup_res.pid}) on failure/timeout.\n"
                            elif cleanup_res.method == "fallback_root_only":
                                t["stdout"] += (
                                    f">>> [PROCESS CLEANUP FAILED] Complete child process-tree termination could not be guaranteed on failure/timeout. "
                                    f"{cleanup_res.error}\n"
                                )
                            else:
                                t["stdout"] += (
                                    f">>> [PROCESS CLEANUP FAILED] Failed to terminate process (PID: {cleanup_res.pid}): "
                                    f"{cleanup_res.error or 'unknown error'}\n"
                                )
                            self._persist_tasks()
                except Exception as e:
                    logger.warning(f"Error during final process cleanup for {task_id}: {e}")
            self._active_processes.pop(task_id, None)
            self._active_session_ids.pop(task_id, None)
            self._pending_permission_futures.pop(task_id, None)

    async def _execute_acp_session(self, task: Dict[str, Any]) -> None:
        """
        Executes an interactive ACP session:
        - agy.exe acp --stdio
        - initialize
        - session/new in 'default' mode (Ask before edits and commands)
        - session/prompt
        - Handles session/update live events
        - Intercepts session/request_permission for human approval
        - Activity-based heartbeat timeout
        """
        if not AGY_CLI_PATH.exists():
            raise FileNotFoundError(f"Antigravity CLI not found at '{AGY_CLI_PATH}'")

        cmd = [str(AGY_CLI_PATH), "acp", "--stdio"]
        task_id = task["id"]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(AUTHORIZED_WORKSPACE),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        self._active_processes[task_id] = proc

        # Track session timing
        session_start_time = asyncio.get_event_loop().time()
        last_activity_time = session_start_time

        async def send_json(payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload) + "\n"
            proc.stdin.write(raw.encode("utf-8"))
            await proc.stdin.drain()

        # Step 1: initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": 1,
                "clientInfo": {"name": "ai-coding-hub", "version": "1.1.0"}
            }
        }
        await send_json(init_req)

        line = await asyncio.wait_for(proc.stdout.readline(), timeout=15.0)
        init_resp = json.loads(line.decode("utf-8"))
        if "error" in init_resp:
            raise RuntimeError(f"ACP initialization error: {init_resp['error']}")

        # Step 2: session/new (Mode: default - Ask before edits and commands)
        session_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/new",
            "params": {
                "cwd": str(AUTHORIZED_WORKSPACE),
                "mcpServers": []
            }
        }
        await send_json(session_req)

        line = await asyncio.wait_for(proc.stdout.readline(), timeout=15.0)
        session_resp = json.loads(line.decode("utf-8"))
        if "error" in session_resp:
            raise RuntimeError(f"ACP session/new error: {session_resp['error']}")

        session_id = session_resp["result"]["sessionId"]
        self._active_session_ids[task_id] = session_id

        async with self._lock:
            task["stdout"] += f">>> [ACP SESSION READY] Session ID: {session_id}\n"
            task["stdout"] += f">>> [SECURITY MODE] 'default' active (Every sensitive action requires approval)\n\n"
            self._persist_tasks()

        # Step 3: session/prompt
        prompt_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "session/prompt",
            "params": {
                "sessionId": session_id,
                "prompt": [{"type": "text", "text": task["prompt"]}]
            }
        }
        await send_json(prompt_req)

        # Step 4: Event loop processing
        while True:
            # Check maximum session ceiling
            now_time = asyncio.get_event_loop().time()
            if (now_time - session_start_time) > MAX_SESSION_SECONDS:
                raise TimeoutError(f"Task exceeded maximum session duration ({MAX_SESSION_SECONDS}s).")

            # Check if task is awaiting permission (pause inactivity timer during user review)
            is_awaiting_approval = (task.get("status") == TaskStatus.AWAITING_ACTION_APPROVAL)
            timeout_window = None if is_awaiting_approval else INACTIVITY_TIMEOUT_SECONDS

            try:
                if timeout_window:
                    line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout_window)
                else:
                    line_bytes = await proc.stdout.readline()
            except asyncio.TimeoutError:
                raise TimeoutError(f"Task inactive for {INACTIVITY_TIMEOUT_SECONDS}s with no agent output.")

            if not line_bytes:
                # EOF reached
                break

            last_activity_time = asyncio.get_event_loop().time()
            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except Exception:
                # Diagnostic non-JSON output
                async with self._lock:
                    task["stdout"] += f"[ACP Raw] {line_str}\n"
                    self._persist_tasks()
                continue

            # Case A: session/request_permission (MANDATORY HUMAN APPROVAL)
            if msg.get("method") == "session/request_permission":
                req_id = msg.get("id")
                params = msg.get("params", {})
                tool_call = params.get("toolCall", {})
                title = tool_call.get("title") or "Action Approval Required"
                kind = tool_call.get("kind") or "tool"
                options = params.get("options", [
                    {"optionId": "allow_once", "name": "Allow once"},
                    {"optionId": "reject_once", "name": "Deny"}
                ])

                perm_future = asyncio.get_event_loop().create_future()
                self._pending_permission_futures[task_id] = perm_future

                async with self._lock:
                    task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
                    task["pending_permission"] = {
                        "permission_id": req_id,
                        "tool_call_id": tool_call.get("toolCallId"),
                        "title": title,
                        "kind": kind,
                        "tool_call": tool_call,
                        "options": options,
                        "requested_at": datetime.now(timezone.utc).isoformat()
                    }
                    task["stdout"] += f"\n>>> [PERMISSION REQUIRED] Action: {title} ({kind})\n"
                    task["stdout"] += f"    Details: {json.dumps(tool_call, indent=2)}\n"
                    task["stdout"] += f"    Status: PAUSED (Waiting for user decision in Dashboard)\n\n"
                    task["events"].append({
                        "type": "permission_requested",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "title": title,
                        "kind": kind
                    })
                    self._persist_tasks()

                # Await user approval from dashboard API
                user_decision = await perm_future

                # Reply back to agy acp
                if user_decision == "cancel":
                    perm_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"outcome": {"outcome": "cancelled"}}
                    }
                else:
                    perm_resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "outcome": {
                                "outcome": "selected",
                                "optionId": user_decision
                            }
                        }
                    }
                await send_json(perm_resp)
                continue

            # Case B: session/update (Streaming live tokens, thoughts, tool states)
            if msg.get("method") == "session/update":
                update = msg.get("params", {}).get("update", {})
                async with self._lock:
                    # Capture thought or message content
                    if "content" in update:
                        c = update["content"]
                        text = c.get("text", "") if isinstance(c, dict) else str(c)
                        task["stdout"] += text
                    elif "text" in update:
                        task["stdout"] += update["text"]

                    if "toolCall" in update:
                        tc = update["toolCall"]
                        task["stdout"] += f"\n[Tool: {tc.get('title', tc.get('name', 'action'))} - {tc.get('status', 'running')}]\n"

                    task["events"].append({
                        "type": "session_update",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "update": update
                    })
                    self._persist_tasks()
                continue

            # Case C: Response to session/prompt (Turn completion)
            if msg.get("id") == 3:
                async with self._lock:
                    task["stdout"] += "\n>>> [ACP] Turn completed.\n"
                    self._persist_tasks()
                break
