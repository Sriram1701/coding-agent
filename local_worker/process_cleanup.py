"""
AI CODING HUB - Local Windows Process Cleanup Engine
Provides safe, audited process-tree termination using Windows-native taskkill /T /F,
exit code 128 handling, concurrent cleanup synchronization, and fallback escalation.
"""

import asyncio
import logging
from typing import Any, Callable, Coroutine, Dict, Optional

logger = logging.getLogger("ai_coding_hub.process_cleanup")


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


class ProcessCleanupManager:
    def __init__(self):
        self._in_flight_cleanups: Dict[int, asyncio.Future] = {}
        self._taskkill_executor: Optional[Callable[[int], Coroutine[Any, Any, int]]] = None

    def set_taskkill_executor(self, executor: Optional[Callable[[int], Coroutine[Any, Any, int]]]) -> None:
        """Injects a custom/mocked taskkill runner for automated testing."""
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
        6. Explicitly reports whether complete tree termination was guaranteed or root-only fallback occurred.
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

        proc_ref_id = id(proc)
        if proc_ref_id in self._in_flight_cleanups:
            cleanup_future = self._in_flight_cleanups[proc_ref_id]
            return await asyncio.shield(cleanup_future)

        loop = asyncio.get_running_loop()
        cleanup_future = loop.create_future()
        self._in_flight_cleanups[proc_ref_id] = cleanup_future

        result: Optional[ProcessCleanupResult] = None
        try:
            taskkill_success = False
            taskkill_is_128 = False
            taskkill_err = None

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
                    logger.warning(f"taskkill.exe not found for PID {pid}. Falling back to proc.terminate().")
                except asyncio.TimeoutError:
                    taskkill_err = "taskkill execution timed out after 5.0s"
                    logger.warning(f"taskkill timed out for PID {pid}. Falling back to proc.terminate().")
                except Exception as e:
                    taskkill_err = str(e)
                    logger.warning(f"taskkill failed for PID {pid}: {e}. Falling back to proc.terminate().")

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

            # Fallback Escalation (terminate -> bounded wait -> kill -> bounded wait)
            fallback_err = None
            try:
                if getattr(proc, "returncode", None) is None:
                    if hasattr(proc, "terminate"):
                        try:
                            proc.terminate()
                        except ProcessLookupError:
                            pass
                    if hasattr(proc, "wait") and getattr(proc, "returncode", None) is None:
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass

                if getattr(proc, "returncode", None) is None:
                    if hasattr(proc, "kill"):
                        try:
                            proc.kill()
                        except ProcessLookupError:
                            pass
                    if hasattr(proc, "wait") and getattr(proc, "returncode", None) is None:
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=1.0)
                        except asyncio.TimeoutError:
                            pass
            except Exception as e:
                fallback_err = str(e)
                logger.warning(f"Fallback process escalation error for PID {pid}: {e}")

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
