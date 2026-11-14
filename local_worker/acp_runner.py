"""
AI CODING HUB - Local Antigravity ACP Session Runner
Executes agy.exe acp --stdio, enforces workspace boundary confinement,
intercepts sensitive tool permissions for human authorization, and streams logs.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional
import uuid

from local_worker.process_cleanup import ProcessCleanupManager, ProcessCleanupResult
from shared.constants import (
    DEFAULT_AGY_CLI_PATH,
    DEFAULT_WORKSPACE_PATH,
    INACTIVITY_TIMEOUT_SECONDS,
    MAX_SESSION_SECONDS,
    DecisionType,
    TaskStatus,
)

logger = logging.getLogger("ai_coding_hub.acp_runner")

AUTHORIZED_WORKSPACE = DEFAULT_WORKSPACE_PATH
AGY_CLI_PATH = DEFAULT_AGY_CLI_PATH


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

    if resolved != AUTHORIZED_WORKSPACE:
        try:
            resolved.relative_to(AUTHORIZED_WORKSPACE)
        except ValueError:
            raise ValueError(
                f"Unauthorized workspace '{resolved}'. "
                f"Tasks are strictly restricted to '{AUTHORIZED_WORKSPACE}'."
            )

    return resolved


class ACPRunner:
    def __init__(self, workspace_path: Optional[Path] = None, agy_cli_path: Optional[Path] = None):
        self.workspace_path = workspace_path or AUTHORIZED_WORKSPACE
        self.agy_cli_path = agy_cli_path or AGY_CLI_PATH
        self.cleanup_manager = ProcessCleanupManager()
        self._active_proc: Optional[asyncio.subprocess.Process] = None
        self._active_session_id: Optional[str] = None
        self._pending_permission_future: Optional[asyncio.Future] = None
        self._mock_handler: Optional[Callable[[Dict[str, Any], Any], Coroutine[Any, Any, None]]] = None

    def set_mock_handler(self, handler: Optional[Callable[[Dict[str, Any], Any], Coroutine[Any, Any, None]]]) -> None:
        """Injects a mock ACP execution handler for automated testing."""
        self._mock_handler = handler

    def resolve_permission(self, permission_id: str, decision: str) -> bool:
        """Resolves an in-flight permission request waiting on human approval."""
        if self._pending_permission_future and not self._pending_permission_future.done():
            self._pending_permission_future.set_result(decision)
            return True
        return False

    async def abort(self) -> ProcessCleanupResult:
        """Aborts the active ACP session safely."""
        if self._pending_permission_future and not self._pending_permission_future.done():
            self._pending_permission_future.set_result("cancel")

        proc = self._active_proc
        if proc:
            # Send ACP session/cancel if possible
            if self._active_session_id and hasattr(proc, "stdin") and proc.stdin:
                try:
                    cancel_msg = {
                        "jsonrpc": "2.0",
                        "method": "session/cancel",
                        "params": {"sessionId": self._active_session_id}
                    }
                    proc.stdin.write((json.dumps(cancel_msg) + "\n").encode("utf-8"))
                    await proc.stdin.drain()
                except Exception:
                    pass

            return await self.cleanup_manager.terminate_process_tree(proc)

        return ProcessCleanupResult(success=True, tree_terminated=False, method="already_exited")

    async def execute_session(
        self,
        task_id: str,
        prompt: str,
        workspace_str: str,
        on_log: Callable[[str, str, Optional[Dict[str, Any]]], Coroutine[Any, Any, None]],
        on_permission: Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]
    ) -> Dict[str, Any]:
        """
        Executes a full interactive Antigravity ACP session over stdio.
        Strictly enforces workspace containment, asks before every sensitive action,
        and streams tokens/events.
        """
        resolved_workspace = validate_workspace(workspace_str)

        if self._mock_handler:
            task_dict = {"id": task_id, "prompt": prompt, "workspace": str(resolved_workspace)}
            await self._mock_handler(task_dict, self)
            return {"status": TaskStatus.COMPLETED, "exit_code": 0, "error": None}

        if not self.agy_cli_path.exists():
            raise FileNotFoundError(f"Antigravity CLI binary not found at '{self.agy_cli_path}'")

        cmd = [str(self.agy_cli_path), "acp", "--stdio"]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(resolved_workspace),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        self._active_proc = proc

        session_start_time = asyncio.get_event_loop().time()
        last_activity_time = session_start_time

        async def send_json(payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload) + "\n"
            proc.stdin.write(raw.encode("utf-8"))
            await proc.stdin.drain()

        try:
            # Step 1: Initialize
            await on_log(">>> [ACP INITIALIZING] Connecting to Antigravity ACP stdio server...\n", "", None)
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": 1,
                    "clientInfo": {"name": "ai-coding-hub-worker", "version": "2.0.0"}
                }
            }
            await send_json(init_req)

            line = await asyncio.wait_for(proc.stdout.readline(), timeout=15.0)
            init_resp = json.loads(line.decode("utf-8"))
            if "error" in init_resp:
                raise RuntimeError(f"ACP initialization error: {init_resp['error']}")

            # Step 2: Session/new (Mode: default - Ask before edits and commands)
            session_req = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/new",
                "params": {
                    "cwd": str(resolved_workspace),
                    "mcpServers": []
                }
            }
            await send_json(session_req)

            line = await asyncio.wait_for(proc.stdout.readline(), timeout=15.0)
            session_resp = json.loads(line.decode("utf-8"))
            if "error" in session_resp:
                raise RuntimeError(f"ACP session/new error: {session_resp['error']}")

            session_id = session_resp["result"]["sessionId"]
            self._active_session_id = session_id
            await on_log(
                f">>> [ACP SESSION READY] Session ID: {session_id}\n"
                f">>> [SECURITY MODE] 'default' active (Every sensitive action requires approval)\n\n",
                "",
                None
            )

            # Step 3: Session/prompt
            prompt_req = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {
                    "sessionId": session_id,
                    "prompt": [{"type": "text", "text": prompt}]
                }
            }
            await send_json(prompt_req)

            # Step 4: Event loop & permission interceptor
            while True:
                now = asyncio.get_event_loop().time()
                if now - session_start_time > MAX_SESSION_SECONDS:
                    raise TimeoutError(f"Session exceeded maximum duration of {MAX_SESSION_SECONDS} seconds.")

                # Wait for line with inactivity timeout
                try:
                    raw_line = await asyncio.wait_for(proc.stdout.readline(), timeout=INACTIVITY_TIMEOUT_SECONDS)
                except asyncio.TimeoutError:
                    raise TimeoutError(f"ACP session timed out after {INACTIVITY_TIMEOUT_SECONDS}s of inactivity.")

                if not raw_line:
                    break

                last_activity_time = asyncio.get_event_loop().time()
                text_line = raw_line.decode("utf-8").strip()
                if not text_line:
                    continue

                try:
                    msg = json.loads(text_line)
                except json.JSONDecodeError:
                    continue

                # Case A: session/prompt turn completion
                if msg.get("id") == 3:
                    if "error" in msg:
                        raise RuntimeError(f"ACP prompt error: {msg['error']}")
                    break

                method = msg.get("method")

                # Case B: session/update (Streaming live tokens, thoughts, tool states)
                if method == "session/update":
                    params = msg.get("params", {})
                    update = params.get("update", {})
                    update_type = update.get("sessionUpdateType")

                    if update_type == "agent_message_chunk":
                        content = update.get("content", {})
                        if content.get("type") == "text":
                            await on_log(content.get("text", ""), "", None)
                    elif update_type == "agent_thought_chunk":
                        thought = update.get("content", {}).get("text", "")
                        await on_log(f"\n[Thinking] {thought}\n", "", None)
                    elif update_type == "tool_call_update":
                        tool_name = update.get("toolCall", {}).get("name", "tool")
                        await on_log(f"\n[Tool Execution] {tool_name}...\n", "", {"type": "tool_call", "tool": tool_name})

                # Case C: session/request_permission (MANDATORY HUMAN APPROVAL)
                elif method == "session/request_permission":
                    perm_req_id = msg.get("id")
                    params = msg.get("params", {})
                    permission_id = str(uuid.uuid4())[:8]

                    tool_call = params.get("toolCall", {})
                    perm_data = {
                        "permission_id": permission_id,
                        "tool_call_id": tool_call.get("id", ""),
                        "title": tool_call.get("title", tool_call.get("name", "Sensitive Action")),
                        "kind": tool_call.get("kind", "tool_call"),
                        "tool_call": tool_call,
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }

                    # Create future to wait for human authorization
                    loop = asyncio.get_running_loop()
                    self._pending_permission_future = loop.create_future()

                    # Notify cloud
                    await on_permission(perm_data)

                    # Await human approval from cloud
                    decision = await self._pending_permission_future
                    self._pending_permission_future = None

                    # Translate decision to ACP response
                    # ACP options: {"decision": "allow_once"} or {"decision": "reject_once"}
                    acp_decision = "allow_once" if decision == DecisionType.ALLOW_ONCE else "reject_once"

                    resp = {
                        "jsonrpc": "2.0",
                        "id": perm_req_id,
                        "result": {
                            "outcome": {
                                "decision": acp_decision
                            }
                        }
                    }
                    await send_json(resp)

            return {"status": TaskStatus.COMPLETED, "exit_code": 0, "error": None}

        finally:
            if self._active_proc:
                await self.cleanup_manager.terminate_process_tree(self._active_proc)
                self._active_proc = None
            self._active_session_id = None
            self._pending_permission_future = None
