"""
AI CODING HUB - Cloud Server Persistent Task Store & Queue
Manages task lifecycles, offline queuing, approval gating, and live SSE event broadcasting.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from shared.constants import (
    DEFAULT_WORKSPACE_PATH,
    DecisionType,
    TaskStatus,
)

logger = logging.getLogger("ai_coding_hub.cloud_task_store")


class CloudTaskStore:
    def __init__(self, storage_path: Optional[Path] = None):
        if storage_path:
            self.storage_path = Path(storage_path).resolve()
        else:
            self.storage_path = Path("data/tasks.json").resolve()

        self._tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._subscribers: Dict[str, Set[asyncio.Queue]] = {}
        self._load_tasks()

    def _load_tasks(self) -> None:
        """Loads tasks from persistent storage."""
        if not self.storage_path.exists():
            return
        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for t in data:
                        if isinstance(t, dict) and "id" in t:
                            self._tasks[t["id"]] = t
                elif isinstance(data, dict):
                    self._tasks = data
        except Exception as e:
            logger.error(f"Failed to load tasks from {self.storage_path}: {e}")

    def _persist_tasks(self) -> None:
        """Safely persists tasks to disk."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            temp_file = self.storage_path.with_suffix(".tmp")
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(list(self._tasks.values()), f, indent=2, ensure_ascii=False)
            temp_file.replace(self.storage_path)
        except Exception as e:
            logger.error(f"Failed to persist tasks to {self.storage_path}: {e}")

    async def submit_task(self, prompt: str, workspace: str, agent: Optional[str] = "antigravity", user: str = "anonymous") -> Dict[str, Any]:
        """Submits a new task into PENDING_APPROVAL."""
        if not prompt or not prompt.strip():
            raise ValueError("Task prompt cannot be empty.")
        if not workspace or not workspace.strip():
            raise ValueError("Workspace cannot be empty.")
        if agent and agent.lower() != "antigravity":
            raise ValueError(f"Agent '{agent}' is not supported. Sole active agent is 'antigravity'.")

        task_id = f"task_{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        task_record: Dict[str, Any] = {
            "id": task_id,
            "prompt": prompt.strip(),
            "workspace": workspace.strip(),
            "agent": "antigravity",
            "status": TaskStatus.PENDING_APPROVAL,
            "created_at": now,
            "updated_at": now,
            "executed_at": None,
            "completed_at": None,
            "submitted_by": user,
            "approved_by": None,
            "exit_code": None,
            "error": None,
            "stdout": "",
            "stderr": "",
            "events": [],
            "pending_permission": None,
            "permission_history": []
        }

        async with self._lock:
            self._tasks[task_id] = task_record
            self._persist_tasks()

        logger.info(f"Task {task_id} submitted by {user} (Status: PENDING_APPROVAL)")
        return task_record

    def list_tasks(self, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists tasks filtered optionally by status, sorted newest first."""
        tasks = list(self._tasks.values())
        if status_filter:
            tasks = [t for t in tasks if t.get("status") == status_filter]
        return sorted(tasks, key=lambda x: x.get("created_at", ""), reverse=True)

    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single task record."""
        return self._tasks.get(task_id)

    async def approve_task(self, task_id: str, user: str) -> Dict[str, Any]:
        """Approves a task in PENDING_APPROVAL and queues it for worker dispatch."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise KeyError(f"Task '{task_id}' not found.")

            current_status = task.get("status")
            if current_status != TaskStatus.PENDING_APPROVAL:
                raise ValueError(
                    f"Cannot approve task {task_id}: current status is '{current_status}'. "
                    f"Only tasks in PENDING_APPROVAL can be approved."
                )

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.QUEUED
            task["approved_by"] = user
            task["updated_at"] = now
            task["stdout"] += f">>> [TASK APPROVED] Authorized by user '{user}'. Queued for dispatch.\n"
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": TaskStatus.QUEUED,
            "new_text": f">>> [TASK APPROVED] Authorized by user '{user}'. Queued for dispatch.\n"
        })
        logger.info(f"Task {task_id} approved by {user} and moved to QUEUED.")
        return task

    async def reject_task(self, task_id: str, reason: Optional[str], user: str) -> Dict[str, Any]:
        """Rejects a task in PENDING_APPROVAL."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise KeyError(f"Task '{task_id}' not found.")

            current_status = task.get("status")
            if current_status != TaskStatus.PENDING_APPROVAL:
                raise ValueError(
                    f"Cannot reject task {task_id}: status is '{current_status}'. "
                    f"Only tasks in PENDING_APPROVAL can be rejected."
                )

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.REJECTED
            task["error"] = reason or "Rejected by user."
            task["updated_at"] = now
            task["stdout"] += f"\n>>> [TASK REJECTED] {reason or 'Rejected by user.'}\n"
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": TaskStatus.REJECTED,
            "error": reason or "Rejected by user."
        })
        return task

    async def cancel_task(self, task_id: str, user: str) -> Dict[str, Any]:
        """Cancels a task if it is active or pending."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise KeyError(f"Task '{task_id}' not found.")

            current_status = task.get("status")
            if current_status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.REJECTED, TaskStatus.CANCELLED]:
                raise ValueError(f"Task {task_id} is already finalized with status '{current_status}'.")

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.CANCELLED
            task["error"] = f"Cancelled by user '{user}'."
            task["updated_at"] = now
            task["pending_permission"] = None
            task["stdout"] += f"\n>>> [TASK CANCELLED] Cancelled by user '{user}'.\n"
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": TaskStatus.CANCELLED,
            "error": f"Cancelled by user '{user}'."
        })
        return task

    async def mark_task_running(self, task_id: str, worker_id: str) -> Optional[Dict[str, Any]]:
        """Transitions QUEUED/APPROVED task to RUNNING once worker acknowledges dispatch."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None
            if task.get("status") not in [TaskStatus.APPROVED, TaskStatus.QUEUED]:
                return None

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.RUNNING
            task["executed_at"] = now
            task["updated_at"] = now
            task["stdout"] += f">>> [DISPATCHED] Execution started on local worker '{worker_id}'.\n"
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": TaskStatus.RUNNING,
            "new_text": f">>> [DISPATCHED] Execution started on local worker '{worker_id}'.\n"
        })
        return task

    async def set_pending_permission(self, task_id: str, permission_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Sets task to AWAITING_ACTION_APPROVAL when local worker requests human permission."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.get("status") != TaskStatus.RUNNING:
                return None

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = TaskStatus.AWAITING_ACTION_APPROVAL
            task["pending_permission"] = permission_data
            task["updated_at"] = now
            task["stdout"] += f"\n>>> [ACTION APPROVAL REQUIRED] Tool: {permission_data.get('title')}\n"
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": TaskStatus.AWAITING_ACTION_APPROVAL,
            "pending_permission": permission_data
        })
        return task

    async def resolve_task_permission(self, task_id: str, decision: str, user: str) -> Dict[str, Any]:
        """Resolves an interactive sensitive-action permission request."""
        if decision not in [DecisionType.ALLOW_ONCE, DecisionType.REJECT_ONCE]:
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

            now = datetime.now(timezone.utc).isoformat()
            record = {
                "permission_id": pending.get("permission_id"),
                "tool_call_id": pending.get("tool_call_id"),
                "title": pending.get("title"),
                "kind": pending.get("kind"),
                "tool_call": pending.get("tool_call"),
                "decision": decision,
                "decided_by": user,
                "decided_at": now
            }
            task["permission_history"].append(record)

            outcome_label = "APPROVED (Allow Once)" if decision == DecisionType.ALLOW_ONCE else "REJECTED (Deny)"
            task["stdout"] += f"\n>>> [ACTION DECISION] {outcome_label} by {user}: {pending.get('title')}\n"
            task["events"].append({
                "type": "permission_decision",
                "timestamp": now,
                "decision": decision,
                "title": pending.get("title"),
                "user": user
            })

            task["status"] = TaskStatus.RUNNING
            task["pending_permission"] = None
            task["updated_at"] = now
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": TaskStatus.RUNNING,
            "pending_permission": None,
            "new_text": f"\n>>> [ACTION DECISION] {outcome_label} by {user}: {pending.get('title')}\n"
        })
        return task

    async def append_logs(self, task_id: str, stdout_chunk: str = "", stderr_chunk: str = "", event: Optional[Dict[str, Any]] = None) -> None:
        """Appends streaming logs and events to the task."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return

            if stdout_chunk:
                task["stdout"] += stdout_chunk
            if stderr_chunk:
                task["stderr"] += stderr_chunk
            if event:
                task["events"].append(event)
            task["updated_at"] = datetime.now(timezone.utc).isoformat()
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": task.get("status"),
            "new_text": stdout_chunk,
            "event": event
        })

    async def finalize_task(self, task_id: str, final_status: str, exit_code: Optional[int] = 0, error: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Marks a task as completed or failed."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None

            now = datetime.now(timezone.utc).isoformat()
            task["status"] = final_status
            task["exit_code"] = exit_code
            task["error"] = error
            task["completed_at"] = now
            task["updated_at"] = now
            task["pending_permission"] = None
            if final_status == TaskStatus.COMPLETED:
                task["stdout"] += f"\n>>> [ACP COMPLETED] Task execution completed successfully.\n"
            else:
                task["stdout"] += f"\n>>> [ACP FAILED] Execution error: {error or 'Unknown failure'}\n"
            self._persist_tasks()

        await self._broadcast_update(task_id, {
            "task_id": task_id,
            "status": final_status,
            "exit_code": exit_code,
            "error": error
        })
        return task

    def get_dispatchable_tasks(self) -> List[Dict[str, Any]]:
        """Returns all approved tasks waiting in the queue."""
        return [t for t in self._tasks.values() if t.get("status") in [TaskStatus.APPROVED, TaskStatus.QUEUED]]

    # -------------------------------------------------------------------------
    # SSE Subscription Mechanics
    # -------------------------------------------------------------------------
    def subscribe(self, task_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(task_id, set()).add(q)
        return q

    def unsubscribe(self, task_id: str, q: asyncio.Queue) -> None:
        if task_id in self._subscribers:
            self._subscribers[task_id].discard(q)
            if not self._subscribers[task_id]:
                del self._subscribers[task_id]

    async def _broadcast_update(self, task_id: str, data: Dict[str, Any]) -> None:
        subscribers = self._subscribers.get(task_id, set()).copy()
        for q in subscribers:
            try:
                await q.put(data)
            except Exception:
                pass
