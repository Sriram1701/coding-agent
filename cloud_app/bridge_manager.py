"""
AI CODING HUB - Cloud Server Agent Bridge Manager
Handles authenticated WebSocket communication with the local Windows agent,
verifies cryptographic signatures, prevents message replay, and routes tasks/approvals.
"""

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from fastapi import WebSocket, WebSocketDisconnect

from shared.constants import (
    BRIDGE_HEARTBEAT_TIMEOUT,
    BRIDGE_NONCE_TTL,
    AgentBridgeStatus,
    TaskStatus,
)
from shared.models import BridgeMessage, BridgeMessageType
from shared.security import ReplayProtection, generate_token, verify_hmac

logger = logging.getLogger("ai_coding_hub.bridge_manager")


class BridgeManager:
    def __init__(self, task_store: Any, secret: Optional[str] = None):
        self.task_store = task_store
        # Load bridge secrets from environment or passed argument (never hardcode secrets)
        env_secret = os.environ.get("AGENT_BRIDGE_SECRET", "")
        raw_secret = secret or env_secret
        if not raw_secret:
            raw_secret = generate_token(32)
            logger.info("AGENT_BRIDGE_SECRET not set in environment; generated ephemeral bridge secret.")
        self.secrets = [s.strip() for s in raw_secret.split(",") if s.strip()]
        self.replay_guard = ReplayProtection(ttl_seconds=BRIDGE_NONCE_TTL)

        self._active_websocket: Optional[WebSocket] = None
        self._active_worker_id: Optional[str] = None
        self._last_heartbeat: float = 0
        self._lock = asyncio.Lock()

    @property
    def is_connected(self) -> bool:
        return self._active_websocket is not None

    @property
    def status(self) -> str:
        if not self.is_connected:
            return AgentBridgeStatus.OFFLINE
        if time.time() - self._last_heartbeat > BRIDGE_HEARTBEAT_TIMEOUT:
            return AgentBridgeStatus.OFFLINE
        return AgentBridgeStatus.ONLINE

    def get_agent_status_dict(self) -> Dict[str, Any]:
        """Provides status details for the dashboard telemetry card."""
        is_online = (self.status == AgentBridgeStatus.ONLINE)
        return {
            "agent": "antigravity",
            "cli_detected": is_online,
            "status": "online" if is_online else "offline",
            "bridge_connected": is_online,
            "worker_id": self._active_worker_id if is_online else None,
            "last_heartbeat": self._last_heartbeat if is_online else None,
            "acp_protocol": "Agent Client Protocol v1 (stdio)",
            "security_mode": "Strict Human-in-the-Loop (Every sensitive action requires approval)",
            "supported_tools": ["edit_file", "write_file", "run_command", "read_file"]
        }

    async def authenticate_worker(self, websocket: WebSocket) -> Optional[str]:
        """
        Performs cryptographic handshake with the connecting worker.
        Validates HMAC signature and verifies freshness/nonce.
        """
        try:
            raw_data = await asyncio.wait_for(websocket.receive_text(), timeout=10.0)
            message = json.loads(raw_data)
        except Exception as e:
            logger.warning(f"Bridge handshake timeout or invalid JSON: {e}")
            await websocket.close(code=1008, reason="Handshake timeout or invalid payload")
            return None

        if message.get("type") != BridgeMessageType.AUTH:
            logger.warning(f"Expected auth message, received: {message.get('type')}")
            await websocket.close(code=1008, reason="Expected auth message")
            return None

        payload = message.get("payload", {})
        worker_id = payload.get("worker_id")
        timestamp = payload.get("timestamp")
        nonce = payload.get("nonce")
        signature = payload.get("signature")

        if not all([worker_id, timestamp, nonce, signature]):
            logger.warning("Auth handshake missing required security fields")
            await websocket.send_text(json.dumps({
                "type": BridgeMessageType.AUTH_FAIL,
                "payload": {"reason": "Missing required authentication fields"}
            }))
            await websocket.close(code=1008, reason="Incomplete authentication")
            return None

        # Verify timestamp and replay nonce
        is_fresh, reason = self.replay_guard.validate_and_record(nonce, float(timestamp))
        if not is_fresh:
            logger.warning(f"Auth handshake replay validation failed: {reason}")
            await websocket.send_text(json.dumps({
                "type": BridgeMessageType.AUTH_FAIL,
                "payload": {"reason": f"Security validation failed: {reason}"}
            }))
            await websocket.close(code=1008, reason="Security validation failed")
            return None

        # Verify HMAC signature over worker_id:timestamp:nonce
        signed_data = f"{worker_id}:{timestamp}:{nonce}"
        if not verify_hmac(self.secrets, signed_data, signature):
            logger.warning(f"Auth handshake invalid signature from worker '{worker_id}'")
            await websocket.send_text(json.dumps({
                "type": BridgeMessageType.AUTH_FAIL,
                "payload": {"reason": "Invalid signature or unauthorized secret"}
            }))
            await websocket.close(code=1008, reason="Unauthorized secret")
            return None

        # Auth successful
        await websocket.send_text(json.dumps({
            "type": BridgeMessageType.AUTH_OK,
            "payload": {
                "worker_id": worker_id,
                "server_time": time.time(),
                "status": "connected"
            }
        }))
        logger.info(f"Worker '{worker_id}' successfully authenticated over WSS bridge.")
        return worker_id

    async def handle_connection(self, websocket: WebSocket) -> None:
        """Main lifecycle loop for an authenticated agent bridge connection."""
        await websocket.accept()
        worker_id = await self.authenticate_worker(websocket)
        if not worker_id:
            return

        async with self._lock:
            # If an existing worker is connected, terminate old connection
            if self._active_websocket and self._active_websocket != websocket:
                try:
                    await self._active_websocket.close(code=1000, reason="Superseded by new worker connection")
                except Exception:
                    pass
            self._active_websocket = websocket
            self._active_worker_id = worker_id
            self._last_heartbeat = time.time()

        logger.info(f"Local agent bridge ONLINE: worker '{worker_id}'")

        # Automatically dispatch any queued/approved tasks upon reconnection
        await self.dispatch_queued_tasks()

        try:
            while True:
                raw_data = await websocket.receive_text()
                message = json.loads(raw_data)
                msg_type = message.get("type")
                payload = message.get("payload", {})

                if msg_type == BridgeMessageType.HEARTBEAT:
                    self._last_heartbeat = time.time()
                    await websocket.send_text(json.dumps({
                        "type": BridgeMessageType.HEARTBEAT_ACK,
                        "payload": {"server_time": time.time()}
                    }))

                elif msg_type == BridgeMessageType.TASK_LOGS:
                    task_id = payload.get("task_id")
                    if task_id:
                        await self.task_store.append_logs(
                            task_id=task_id,
                            stdout_chunk=payload.get("stdout", ""),
                            stderr_chunk=payload.get("stderr", ""),
                            event=payload.get("event")
                        )

                elif msg_type == BridgeMessageType.PERMISSION_REQUEST:
                    task_id = payload.get("task_id")
                    perm_data = payload.get("permission_data")
                    if task_id and perm_data:
                        await self.task_store.set_pending_permission(task_id, perm_data)

                elif msg_type == BridgeMessageType.TASK_STATUS:
                    task_id = payload.get("task_id")
                    status = payload.get("status")
                    if task_id and status:
                        if status == TaskStatus.RUNNING:
                            await self.task_store.mark_task_running(task_id, worker_id)
                        elif status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                            await self.task_store.finalize_task(
                                task_id=task_id,
                                final_status=status,
                                exit_code=payload.get("exit_code", 0),
                                error=payload.get("error")
                            )

        except (WebSocketDisconnect, asyncio.CancelledError):
            logger.info(f"Worker '{worker_id}' disconnected from WSS bridge.")
        except Exception as e:
            logger.error(f"Error on agent bridge connection with worker '{worker_id}': {e}")
        finally:
            async with self._lock:
                if self._active_websocket == websocket:
                    self._active_websocket = None
                    self._active_worker_id = None
            logger.info("Local agent bridge OFFLINE.")

    async def dispatch_queued_tasks(self) -> None:
        """Dispatches all eligible queued tasks to the connected worker."""
        if not self.is_connected:
            return

        dispatchable = self.task_store.get_dispatchable_tasks()
        for task in dispatchable:
            await self.send_task_dispatch(task)

    async def send_task_dispatch(self, task: Dict[str, Any]) -> bool:
        """Sends a single task execution payload to the active worker."""
        if not self.is_connected or not self._active_websocket:
            return False

        msg = {
            "type": BridgeMessageType.TASK_DISPATCH,
            "payload": {
                "task_id": task["id"],
                "prompt": task["prompt"],
                "workspace": task["workspace"],
                "agent": task.get("agent", "antigravity")
            }
        }
        try:
            await self._active_websocket.send_text(json.dumps(msg))
            await self.task_store.mark_task_running(task["id"], self._active_worker_id or "local_worker")
            logger.info(f"Dispatched task {task['id']} to worker '{self._active_worker_id}'")
            return True
        except Exception as e:
            logger.error(f"Failed to dispatch task {task['id']} over bridge: {e}")
            return False

    async def forward_permission_decision(self, task_id: str, permission_id: str, decision: str) -> bool:
        """Forwards user's human approval/rejection decision to the local worker."""
        if not self.is_connected or not self._active_websocket:
            return False

        msg = {
            "type": BridgeMessageType.PERMISSION_DECISION,
            "payload": {
                "task_id": task_id,
                "permission_id": permission_id,
                "decision": decision
            }
        }
        try:
            await self._active_websocket.send_text(json.dumps(msg))
            logger.info(f"Forwarded action decision '{decision}' for task {task_id} to worker.")
            return True
        except Exception as e:
            logger.error(f"Failed to forward permission decision for task {task_id}: {e}")
            return False

    async def forward_task_cancel(self, task_id: str) -> bool:
        """Sends task cancellation notification to the local worker."""
        if not self.is_connected or not self._active_websocket:
            return False

        msg = {
            "type": BridgeMessageType.TASK_CANCEL,
            "payload": {"task_id": task_id}
        }
        try:
            await self._active_websocket.send_text(json.dumps(msg))
            logger.info(f"Sent task cancellation notification for {task_id} to worker.")
            return True
        except Exception as e:
            logger.error(f"Failed to send task cancellation over bridge: {e}")
            return False
