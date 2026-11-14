"""
AI CODING HUB - Local Windows Agent Bridge Worker
Connects outbound via authenticated WSS to the cloud dashboard server,
executes the Antigravity ACP stdio subprocess locally, and forwards human approvals.
"""

import asyncio
import json
import logging
import os
import platform
import signal
import sys
import time
from typing import Optional

import websockets

from local_worker.acp_runner import ACPRunner
from shared.constants import (
    BRIDGE_HEARTBEAT_INTERVAL,
    AgentBridgeStatus,
    TaskStatus,
)
from shared.models import BridgeMessageType
from shared.security import compute_hmac, generate_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("ai_coding_hub.local_worker")


class AgentBridgeWorker:
    def __init__(
        self,
        cloud_ws_url: Optional[str] = None,
        bridge_secret: Optional[str] = None,
        worker_id: Optional[str] = None
    ):
        self.cloud_ws_url = cloud_ws_url or os.environ.get("ACH_CLOUD_WS_URL", "ws://127.0.0.1:8000/ws/agent-bridge")
        self.bridge_secret = bridge_secret or os.environ.get("AGENT_BRIDGE_SECRET", "")
        self.worker_id = worker_id or os.environ.get("ACH_WORKER_ID", f"win_agent_{platform.node().lower()}")
        self.runner = ACPRunner()
        self._running = True
        self._ws: Optional[websockets.WebSocketClientProtocol] = None
        self._active_task_id: Optional[str] = None

    async def connect_and_authenticate(self) -> websockets.WebSocketClientProtocol:
        """Establishes outbound WebSocket connection and conducts cryptographic handshake."""
        if not self.bridge_secret:
            raise ValueError(
                "AGENT_BRIDGE_SECRET is not configured. Set the AGENT_BRIDGE_SECRET environment variable before starting."
            )
        logger.info(f"Connecting to Cloud Agent Gateway: {self.cloud_ws_url}")
        ws = await websockets.connect(self.cloud_ws_url, ping_interval=20, ping_timeout=20)

        # Generate fresh timestamp, nonce, and HMAC-SHA256 signature
        now = time.time()
        nonce = generate_token(16)
        signed_data = f"{self.worker_id}:{now}:{nonce}"
        signature = compute_hmac(self.bridge_secret, signed_data)

        auth_msg = {
            "type": BridgeMessageType.AUTH,
            "payload": {
                "worker_id": self.worker_id,
                "timestamp": now,
                "nonce": nonce,
                "signature": signature
            }
        }
        await ws.send(json.dumps(auth_msg))

        resp_raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
        resp = json.loads(resp_raw)

        if resp.get("type") != BridgeMessageType.AUTH_OK:
            reason = resp.get("payload", {}).get("reason", "Unknown authentication error")
            await ws.close()
            raise PermissionError(f"Bridge authentication rejected by server: {reason}")

        logger.info(f"Handshake successful! Worker '{self.worker_id}' authenticated with cloud gateway.")
        return ws

    async def _heartbeat_loop(self, ws: websockets.WebSocketClientProtocol) -> None:
        """Sends periodic heartbeats to maintain active status on the cloud dashboard."""
        try:
            while self._running:
                await asyncio.sleep(BRIDGE_HEARTBEAT_INTERVAL)
                heartbeat = {
                    "type": BridgeMessageType.HEARTBEAT,
                    "payload": {
                        "worker_id": self.worker_id,
                        "timestamp": time.time(),
                        "status": AgentBridgeStatus.BUSY if self._active_task_id else AgentBridgeStatus.ONLINE
                    }
                }
                await ws.send(json.dumps(heartbeat))
        except (websockets.ConnectionClosed, asyncio.CancelledError):
            pass

    async def _handle_task_dispatch(self, ws: websockets.WebSocketClientProtocol, payload: dict) -> None:
        """Executes an authorized task dispatched from the cloud."""
        task_id = payload["task_id"]
        prompt = payload["prompt"]
        workspace = payload["workspace"]
        self._active_task_id = task_id

        logger.info(f"Received task dispatch: {task_id} (Prompt: '{prompt[:40]}...')")

        # Report task status RUNNING
        await ws.send(json.dumps({
            "type": BridgeMessageType.TASK_STATUS,
            "payload": {"task_id": task_id, "status": TaskStatus.RUNNING}
        }))

        async def on_log_chunk(stdout_text: str, stderr_text: str, event_data: Optional[dict] = None) -> None:
            msg = {
                "type": BridgeMessageType.TASK_LOGS,
                "payload": {
                    "task_id": task_id,
                    "stdout": stdout_text,
                    "stderr": stderr_text,
                    "event": event_data
                }
            }
            await ws.send(json.dumps(msg))

        async def on_permission_request(perm_data: dict) -> None:
            msg = {
                "type": BridgeMessageType.PERMISSION_REQUEST,
                "payload": {
                    "task_id": task_id,
                    "permission_data": perm_data
                }
            }
            await ws.send(json.dumps(msg))

        try:
            res = await self.runner.execute_session(
                task_id=task_id,
                prompt=prompt,
                workspace_str=workspace,
                on_log=on_log_chunk,
                on_permission=on_permission_request
            )
            await ws.send(json.dumps({
                "type": BridgeMessageType.TASK_STATUS,
                "payload": {
                    "task_id": task_id,
                    "status": res["status"],
                    "exit_code": res.get("exit_code", 0),
                    "error": res.get("error")
                }
            }))
        except Exception as e:
            logger.error(f"Task {task_id} execution error: {e}")
            await ws.send(json.dumps({
                "type": BridgeMessageType.TASK_STATUS,
                "payload": {
                    "task_id": task_id,
                    "status": TaskStatus.FAILED,
                    "exit_code": 1,
                    "error": str(e)
                }
            }))
        finally:
            self._active_task_id = None

    async def run(self) -> None:
        """Main lifecycle loop with exponential backoff automatic reconnection."""
        delay = 2.0
        max_delay = 30.0

        while self._running:
            heartbeat_task = None
            try:
                ws = await self.connect_and_authenticate()
                self._ws = ws
                delay = 2.0  # Reset backoff on successful connection

                heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))

                while self._running:
                    raw_msg = await ws.recv()
                    message = json.loads(raw_msg)
                    msg_type = message.get("type")
                    payload = message.get("payload", {})

                    if msg_type == BridgeMessageType.TASK_DISPATCH:
                        asyncio.create_task(self._handle_task_dispatch(ws, payload))

                    elif msg_type == BridgeMessageType.PERMISSION_DECISION:
                        perm_id = payload.get("permission_id", "")
                        decision = payload.get("decision", "")
                        self.runner.resolve_permission(perm_id, decision)

                    elif msg_type == BridgeMessageType.TASK_CANCEL:
                        task_id = payload.get("task_id")
                        if self._active_task_id == task_id:
                            await self.runner.abort()

            except (websockets.ConnectionClosed, ConnectionRefusedError, OSError) as e:
                logger.warning(f"Bridge disconnected ({e}). Reconnecting in {delay:.1f}s...")
            except PermissionError as e:
                logger.error(f"Bridge authentication error: {e}. Check AGENT_BRIDGE_SECRET.")
            except Exception as e:
                logger.error(f"Unexpected worker error: {e}")
            finally:
                if heartbeat_task and not heartbeat_task.done():
                    heartbeat_task.cancel()
                self._ws = None

            if self._running:
                await asyncio.sleep(delay)
                delay = min(delay * 2.0, max_delay)

    def stop(self) -> None:
        self._running = False


def main():
    worker = AgentBridgeWorker()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def handle_signal():
        logger.info("Shutdown signal received. Stopping worker...")
        worker.stop()

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, handle_signal)
        except NotImplementedError:
            pass  # Windows event loop limitation

    try:
        loop.run_until_complete(worker.run())
    except KeyboardInterrupt:
        logger.info("Worker stopped by user.")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
