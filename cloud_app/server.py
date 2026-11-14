"""
AI CODING HUB - Cloud Server FastAPI Application
Provides web dashboard serving, authenticated REST APIs, CSRF protection,
and the authenticated Agent Bridge WebSocket endpoint.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Header,
    Query,
    Request,
    Response,
    WebSocket,
    status,
)
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from cloud_app.auth import (
    SessionData,
    auth_manager,
    get_client_ip,
    get_current_user,
    verify_csrf_token,
)
from cloud_app.bridge_manager import BridgeManager
from cloud_app.task_store import CloudTaskStore
from shared.constants import (
    COOKIE_NAME,
    CSRF_HEADER_NAME,
    DEFAULT_WORKSPACE_PATH,
    TaskStatus,
)
from shared.models import (
    LoginRequest,
    LoginResponse,
    TaskCreateRequest,
    TaskPermissionRequest,
    TaskRejectRequest,
)

logger = logging.getLogger("ai_coding_hub.cloud_server")

# Base Directories
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

# Configuration
COOKIE_SECURE = os.environ.get("ACH_COOKIE_SECURE", "false").lower() in ["1", "true", "yes"]

# Initialize Task Store and Bridge Manager
task_store = CloudTaskStore()
bridge_manager = BridgeManager(task_store=task_store)

app = FastAPI(
    title="AI CODING HUB Cloud Server",
    description="Online Dashboard and Secure Agent Relay Gateway",
    version="2.0.0"
)

# Mount static web assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# -----------------------------------------------------------------------------
# Public Web & Health Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def home():
    return {
        "status": "online",
        "service": "AI CODING HUB Cloud Gateway",
        "version": "2.0.0",
        "agent_status": bridge_manager.status
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "agent_bridge": bridge_manager.status
    }


@app.get("/dashboard")
def get_dashboard():
    """Serves the dashboard user interface."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI not found")
    return FileResponse(index_file)


# -----------------------------------------------------------------------------
# Authentication Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/auth/login", response_model=LoginResponse)
async def login(request: Request, response: Response, payload: LoginRequest):
    """
    Authenticates username and password against PBKDF2 hash.
    Sets secure HttpOnly session cookie and returns a CSRF token.
    Enforces IP rate limiting.
    """
    client_ip = get_client_ip(request)
    success, session_id, csrf_token = auth_manager.authenticate(
        username=payload.username,
        password=payload.password,
        client_ip=client_ip
    )

    if not success or not session_id or not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )

    response.set_cookie(
        key=COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/"
    )

    return LoginResponse(
        status="ok",
        username=payload.username,
        csrf_token=csrf_token,
        message="Authentication successful."
    )


@app.post("/api/auth/logout")
async def logout(response: Response, user: SessionData = Depends(get_current_user)):
    """Terminates session and clears HTTP-only cookie."""
    auth_manager.terminate_session(user.csrf_token)
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"status": "logged_out", "message": "Session terminated."}


@app.get("/api/auth/me")
async def auth_me(user: SessionData = Depends(get_current_user)):
    """Returns current authenticated session details and active CSRF token."""
    return {
        "authenticated": True,
        "username": user.username,
        "csrf_token": user.csrf_token
    }


# -----------------------------------------------------------------------------
# Agent Telemetry Endpoints (Authenticated)
# -----------------------------------------------------------------------------

@app.get("/api/agent/status")
def get_agent_status(user: SessionData = Depends(get_current_user)):
    """Returns real-time connection status of the local Antigravity ACP worker."""
    return bridge_manager.get_agent_status_dict()


# -----------------------------------------------------------------------------
# Task Management & Human Approval Endpoints (Authenticated & CSRF Protected)
# -----------------------------------------------------------------------------

@app.post("/api/tasks", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf_token)])
async def submit_task(request: TaskCreateRequest, user: SessionData = Depends(get_current_user)):
    """
    Submits a new coding task into PENDING_APPROVAL.
    CRITICAL: Does NOT dispatch or execute agent without explicit human approval.
    """
    try:
        task = await task_store.submit_task(
            prompt=request.prompt,
            workspace=request.workspace,
            agent=request.agent,
            user=user.username
        )
        return task
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/tasks")
def list_tasks(status: Optional[str] = Query(None), user: SessionData = Depends(get_current_user)):
    """Lists tasks with optional status filter."""
    return task_store.list_tasks(status_filter=status)


@app.get("/api/tasks/{task_id}")
def get_task_details(task_id: str, user: SessionData = Depends(get_current_user)):
    """Retrieves full details of a specific task."""
    task = task_store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    return task


@app.post("/api/tasks/{task_id}/approve", dependencies=[Depends(verify_csrf_token)])
async def approve_task(task_id: str, user: SessionData = Depends(get_current_user)):
    """
    Explicit user approval to transition a task from PENDING_APPROVAL.
    Dispatches to local worker if connected, or retains in QUEUED status if offline.
    """
    try:
        task = await task_store.approve_task(task_id, user=user.username)
        # If worker is currently online, dispatch immediately
        if bridge_manager.is_connected:
            await bridge_manager.send_task_dispatch(task)
        return task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/tasks/{task_id}/reject", dependencies=[Depends(verify_csrf_token)])
async def reject_task(task_id: str, request: Optional[TaskRejectRequest] = None, user: SessionData = Depends(get_current_user)):
    """Rejects a task in PENDING_APPROVAL. Never dispatches to worker."""
    reason = request.reason if request else None
    try:
        task = await task_store.reject_task(task_id, reason=reason, user=user.username)
        return task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/tasks/{task_id}/permission", dependencies=[Depends(verify_csrf_token)])
async def resolve_task_permission(task_id: str, request: TaskPermissionRequest, user: SessionData = Depends(get_current_user)):
    """
    MANDATORY SENSITIVE ACTION APPROVAL:
    Explicit human authorization before executing a sensitive tool action
    (file write/edit, terminal command, deletion).
    """
    try:
        task = task_store.get_task(task_id)
        if not task:
            raise KeyError(f"Task '{task_id}' not found.")

        pending = task.get("pending_permission")
        if not pending:
            raise ValueError(f"Task {task_id} has no pending permission request.")

        perm_id = pending.get("permission_id", "")
        updated_task = await task_store.resolve_task_permission(task_id, request.decision, user=user.username)

        # Forward decision to the active worker over WSS
        if bridge_manager.is_connected:
            await bridge_manager.forward_permission_decision(task_id, perm_id, request.decision)

        return updated_task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/tasks/{task_id}/cancel", dependencies=[Depends(verify_csrf_token)])
async def cancel_task(task_id: str, user: SessionData = Depends(get_current_user)):
    """Cancels a pending, running, or permission-waiting task."""
    try:
        task = await task_store.cancel_task(task_id, user=user.username)
        if bridge_manager.is_connected:
            await bridge_manager.forward_task_cancel(task_id)
        return task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/tasks/{task_id}/logs")
def get_task_logs(task_id: str, user: SessionData = Depends(get_current_user)):
    """Retrieves full stdout, stderr, events, pending permission, and permission history."""
    task = task_store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    return {
        "task_id": task["id"],
        "status": task["status"],
        "stdout": task.get("stdout", ""),
        "stderr": task.get("stderr", ""),
        "events": task.get("events", []),
        "pending_permission": task.get("pending_permission"),
        "permission_history": task.get("permission_history", []),
        "exit_code": task.get("exit_code"),
        "error": task.get("error"),
        "executed_at": task.get("executed_at"),
        "completed_at": task.get("completed_at")
    }


@app.get("/api/tasks/{task_id}/stream")
async def stream_task_logs(task_id: str, user: SessionData = Depends(get_current_user)):
    """Server-Sent Events (SSE) live event stream for logs and action approval prompts."""
    task = task_store.get_task(task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")

    queue = task_store.subscribe(task_id)

    async def event_generator():
        try:
            # Send initial state snapshot
            t = task_store.get_task(task_id)
            if t:
                snapshot = {
                    "task_id": task_id,
                    "status": t.get("status"),
                    "new_text": t.get("stdout", ""),
                    "pending_permission": t.get("pending_permission"),
                    "completed_at": t.get("completed_at"),
                    "error": t.get("error")
                }
                yield f"data: {json.dumps(snapshot)}\n\n"

            while True:
                try:
                    update = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(update)}\n\n"
                    if update.get("status") in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.REJECTED, TaskStatus.CANCELLED]:
                        break
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat
                    yield f": keep-alive\n\n"
        finally:
            task_store.unsubscribe(task_id, queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# -----------------------------------------------------------------------------
# Agent Bridge WebSocket Endpoint
# -----------------------------------------------------------------------------

@app.websocket("/ws/agent-bridge")
async def websocket_agent_bridge(websocket: WebSocket):
    """
    Authenticated WebSocket endpoint for the local Windows agent bridge.
    Requires cryptographic HMAC handshake and nonce replay validation.
    """
    await bridge_manager.handle_connection(websocket)


if __name__ == "__main__":
    import uvicorn
    port_str = os.environ.get("PORT", "8000")
    try:
        port = int(port_str)
    except ValueError:
        port = 8000
    uvicorn.run("cloud_app.server:app", host="0.0.0.0", port=port, reload=False)
