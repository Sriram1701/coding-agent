import asyncio
import json
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from task_manager import TaskManager, TaskStatus, validate_workspace, AUTHORIZED_WORKSPACE

app = FastAPI(
    title="AI CODING HUB",
    description="Local AI Coding Automation System",
    version="1.2.0"
)

# Directories
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# Task Manager Instance (ACP Engine)
task_manager = TaskManager()

# Mount static assets
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# -----------------------------------------------------------------------------
# Existing Endpoints (Strictly Preserved)
# -----------------------------------------------------------------------------
@app.get("/")
def home():
    return {
        "status": "online",
        "message": "AI CODING HUB is running!"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/dashboard")
def get_dashboard():
    return FileResponse(STATIC_DIR / "index.html")


# -----------------------------------------------------------------------------
# Pydantic Schemas
# -----------------------------------------------------------------------------
class TaskCreateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Coding task description")
    workspace: str = Field(..., description="Target workspace path (restricted)")
    agent: Optional[str] = Field("antigravity", description="Target agent (strictly 'antigravity')")


class TaskRejectRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Optional rejection reason")


class TaskPermissionRequest(BaseModel):
    decision: str = Field(..., description="User decision: 'allow_once' or 'reject_once'")


# -----------------------------------------------------------------------------
# Antigravity Agent & Task Management API Endpoints
# -----------------------------------------------------------------------------
@app.get("/api/agent/status")
def get_agent_status():
    """Returns detected Antigravity CLI status, ACP protocol, and security posture."""
    return task_manager.get_agent_status()


@app.post("/api/tasks", status_code=status.HTTP_201_CREATED)
async def submit_task(request: TaskCreateRequest):
    """
    Submits a new coding task into PENDING_APPROVAL.
    CRITICAL: Does NOT launch ACP upon submission.
    Strictly restricted to Antigravity ACP.
    """
    try:
        task = await task_manager.submit_task(
            prompt=request.prompt,
            workspace=request.workspace,
            agent=request.agent
        )
        return task
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/tasks")
def list_tasks(status: Optional[str] = Query(None, description="Filter by task status")):
    """Retrieves all tasks or tasks filtered by status."""
    return task_manager.list_tasks(status=status)


@app.get("/api/tasks/{task_id}")
def get_task_details(task_id: str):
    """Retrieves full details and execution status for a specific task."""
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    return task


@app.post("/api/tasks/{task_id}/approve")
async def approve_task(task_id: str):
    """
    Explicit user approval to start an Antigravity ACP session.
    CRITICAL: Validates that the task is in PENDING_APPROVAL.
    Prevents duplicate executions.
    """
    try:
        task = await task_manager.approve_task(task_id)
        return task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/tasks/{task_id}/permission")
async def resolve_task_permission(task_id: str, request: TaskPermissionRequest):
    """
    MANDATORY SENSITIVE ACTION APPROVAL:
    Explicit human authorization before executing a sensitive tool action
    (file write/edit, terminal command, deletion).
    """
    try:
        task = await task_manager.resolve_task_permission(task_id, request.decision)
        return task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/tasks/{task_id}/reject")
async def reject_task(task_id: str, request: Optional[TaskRejectRequest] = None):
    """
    Rejects a pending task.
    CRITICAL: Never launches ACP.
    """
    reason = request.reason if request else None
    try:
        task = await task_manager.reject_task(task_id, reason=reason)
        return task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    """Cancels a pending, running, or permission-waiting task safely."""
    try:
        task = await task_manager.cancel_task(task_id)
        return task
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/api/tasks/{task_id}/logs")
def get_task_logs(task_id: str):
    """Retrieves stdout, stderr, events, pending permission, and permission history."""
    task = task_manager.get_task(task_id)
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
async def stream_task_logs(task_id: str):
    """Server-Sent Events (SSE) live event stream for live log and action approval broadcasts."""
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' not found.")

    async def event_generator():
        last_stdout_len = 0
        while True:
            t = task_manager.get_task(task_id)
            if not t:
                break

            current_stdout = t.get("stdout", "")
            new_text = current_stdout[last_stdout_len:]
            last_stdout_len = len(current_stdout)

            payload = {
                "task_id": task_id,
                "status": t.get("status"),
                "new_text": new_text,
                "pending_permission": t.get("pending_permission"),
                "completed_at": t.get("completed_at"),
                "error": t.get("error")
            }
            yield f"data: {json.dumps(payload)}\n\n"

            if t.get("status") in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.REJECTED, TaskStatus.CANCELLED]:
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
