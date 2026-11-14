"""
AI CODING HUB - Shared Pydantic Data Models
Defines request, response, and WebSocket bridge message schemas.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# -----------------------------------------------------------------------------
# REST API Schemas
# -----------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    status: str
    username: str
    csrf_token: str
    message: str


class TaskCreateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Coding task description")
    workspace: str = Field(..., description="Target workspace path (restricted)")
    agent: Optional[str] = Field("antigravity", description="Target agent (strictly 'antigravity')")


class TaskRejectRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Optional rejection reason")


class TaskPermissionRequest(BaseModel):
    decision: str = Field(..., description="User decision: 'allow_once' or 'reject_once'")


# -----------------------------------------------------------------------------
# Bridge WebSocket Protocol Schemas
# -----------------------------------------------------------------------------

class BridgeMessageType:
    AUTH = "auth"
    AUTH_OK = "auth_ok"
    AUTH_FAIL = "auth_fail"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    TASK_DISPATCH = "task_dispatch"
    TASK_STATUS = "task_status"
    TASK_LOGS = "task_logs"
    PERMISSION_REQUEST = "permission_request"
    PERMISSION_DECISION = "permission_decision"
    TASK_CANCEL = "task_cancel"


class BridgeMessage(BaseModel):
    type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
