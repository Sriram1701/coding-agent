"""
AI CODING HUB - Shared Constants & Enums
Defines lifecycle statuses, timeouts, security thresholds, and protocol types.
"""

from pathlib import Path


class TaskStatus:
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    AWAITING_ACTION_APPROVAL = "AWAITING_ACTION_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class AgentBridgeStatus:
    OFFLINE = "OFFLINE"
    ONLINE = "ONLINE"
    BUSY = "BUSY"


class DecisionType:
    ALLOW_ONCE = "allow_once"
    REJECT_ONCE = "reject_once"


# Security & Session Settings
DEFAULT_WORKSPACE_PATH = Path(r"C:\Users\lovel\Desktop\AI-CODING-HUB").resolve()
DEFAULT_AGY_CLI_PATH = Path(r"C:\Users\lovel\.gemini\bin\agy.exe")

# Timeouts (in seconds)
INACTIVITY_TIMEOUT_SECONDS = 90
MAX_SESSION_SECONDS = 900
BRIDGE_HEARTBEAT_INTERVAL = 15
BRIDGE_HEARTBEAT_TIMEOUT = 45
BRIDGE_NONCE_TTL = 120  # Replay protection window

# Rate Limiting & Auth
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutes lockout
SESSION_EXPIRATION_SECONDS = 86400  # 24 hours
COOKIE_NAME = "ach_session"
CSRF_HEADER_NAME = "X-CSRF-Token"
