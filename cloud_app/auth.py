"""
AI CODING HUB - Cloud Server Authentication & Security
Provides secure session management, password hashing, CSRF protection,
and IP-based rate limiting.
"""

from datetime import datetime, timezone
import logging
import os
import time
from typing import Dict, Optional, Tuple

from fastapi import Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel

from shared.constants import (
    COOKIE_NAME,
    CSRF_HEADER_NAME,
    LOGIN_LOCKOUT_SECONDS,
    MAX_LOGIN_ATTEMPTS,
    SESSION_EXPIRATION_SECONDS,
)
from shared.security import generate_token, hash_password, verify_password

logger = logging.getLogger("ai_coding_hub.auth")


class SessionData:
    def __init__(self, username: str, expires_at: float, csrf_token: str):
        self.username = username
        self.expires_at = expires_at
        self.csrf_token = csrf_token


class LoginRateLimiter:
    """Tracks failed login attempts per client IP and enforces temporary lockouts."""
    def __init__(self, max_attempts: int = MAX_LOGIN_ATTEMPTS, lockout_seconds: int = LOGIN_LOCKOUT_SECONDS):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._failures: Dict[str, list[float]] = {}
        self._lockouts: Dict[str, float] = {}

    def is_locked(self, ip: str) -> Tuple[bool, float]:
        now = time.time()
        lockout_until = self._lockouts.get(ip, 0)
        if lockout_until > now:
            return True, lockout_until - now
        return False, 0.0

    def record_failure(self, ip: str) -> None:
        now = time.time()
        attempts = self._failures.setdefault(ip, [])
        # Keep failures within the lockout window
        attempts = [t for t in attempts if now - t < self.lockout_seconds]
        attempts.append(now)
        self._failures[ip] = attempts

        if len(attempts) >= self.max_attempts:
            self._lockouts[ip] = now + self.lockout_seconds
            logger.warning(f"IP {ip} locked out for {self.lockout_seconds}s after {len(attempts)} failed logins.")

    def record_success(self, ip: str) -> None:
        self._failures.pop(ip, None)
        self._lockouts.pop(ip, None)


class AuthManager:
    """Manages user credentials, active sessions, and CSRF tokens."""
    def __init__(self):
        self.rate_limiter = LoginRateLimiter()
        self._sessions: Dict[str, SessionData] = {}

        # Default admin credentials loaded from environment or securely generated
        admin_user = os.environ.get("ACH_ADMIN_USER", "admin")
        admin_pass = os.environ.get("ACH_ADMIN_PASSWORD")
        if not admin_pass:
            admin_pass = generate_token(16)
            logger.info("ACH_ADMIN_PASSWORD not set in environment; generated secure ephemeral credentials.")
        self._users: Dict[str, str] = {
            admin_user: hash_password(admin_pass)
        }

    def register_user(self, username: str, password_hash: str) -> None:
        self._users[username] = password_hash

    def authenticate(self, username: str, password: str, client_ip: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Authenticates credentials against stored password hashes.
        Returns (success, session_id, csrf_token).
        """
        is_locked, remaining = self.rate_limiter.is_locked(client_ip)
        if is_locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many failed login attempts. Locked out for {int(remaining)} seconds."
            )

        stored_hash = self._users.get(username)
        if not stored_hash or not verify_password(password, stored_hash):
            self.rate_limiter.record_failure(client_ip)
            return False, None, None

        self.rate_limiter.record_success(client_ip)
        session_id = generate_token(32)
        csrf_token = generate_token(32)
        expires_at = time.time() + SESSION_EXPIRATION_SECONDS

        self._sessions[session_id] = SessionData(
            username=username,
            expires_at=expires_at,
            csrf_token=csrf_token
        )
        return True, session_id, csrf_token

    def get_session(self, session_id: Optional[str]) -> Optional[SessionData]:
        if not session_id:
            return None
        session = self._sessions.get(session_id)
        if not session:
            return None
        if time.time() > session.expires_at:
            self._sessions.pop(session_id, None)
            return None
        return session

    def terminate_session(self, session_id: Optional[str]) -> None:
        if session_id:
            self._sessions.pop(session_id, None)


# Global instance for cloud app
auth_manager = AuthManager()


# -----------------------------------------------------------------------------
# FastAPI Dependencies
# -----------------------------------------------------------------------------

def get_client_ip(request: Request) -> str:
    """Extracts client IP, respecting X-Forwarded-For if behind a reverse proxy."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


async def get_current_user(
    request: Request,
    ach_session: Optional[str] = Cookie(None, alias=COOKIE_NAME),
    authorization: Optional[str] = Header(None)
) -> SessionData:
    """
    Validates authenticated user session from HTTP-only cookie or Authorization header.
    Rejects unauthenticated requests with HTTP 401.
    """
    session_id = ach_session

    if not session_id and authorization:
        parts = authorization.split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            session_id = parts[1]

    session = auth_manager.get_session(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return session


async def verify_csrf_token(
    request: Request,
    user_session: SessionData = Depends(get_current_user),
    x_csrf_token: Optional[str] = Header(None, alias=CSRF_HEADER_NAME)
) -> None:
    """
    Enforces double-submit CSRF token validation on state-changing requests.
    Prevents Cross-Site Request Forgery attacks against authenticated sessions.
    """
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        if not x_csrf_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"CSRF protection: missing '{CSRF_HEADER_NAME}' header."
            )
        if x_csrf_token != user_session.csrf_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF protection: invalid CSRF token."
            )
