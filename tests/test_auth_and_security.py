"""
Unit tests for AI CODING HUB Cloud Authentication & Security
Verifies password hashing, rate limiting, session management, CSRF validation, and unauthenticated API protection.
"""

import time
import unittest
from fastapi import HTTPException, Request

from cloud_app.auth import (
    AuthManager,
    LoginRateLimiter,
    SessionData,
    get_current_user,
    verify_csrf_token,
)
from shared.constants import COOKIE_NAME, CSRF_HEADER_NAME
from shared.security import (
    ReplayProtection,
    compute_hmac,
    generate_token,
    hash_password,
    verify_hmac,
    verify_password,
)


class TestAuthAndSecurity(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.auth = AuthManager()
        self.auth.register_user("testuser", hash_password("CorrectPassword123!"))

    def test_password_hashing_and_verification(self):
        """Verifies PBKDF2 password hashing and timing-safe verification."""
        hashed = hash_password("SecretPass")
        self.assertTrue(verify_password("SecretPass", hashed))
        self.assertFalse(verify_password("WrongPass", hashed))
        self.assertFalse(verify_password("", hashed))
        self.assertFalse(verify_password("SecretPass", "malformed$hash"))

    def test_hmac_computation_and_rotation(self):
        """Verifies HMAC signing and support for multiple rotation secrets."""
        primary_secret = "secret_v1"
        secondary_secret = "secret_v2"
        data = "worker_1:1700000000:nonce_123"

        sig_v1 = compute_hmac(primary_secret, data)
        sig_v2 = compute_hmac(secondary_secret, data)

        # Single secret match
        self.assertTrue(verify_hmac(primary_secret, data, sig_v1))
        self.assertFalse(verify_hmac(primary_secret, data, "invalid_sig"))

        # Rotated secrets match
        rotated_secrets = [primary_secret, secondary_secret]
        self.assertTrue(verify_hmac(rotated_secrets, data, sig_v1))
        self.assertTrue(verify_hmac(rotated_secrets, data, sig_v2))
        self.assertFalse(verify_hmac(rotated_secrets, data, "wrong_sig"))

    def test_replay_protection(self):
        """Verifies replay attack detection and timestamp freshness window."""
        guard = ReplayProtection(ttl_seconds=10.0)
        now = time.time()

        # Valid fresh nonce
        valid, _ = guard.validate_and_record("nonce_abc123", now)
        self.assertTrue(valid)

        # Replay attack with same nonce
        valid_replay, reason = guard.validate_and_record("nonce_abc123", now)
        self.assertFalse(valid_replay)
        self.assertIn("Replay detected", reason)

        # Excessive clock skew
        valid_stale, reason_stale = guard.validate_and_record("nonce_stale", now - 25.0)
        self.assertFalse(valid_stale)
        self.assertIn("exceeds TTL", reason_stale)

    def test_successful_login(self):
        """Verifies successful login returns session ID and CSRF token."""
        success, session_id, csrf_token = self.auth.authenticate(
            "testuser", "CorrectPassword123!", client_ip="192.168.1.100"
        )
        self.assertTrue(success)
        self.assertIsNotNone(session_id)
        self.assertIsNotNone(csrf_token)

        # Session lookup
        session = self.auth.get_session(session_id)
        self.assertIsNotNone(session)
        self.assertEqual(session.username, "testuser")
        self.assertEqual(session.csrf_token, csrf_token)

    def test_invalid_login_rejection(self):
        """Verifies invalid credentials fail and don't produce sessions."""
        success, session_id, csrf_token = self.auth.authenticate(
            "testuser", "WrongPassword", client_ip="192.168.1.101"
        )
        self.assertFalse(success)
        self.assertIsNone(session_id)
        self.assertIsNone(csrf_token)

    def test_login_rate_limiting(self):
        """Verifies that 5 failed logins triggers a lockout."""
        ip = "192.168.1.50"
        for i in range(5):
            success, _, _ = self.auth.authenticate("testuser", "BadPass", client_ip=ip)
            self.assertFalse(success)

        # 6th attempt should raise HTTP 429
        with self.assertRaises(HTTPException) as ctx:
            self.auth.authenticate("testuser", "CorrectPassword123!", client_ip=ip)
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("Too many failed login attempts", ctx.exception.detail)

    async def test_unauthorized_api_access(self):
        """Verifies get_current_user raises 401 when unauthenticated."""
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/tasks",
            "headers": []
        }
        req = Request(scope=scope)

        with self.assertRaises(HTTPException) as ctx:
            await get_current_user(request=req, ach_session=None, authorization=None)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertIn("Authentication required", ctx.exception.detail)

    async def test_csrf_protection_enforcement(self):
        """Verifies verify_csrf_token blocks mutating requests missing or having mismatched CSRF headers."""
        session = SessionData(username="testuser", expires_at=time.time() + 3600, csrf_token="valid_csrf_token")

        # POST without CSRF header -> 403 Forbidden
        post_scope = {"type": "http", "method": "POST", "path": "/api/tasks", "headers": []}
        post_req = Request(scope=post_scope)

        with self.assertRaises(HTTPException) as ctx:
            await verify_csrf_token(request=post_req, user_session=session, x_csrf_token=None)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("missing", ctx.exception.detail)

        # POST with mismatched CSRF token -> 403 Forbidden
        with self.assertRaises(HTTPException) as ctx:
            await verify_csrf_token(request=post_req, user_session=session, x_csrf_token="wrong_csrf_token")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("invalid CSRF token", ctx.exception.detail)

        # POST with matching CSRF token -> Passes
        try:
            await verify_csrf_token(request=post_req, user_session=session, x_csrf_token="valid_csrf_token")
        except HTTPException:
            self.fail("verify_csrf_token unexpectedly raised HTTPException for valid CSRF token")


if __name__ == "__main__":
    unittest.main()
