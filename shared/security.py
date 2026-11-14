"""
AI CODING HUB - Shared Cryptographic & Security Utilities
Provides password hashing (PBKDF2), HMAC signing with rotation support,
session tokens, and replay attack protection.
"""

import hashlib
import hmac
import os
import secrets
import time
from typing import List, Optional, Set, Tuple, Union


def hash_password(password: str, iterations: int = 100_000) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with a unique 16-byte salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{salt.hex()}${iterations}${key.hex()}"


def verify_password(password: str, hashed_str: str) -> bool:
    """Verifies a password against a stored PBKDF2 hash using timing-safe comparison."""
    try:
        parts = hashed_str.split("$")
        if len(parts) != 3:
            return False
        salt_hex, iter_str, key_hex = parts
        salt = bytes.fromhex(salt_hex)
        iterations = int(iter_str)
        expected_key = bytes.fromhex(key_hex)
        candidate_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(candidate_key, expected_key)
    except Exception:
        return False


def compute_hmac(secret: str, data: str) -> str:
    """Computes an HMAC-SHA256 hex digest for message authentication."""
    return hmac.new(secret.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_hmac(secrets_candidate: Union[str, List[str]], data: str, signature: str) -> bool:
    """
    Verifies an HMAC-SHA256 signature against one or more allowed secrets.
    Supports seamless secret rotation.
    """
    if isinstance(secrets_candidate, str):
        allowed_secrets = [s.strip() for s in secrets_candidate.split(",") if s.strip()]
    else:
        allowed_secrets = [s.strip() for s in secrets_candidate if s.strip()]

    if not allowed_secrets:
        return False

    for secret in allowed_secrets:
        expected = compute_hmac(secret, data)
        if hmac.compare_digest(expected, signature):
            return True
    return False


def generate_token(nbytes: int = 32) -> str:
    """Generates a cryptographically secure URL-safe token."""
    return secrets.token_urlsafe(nbytes)


class ReplayProtection:
    """
    Tracks nonces within a sliding time window to prevent message replay attacks.
    Automatically purges expired nonces.
    """
    def __init__(self, ttl_seconds: float = 120.0):
        self.ttl_seconds = ttl_seconds
        self._nonces: dict[str, float] = {}

    def validate_and_record(self, nonce: str, timestamp: float) -> Tuple[bool, str]:
        """
        Validates timestamp freshness and verifies nonce has not been previously observed.
        Returns (is_valid, reason).
        """
        now = time.time()
        # Clean expired nonces
        expired_keys = [k for k, exp in self._nonces.items() if exp <= now]
        for k in expired_keys:
            del self._nonces[k]

        # Check time skew
        if abs(now - timestamp) > self.ttl_seconds:
            return False, f"Timestamp drift ({abs(now - timestamp):.1f}s) exceeds TTL ({self.ttl_seconds}s)"

        if not nonce or len(nonce) < 8:
            return False, "Invalid or insufficient nonce length"

        if nonce in self._nonces:
            return False, "Replay detected: nonce has already been used"

        # Record nonce with expiration
        self._nonces[nonce] = now + self.ttl_seconds
        return True, "Valid"
