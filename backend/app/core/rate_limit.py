"""
In-memory sliding-window rate limiting. No external dependencies.

Limits are per process and reset on restart. That is adequate for a single
backend container; a multi-instance deployment would need a shared store.
"""

import threading
import time
from collections import deque
from typing import Deque, Dict, Tuple

from fastapi import HTTPException, Request

# Per-minute limits for the existing browser-facing auth endpoints (per client IP).
SENSITIVE_AUTH_LIMITS = {
    "/api/auth/login": 20,
    "/api/auth/request-otp": 10,
    "/api/auth/verify-otp": 20,
    "/api/auth/verify-face": 60,
    "/api/auth/forgot-password": 10,
    "/api/auth/reset-password": 10,
}

# Integration API (/api/v1).
V1_CLIENT_LIMIT_PER_MINUTE = 300     # per service client
V1_FAILED_AUTH_PER_MINUTE = 30       # failed client authentications per IP


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: float = 60.0) -> Tuple[bool, int]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            queue = self._hits.get(key)
            if queue is None:
                queue = deque()
                self._hits[key] = queue
            while queue and queue[0] <= cutoff:
                queue.popleft()
            if len(queue) >= limit:
                retry_after = max(1, int(queue[0] + window_seconds - now) + 1)
                return False, retry_after
            queue.append(now)
            if len(self._hits) > 10000:
                self._prune(cutoff)
            return True, 0

    def _prune(self, cutoff: float) -> None:
        stale = [k for k, q in self._hits.items() if not q or q[-1] <= cutoff]
        for key in stale:
            del self._hits[key]


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    """
    Best-effort caller IP. Behind the nginx proxy the TCP peer is the proxy, so
    the first X-Forwarded-For entry is preferred when present. If port 8000 is
    reachable directly, that header can be spoofed; in a real deployment only
    the proxy should be exposed.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def limit_sensitive_auth(request: Request) -> None:
    """Router-level dependency for the existing /api/auth router."""
    limit = SENSITIVE_AUTH_LIMITS.get(request.url.path)
    if limit is None:
        return
    allowed, retry_after = limiter.hit(f"auth:{request.url.path}:{client_ip(request)}", limit)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many attempts. Please wait a moment and try again.",
            headers={"Retry-After": str(retry_after)},
        )