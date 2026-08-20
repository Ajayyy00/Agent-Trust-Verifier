"""Middlewares for payload sizing, basic rate limiting, and exception handling."""

import logging
import time

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class PayloadSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests with a body larger than the allowed size."""

    def __init__(self, app, max_upload_size: int = 512 * 1024):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_upload_size:
            return JSONResponse(status_code=413, content={"error": "Payload too large"})
        return await call_next(request)


class BasicRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Demo-scope basic in-memory rate limiter keyed by client host.
    In a real production environment (per the hardening boundary),
    this belongs at the API Gateway/WAF layer, not in application code.
    """

    def __init__(self, app):
        super().__init__(app)
        self._requests = {}
        self._window_seconds = 60
        self._max_requests = 100

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Cleanup old requests
        self._requests[client_ip] = [
            t
            for t in self._requests.get(client_ip, [])
            if now - t < self._window_seconds
        ]

        if len(self._requests[client_ip]) >= self._max_requests:
            return JSONResponse(
                status_code=429, content={"error": "Rate limit exceeded"}
            )

        self._requests[client_ip].append(now)
        return await call_next(request)


class GlobalExceptionHandlerMiddleware(BaseHTTPMiddleware):
    """Return a structured JSON error for all unhandled exceptions, avoiding raw tracebacks."""

    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except Exception:
            logger.exception("Unhandled server error")
            return JSONResponse(
                status_code=500, content={"error": "Internal server error"}
            )
