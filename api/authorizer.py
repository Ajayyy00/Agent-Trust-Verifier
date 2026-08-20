"""AWS API Gateway Lambda Authorizer for API key authentication."""

import os
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Public endpoints that bypass authorization
PUBLIC_PATHS = {"/health", "/instruction/verify"}

# Endpoints that are public ONLY when test/demo mode is enabled
DEMO_PATHS = {
    "/test/bootstrap",
    "/test/chaos/audit",
    "/test/audit/reset",
    "/demo/send-valid",
    "/demo/manual",
    "/dashboard/state",
}

def handler(event: dict, context: object) -> dict:
    """Lambda Authorizer entry point for API Gateway HTTP API (Payload Format 2.0)."""
    raw_path = event.get("rawPath", "")
    if not raw_path:
        # Fallback to requestContext path if rawPath is absent
        raw_path = event.get("requestContext", {}).get("http", {}).get("path", "")

    # Clean trailing slash if present (except for root path)
    if len(raw_path) > 1 and raw_path.endswith("/"):
        raw_path = raw_path[:-1]

    logger.info("Authorizing request path: %s", raw_path)

    # 1. Always allow public endpoints
    if raw_path in PUBLIC_PATHS:
        logger.info("Path %s is public. Access allowed.", raw_path)
        return {"isAuthorized": True}

    # 2. Allow demo endpoints if ALLOW_TEST_BOOTSTRAP is set to "1"
    allow_test = os.getenv("ALLOW_TEST_BOOTSTRAP") == "1"
    if allow_test:
        if raw_path in DEMO_PATHS:
            logger.info("Demo mode active. Access to %s allowed.", raw_path)
            return {"isAuthorized": True}
        # In demo mode, revocation is also bypassed to allow the dashboard to work
        if raw_path.startswith("/agents/") and raw_path.endswith("/revoke"):
            logger.info("Demo mode active. Revocation for %s allowed.", raw_path)
            return {"isAuthorized": True}

    # 3. Secure endpoints require matching the ADMIN_API_KEY
    expected_key = os.getenv("ADMIN_API_KEY", "")
    if not expected_key:
        logger.error("ADMIN_API_KEY is not configured in environment. Failing closed.")
        return {"isAuthorized": False}

    # Extract authorization header case-insensitively
    headers = event.get("headers", {})
    auth_header = None
    for key, value in headers.items():
        if key.lower() == "authorization":
            auth_header = value
            break

    if auth_header == expected_key:
        logger.info("Valid Admin API Key provided. Access allowed.")
        return {"isAuthorized": True}

    logger.warning("Unauthorized access attempt to %s.", raw_path)
    return {"isAuthorized": False}
