"""FastAPI Application Main Entry Point."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from identity.keygen import generate_keypair
from storage.backend import (
    get_audit_service,
    get_key_registry,
    get_replay_store,
    get_reputation_service,
)
from verifier.trust_verifier import TrustVerifier

from .middleware import (
    BasicRateLimitMiddleware,
    GlobalExceptionHandlerMiddleware,
    PayloadSizeLimitMiddleware,
)
from .routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Construct core components ONCE at startup.
    # Note: Boto3 client/resource objects used by our DynamoDB implementations
    # are thread-safe for method calls, so they are perfectly safe to instantiate
    # once and share across FastAPI's async/threadpool request handlers.

    replay_store = get_replay_store()
    key_registry = get_key_registry()
    audit_service = get_audit_service()
    reputation_service = get_reputation_service()

    # In demo mode, if the root key is not provided, generate an ephemeral one.
    root_keypair = generate_keypair()
    agent_id = os.getenv("VERIFIER_AGENT_ID", "agent-api")

    # Define a default local policy allowing all actions for the demo
    local_policy = {"finance:report:generate"}

    trust_verifier = TrustVerifier(
        agent_id=agent_id,
        root_public_key=root_keypair.public_key,
        key_registry=key_registry,
        replay_store=replay_store,
        local_policy=local_policy,
        audit_service=audit_service,
        reputation_service=reputation_service,
    )

    app.state.trust_verifier = trust_verifier
    app.state.key_registry = key_registry
    app.state.audit_service = audit_service
    app.state.reputation_service = reputation_service
    app.state.root_keypair = root_keypair  # For testing/demo purposes

    yield

    # Teardown (nothing required for these backends)


app = FastAPI(title="Agent Trust Verifier API", lifespan=lifespan)

# Add custom middlewares
# Important: middlewares run in order they are added in FastAPI.
app.add_middleware(GlobalExceptionHandlerMiddleware)
app.add_middleware(BasicRateLimitMiddleware)
app.add_middleware(PayloadSizeLimitMiddleware, max_upload_size=512 * 1024)


# Exception handler for Pydantic validation errors to return structured JSON
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "Validation error", "details": exc.errors()},
    )


app.include_router(router)
