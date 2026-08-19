"""FastAPI Application Main Entry Point."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from identity.keygen import generate_keypair, load_keypair_from_private_key_b64
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

    # Deployments provide a stable root key so signatures survive Lambda cold starts.
    # An ephemeral root remains convenient and safe for local/test use only.
    root_private_key_b64 = os.getenv("ROOT_PRIVATE_KEY_B64")
    root_keypair = (
        load_keypair_from_private_key_b64(root_private_key_b64)
        if root_private_key_b64
        else generate_keypair()
    )
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
    # Process-local private credentials used exclusively by the demo manual-prompt route.
    app.state.manual_agent_credentials = {}

    yield

    # Teardown (nothing required for these backends)


app = FastAPI(title="Agent Trust Verifier API", lifespan=lifespan)

# The dashboard is static and may be hosted separately from the API Gateway URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("DASHBOARD_ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

# Add custom middlewares
# Important: middlewares run in order they are added in FastAPI.
app.add_middleware(GlobalExceptionHandlerMiddleware)
app.add_middleware(BasicRateLimitMiddleware)
app.add_middleware(PayloadSizeLimitMiddleware, max_upload_size=512 * 1024)


# Exception handler for Pydantic validation errors to return structured JSON
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    from fastapi.encoders import jsonable_encoder
    return JSONResponse(
        status_code=422,
        content={"error": "Validation error", "details": jsonable_encoder(exc.errors())},
    )


app.include_router(router)
