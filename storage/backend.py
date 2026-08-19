"""Factories selecting memory or DynamoDB persistence by environment setting."""

import os
from typing import Any

from audit.logger import AuditService
from identity.key_registry import KeyRegistry
from reputation.scorer import ReputationService
from verifier.replay_store import ReplayStore

from .dynamo_client import get_dynamodb_resource
from .schema import AUDIT_TABLE, IDENTITY_TABLE, REPLAY_TABLE, REPUTATION_TABLE


def _backend() -> str:
    backend = os.getenv("STORAGE_BACKEND", "memory").lower()
    if backend not in {"memory", "dynamodb"}:
        raise ValueError("STORAGE_BACKEND must be 'memory' or 'dynamodb'")
    return backend


def get_replay_store() -> Any:
    """Return the configured replay-store implementation."""
    if _backend() == "memory":
        return ReplayStore()
    from verifier.dynamo_replay_store import DynamoReplayStore

    return DynamoReplayStore(get_dynamodb_resource().Table(REPLAY_TABLE))


def get_key_registry() -> Any:
    """Return the configured key-registry implementation."""
    if _backend() == "memory":
        return KeyRegistry()
    from identity.dynamo_key_registry import DynamoKeyRegistry

    return DynamoKeyRegistry(get_dynamodb_resource().Table(IDENTITY_TABLE))


def get_audit_service() -> Any:
    """Return the configured audit-service implementation."""
    if _backend() == "memory":
        return AuditService()
    from audit.dynamo_logger import DynamoAuditService

    return DynamoAuditService(get_dynamodb_resource().Table(AUDIT_TABLE))


def get_reputation_service() -> Any:
    """Return the configured reputation-service implementation."""
    if _backend() == "memory":
        return ReputationService()
    from reputation.dynamo_scorer import DynamoReputationService

    return DynamoReputationService(get_dynamodb_resource().Table(REPUTATION_TABLE))
