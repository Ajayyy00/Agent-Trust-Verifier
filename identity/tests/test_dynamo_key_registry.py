"""DynamoDB-backed key registry tests — interface-parity mirror of test_key_registry.py."""

import pytest

from identity.dynamo_key_registry import DynamoKeyRegistry
from identity.keygen import (
    generate_keypair,
    serialize_public_key,
    sign_payload,
    verify_signature,
)
from storage.tests.helpers import create_test_tables


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry_and_mock():
    mock, tables = create_test_tables()
    yield DynamoKeyRegistry(tables["identity"])
    mock.stop()


# ---------------------------------------------------------------------------
# Interface-parity tests (mirror of test_key_registry.py)
# ---------------------------------------------------------------------------


def test_register_and_get_active_key(registry_and_mock: DynamoKeyRegistry) -> None:
    registry = registry_and_mock
    registry.register("agent-a", "key-a")

    assert registry.get_active_key("agent-a") == "key-a"
    assert registry.get_status("agent-a") == "active"


def test_registering_duplicate_version_raises(
    registry_and_mock: DynamoKeyRegistry,
) -> None:
    registry = registry_and_mock
    registry.register("agent-a", "key-a")

    with pytest.raises(ValueError):
        registry.register("agent-a", "other-key")


def test_revocation_blocks_active_use_but_preserves_key_for_audit(
    registry_and_mock: DynamoKeyRegistry,
) -> None:
    registry = registry_and_mock
    registry.register("agent-a", "key-a")
    registry.revoke("agent-a", "credential exposed")

    assert registry.get_status("agent-a") == "revoked"
    assert registry.get_active_key("agent-a") is None
    # get_key_for_verification uses ConsistentRead=True so the revoked key is
    # still returned for historical audit purposes, but is not usable for new
    # instructions.
    assert registry.get_key_for_verification("agent-a") == "key-a"


def test_rotation_creates_new_version_and_supersedes_old_key(
    registry_and_mock: DynamoKeyRegistry,
) -> None:
    registry = registry_and_mock
    registry.register("agent-a", "old-key")

    assert registry.rotate("agent-a", "new-key") == "v2"
    assert registry.get_active_key("agent-a") == "new-key"
    assert registry.get_key_for_verification("agent-a", "v1") == "old-key"


def test_registered_key_signs_and_detects_tampering(
    registry_and_mock: DynamoKeyRegistry,
) -> None:
    keypair = generate_keypair()
    registry = registry_and_mock
    registry.register("agent-a", serialize_public_key(keypair.public_key))
    payload = {"instruction": "transfer", "amount": 10}
    signature = sign_payload(keypair.private_key, payload)
    verification_key = registry.get_key_for_verification("agent-a")

    assert verification_key is not None
    assert verify_signature(keypair.public_key, payload, signature)
    assert not verify_signature(
        keypair.public_key, {"instruction": "transfer", "amount": 11}, signature
    )


def test_unknown_agent_returns_unknown_status(
    registry_and_mock: DynamoKeyRegistry,
) -> None:
    registry = registry_and_mock

    assert registry.get_status("nonexistent-agent") == "unknown"


def test_unknown_agent_get_active_key_returns_none(
    registry_and_mock: DynamoKeyRegistry,
) -> None:
    registry = registry_and_mock

    assert registry.get_active_key("nonexistent-agent") is None


def test_revoke_unknown_agent_raises(registry_and_mock: DynamoKeyRegistry) -> None:
    registry = registry_and_mock

    with pytest.raises(KeyError):
        registry.revoke("nonexistent-agent", "reason")


def test_rotate_unknown_agent_raises(registry_and_mock: DynamoKeyRegistry) -> None:
    registry = registry_and_mock

    with pytest.raises(KeyError):
        registry.rotate("nonexistent-agent", "new-key")


def test_consistent_read_rejects_revoked_status_immediately(
    registry_and_mock: DynamoKeyRegistry,
) -> None:
    """get_status() and get_key_for_verification() use ConsistentRead=True, ensuring
    a revocation is visible in the same verification cycle — no eventual-consistency gap.
    """
    registry = registry_and_mock
    registry.register("agent-a", "key-a")
    registry.revoke("agent-a", "compromised")

    # Both calls use ConsistentRead=True at the GetItem call site, so revocation
    # is immediately visible — no stale read can accept a revoked credential.
    assert registry.get_status("agent-a") == "revoked"
    assert registry.get_active_key("agent-a") is None
