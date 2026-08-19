import pytest

from identity.key_registry import KeyRegistry
from identity.keygen import (
    generate_keypair,
    serialize_public_key,
    sign_payload,
    verify_signature,
)


def test_register_and_get_active_key() -> None:
    registry = KeyRegistry()
    registry.register("agent-a", "key-a")

    assert registry.get_active_key("agent-a") == "key-a"
    assert registry.get_status("agent-a") == "active"


def test_registering_duplicate_version_raises() -> None:
    registry = KeyRegistry()
    registry.register("agent-a", "key-a")

    with pytest.raises(ValueError):
        registry.register("agent-a", "other-key")


def test_revocation_blocks_active_use_but_preserves_key_for_audit() -> None:
    registry = KeyRegistry()
    registry.register("agent-a", "key-a")
    registry.revoke("agent-a", "credential exposed")

    assert registry.get_status("agent-a") == "revoked"
    assert registry.get_active_key("agent-a") is None
    assert registry.get_key_for_verification("agent-a") == "key-a"


def test_rotation_creates_new_version_and_supersedes_old_key() -> None:
    registry = KeyRegistry()
    registry.register("agent-a", "old-key")

    assert registry.rotate("agent-a", "new-key") == "v2"
    assert registry.get_active_key("agent-a") == "new-key"
    assert registry.get_key_for_verification("agent-a", "v1") == "old-key"
    assert registry._keys["agent-a"]["v1"].status == "superseded"


def test_registered_key_signs_and_detects_tampering() -> None:
    keypair = generate_keypair()
    registry = KeyRegistry()
    registry.register("agent-a", serialize_public_key(keypair.public_key))
    payload = {"instruction": "transfer", "amount": 10}
    signature = sign_payload(keypair.private_key, payload)
    verification_key = registry.get_key_for_verification("agent-a")

    assert verification_key is not None
    assert verify_signature(keypair.public_key, payload, signature)
    assert not verify_signature(
        keypair.public_key, {"instruction": "transfer", "amount": 11}, signature
    )
