"""Identity primitives for the Agent Trust Verifier."""

from .key_registry import KeyRegistry
from .keygen import (
    KeyPair,
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
    sign_payload,
    verify_signature,
)

__all__ = [
    "KeyPair",
    "KeyRegistry",
    "deserialize_public_key",
    "generate_keypair",
    "serialize_public_key",
    "sign_payload",
    "verify_signature",
]
