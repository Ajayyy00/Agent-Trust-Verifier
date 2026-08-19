"""Ed25519 key and signing helpers."""

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 keypair and its raw 32-byte encodings."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    public_key_bytes: bytes
    private_key_bytes: bytes


def generate_keypair() -> KeyPair:
    """Generate Ed25519 keys because they are small, fast, and a modern cryptographic standard."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return KeyPair(
        private_key=private_key,
        public_key=public_key,
        public_key_bytes=public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        private_key_bytes=private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
    )


def serialize_public_key(public_key: Ed25519PublicKey) -> str:
    """Serialize an Ed25519 public key as base64-encoded raw bytes."""
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_key).decode("ascii")


def deserialize_public_key(b64_str: str) -> Ed25519PublicKey:
    """Deserialize a base64-encoded raw Ed25519 public key."""
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64_str, validate=True))


def sign_payload(private_key: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    """Canonicalize and sign a payload, returning a base64-encoded Ed25519 signature."""
    return base64.b64encode(private_key.sign(canonicalize(payload))).decode("ascii")


def verify_signature(
    public_key: Ed25519PublicKey, payload: dict[str, Any], signature_b64: str
) -> bool:
    """Verify a payload signature; invalid signatures return False, malformed input raises."""
    signature = base64.b64decode(signature_b64, validate=True)
    try:
        public_key.verify(signature, canonicalize(payload))
    except InvalidSignature:
        return False
    return True
