import base64

from identity.keygen import (
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
    verify_signature,
)


def test_generated_key_round_trips_through_base64_serialization() -> None:
    keypair = generate_keypair()

    assert deserialize_public_key(
        serialize_public_key(keypair.public_key)
    ).public_bytes_raw() == (keypair.public_key_bytes)


def test_key_generation_produces_distinct_keys() -> None:
    assert generate_keypair().public_key_bytes != generate_keypair().public_key_bytes


def test_none_signature_is_rejected_without_raising() -> None:
    keypair = generate_keypair()

    assert not verify_signature(keypair.public_key, {"action": "read"}, None)


def test_empty_signature_is_rejected_without_raising() -> None:
    keypair = generate_keypair()

    assert not verify_signature(keypair.public_key, {"action": "read"}, "")


def test_malformed_base64_signature_is_rejected_without_raising() -> None:
    keypair = generate_keypair()

    assert not verify_signature(
        keypair.public_key, {"action": "read"}, "not-valid-base64!!!"
    )


def test_wrong_length_signature_is_rejected_without_raising() -> None:
    keypair = generate_keypair()
    short_signature = base64.b64encode(b"too-short").decode()

    assert not verify_signature(keypair.public_key, {"action": "read"}, short_signature)
