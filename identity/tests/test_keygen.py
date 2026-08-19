from identity.keygen import (
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
)


def test_generated_key_round_trips_through_base64_serialization() -> None:
    keypair = generate_keypair()

    assert deserialize_public_key(
        serialize_public_key(keypair.public_key)
    ).public_bytes_raw() == (keypair.public_key_bytes)


def test_key_generation_produces_distinct_keys() -> None:
    assert generate_keypair().public_key_bytes != generate_keypair().public_key_bytes
