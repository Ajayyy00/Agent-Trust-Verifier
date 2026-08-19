import time

import pytest

from authority.delegation_issuer import DelegationIssuer, verify_token_signature
from identity.delegation_token import DelegationToken, is_expired
from identity.keygen import generate_keypair


def test_issued_token_signature_verifies_with_root_public_key() -> None:
    root = generate_keypair()
    issuer = DelegationIssuer(root.private_key, "root-v1")

    token = issuer.issue_token("agent-a", ["read:financials"], expiry_seconds=300)

    assert token.token_id.startswith("dtok_")
    assert token.issuer_signature is not None
    assert verify_token_signature(token, root.public_key)


def test_tampering_with_signed_field_invalidates_signature() -> None:
    root = generate_keypair()
    issuer = DelegationIssuer(root.private_key, "root-v1")
    token = issuer.issue_token("agent-a", ["read:financials"], expiry_seconds=300)

    token.max_scope = ["write:financials"]

    assert not verify_token_signature(token, root.public_key)


def test_issuer_rejects_non_single_hop_delegation() -> None:
    root = generate_keypair()
    issuer = DelegationIssuer(root.private_key, "root-v1")

    with pytest.raises(ValueError, match="single-hop"):
        issuer.issue_token("agent-a", ["read:financials"], 300, requested_depth=2)


def test_expired_token_is_flagged() -> None:
    token = DelegationToken(
        token_id="dtok_expired",
        subject_agent_id="agent-a",
        max_scope=["read:financials"],
        delegation_depth=1,
        max_delegation_depth=1,
        expiry=int(time.time()) - 1,
        issuer_key_id="root-v1",
        issuer_signature=None,
    )

    assert is_expired(token, now=int(time.time()))
