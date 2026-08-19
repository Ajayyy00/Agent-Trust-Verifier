"""Root Authority issuance and signature verification for delegation tokens."""

import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from identity.delegation_token import DelegationToken, to_signable_dict
from identity.keygen import sign_payload, verify_signature


class DelegationIssuer:
    """Issue single-hop, Root Authority-signed delegation tokens."""

    def __init__(self, root_private_key: Ed25519PrivateKey, issuer_key_id: str) -> None:
        self._root_private_key = root_private_key
        self._issuer_key_id = issuer_key_id

    def issue_token(
        self,
        subject_agent_id: str,
        max_scope: list[str],
        expiry_seconds: int,
        requested_depth: int = 1,
    ) -> DelegationToken:
        """Create a signed token, enforcing the Phase 2 single-hop boundary."""
        if requested_depth != 1:
            raise ValueError(
                "Requested delegation depth must be 1 under the single-hop scope decision."
            )

        token = DelegationToken(
            token_id=f"dtok_{uuid.uuid4().hex}",
            subject_agent_id=subject_agent_id,
            max_scope=max_scope.copy(),
            delegation_depth=requested_depth,
            max_delegation_depth=1,
            expiry=int(time.time()) + expiry_seconds,
            issuer_key_id=self._issuer_key_id,
            issuer_signature=None,
        )
        token.issuer_signature = sign_payload(
            self._root_private_key, to_signable_dict(token)
        )
        return token


def verify_token_signature(
    token: DelegationToken, root_public_key: Ed25519PublicKey
) -> bool:
    """Verify a token signature, returning False when no signature is present or it is invalid."""
    if token.issuer_signature is None:
        return False
    return verify_signature(
        root_public_key, to_signable_dict(token), token.issuer_signature
    )
