"""Delegation-token data and validation helpers independent of token issuance."""

from dataclasses import dataclass


@dataclass
class DelegationToken:
    """A signed, time-limited delegation of capabilities to an agent."""

    token_id: str
    subject_agent_id: str
    max_scope: list[str]
    delegation_depth: int
    max_delegation_depth: int
    expiry: int
    issuer_key_id: str
    issuer_signature: str | None


def to_signable_dict(token: DelegationToken) -> dict[str, object]:
    """Return the stable token fields that are covered by the issuer signature."""
    return {
        "token_id": token.token_id,
        "subject_agent_id": token.subject_agent_id,
        "max_scope": token.max_scope.copy(),
        "delegation_depth": token.delegation_depth,
        "max_delegation_depth": token.max_delegation_depth,
        "expiry": token.expiry,
        "issuer_key_id": token.issuer_key_id,
    }


def is_expired(token: DelegationToken, now: int) -> bool:
    """Return whether a token has reached its Unix-epoch expiry time."""
    return token.expiry <= now


def is_depth_valid(token: DelegationToken) -> bool:
    """Return whether the delegation depth is within its stated maximum."""
    return token.delegation_depth <= token.max_delegation_depth
