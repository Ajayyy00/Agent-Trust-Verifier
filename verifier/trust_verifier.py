"""Fail-closed, ordered verification of signed agent instructions."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from authority.delegation_issuer import verify_token_signature
from identity.delegation_token import is_expired
from identity.instruction import Instruction, to_signable_dict
from identity.key_registry import KeyRegistry
from identity.keygen import deserialize_public_key, verify_signature
from identity.scope import is_action_within_scope

from .replay_store import ReplayStore
from .result import (
    ACCEPTED,
    AGENT_REVOKED,
    FUTURE_TIMESTAMP,
    INVALID_SCHEMA,
    INVALID_SIGNATURE,
    POLICY_DENIED,
    REPLAY_DETECTED,
    STALE_INSTRUCTION,
    TOKEN_EXPIRED,
    TOKEN_SCOPE_DENIED,
    TOKEN_SIGNATURE_INVALID,
    TOKEN_SUBJECT_MISMATCH,
    UNKNOWN_KEY,
    WRONG_AUDIENCE,
    VerificationResult,
)


class TrustVerifier:
    """Verify that an instruction is fresh, authorized, authentic, and unreplayed."""

    def __init__(
        self,
        agent_id: str,
        root_public_key: Ed25519PublicKey,
        key_registry: KeyRegistry,
        replay_store: ReplayStore,
        local_policy: set[str],
        max_clock_skew_seconds: int = 30,
        max_instruction_age_seconds: int = 300,
    ) -> None:
        self.agent_id = agent_id
        self.root_public_key = root_public_key
        self.key_registry = key_registry
        self.replay_store = replay_store
        self.local_policy = local_policy
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.max_instruction_age_seconds = max_instruction_age_seconds

    @staticmethod
    def _result(
        instruction: Instruction, accepted: bool, reason_code: str
    ) -> VerificationResult:
        return VerificationResult(
            accepted=accepted,
            reason_code=reason_code,
            instruction_id=instruction.instruction_id,
            issuer=instruction.issuer,
            target=instruction.target_agent_id,
            action=instruction.action,
            token_id=instruction.delegation_token.token_id,
        )

    def verify(self, instruction: Instruction, now: int) -> VerificationResult:
        """Run the ordered trust checks, failing closed at the first failed check."""
        if not isinstance(instruction, Instruction):
            return VerificationResult(False, INVALID_SCHEMA, "", "", "", "")

        if instruction.target_agent_id != self.agent_id:
            return self._result(instruction, False, WRONG_AUDIENCE)

        if instruction.issued_at > now + self.max_clock_skew_seconds:
            return self._result(instruction, False, FUTURE_TIMESTAMP)
        if now - instruction.issued_at > self.max_instruction_age_seconds:
            return self._result(instruction, False, STALE_INSTRUCTION)

        if is_expired(instruction.delegation_token, now):
            return self._result(instruction, False, TOKEN_EXPIRED)

        try:
            token_signature_is_valid = verify_token_signature(
                instruction.delegation_token, self.root_public_key
            )
        except (TypeError, ValueError):
            token_signature_is_valid = False
        if not token_signature_is_valid:
            return self._result(instruction, False, TOKEN_SIGNATURE_INVALID)

        if instruction.delegation_token.subject_agent_id != instruction.issuer:
            return self._result(instruction, False, TOKEN_SUBJECT_MISMATCH)

        public_key_b64 = self.key_registry.get_key_for_verification(
            instruction.issuer, instruction.signer_pubkey_id
        )
        if public_key_b64 is None:
            return self._result(instruction, False, UNKNOWN_KEY)
        try:
            public_key = deserialize_public_key(public_key_b64)
            signature_is_valid = instruction.signature is not None and verify_signature(
                public_key, to_signable_dict(instruction), instruction.signature
            )
        except (TypeError, ValueError):
            signature_is_valid = False
        if not signature_is_valid:
            return self._result(instruction, False, INVALID_SIGNATURE)

        # Read the live registry on every attempt: revocation takes effect in one cycle.
        if self.key_registry.get_status(instruction.issuer) != "active":
            return self._result(instruction, False, AGENT_REVOKED)

        if not is_action_within_scope(
            instruction.action, instruction.delegation_token.max_scope
        ):
            return self._result(instruction, False, TOKEN_SCOPE_DENIED)

        if instruction.action not in self.local_policy:
            return self._result(instruction, False, POLICY_DENIED)

        if not self.replay_store.consume(
            instruction.target_agent_id, instruction.instruction_nonce
        ):
            return self._result(instruction, False, REPLAY_DETECTED)

        return self._result(instruction, True, ACCEPTED)
