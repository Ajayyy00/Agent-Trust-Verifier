"""Storage-agnostic, in-memory replay protection."""


class ReplayStore:
    """Record consumed instruction nonces per receiving agent."""

    def __init__(self) -> None:
        self._consumed: dict[str, object] = {}

    def consume(self, target_agent_id: str, nonce: str) -> bool:
        """Atomically record a nonce and report whether it was first seen."""
        key = f"{target_agent_id}:{nonce}"
        # This set-if-absent primitive becomes a DynamoDB conditional write later.
        marker = object()
        return self._consumed.setdefault(key, marker) is marker
