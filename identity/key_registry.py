"""Storage-agnostic in-memory public-key registry."""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class _KeyRecord:
    public_key_b64: str
    status: str = "active"
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


class KeyRegistry:
    """Manage agent public keys without exposing the underlying storage model."""

    def __init__(self) -> None:
        self._keys: dict[str, dict[str, _KeyRecord]] = {}
        self._active_versions: dict[str, str] = {}

    def register(
        self, agent_id: str, public_key_b64: str, key_version: str = "v1"
    ) -> None:
        """Register a public key, refusing to overwrite an existing version."""
        agent_keys = self._keys.setdefault(agent_id, {})
        if key_version in agent_keys:
            raise ValueError(
                f"Key version {key_version!r} is already registered for {agent_id!r}"
            )
        agent_keys[key_version] = _KeyRecord(public_key_b64=public_key_b64)
        self._active_versions[agent_id] = key_version

    def get_active_key(self, agent_id: str) -> str | None:
        """Return the active public key only when it remains trusted for new instructions."""
        version = self._active_versions.get(agent_id)
        if version is None:
            return None
        record = self._keys[agent_id][version]
        return record.public_key_b64 if record.status == "active" else None

    def get_key_for_verification(
        self, agent_id: str, key_version: str | None = None
    ) -> str | None:
        """Return a stored key for historical signature verification, even if revoked."""
        version = key_version or self._active_versions.get(agent_id)
        if version is None:
            return None
        record = self._keys.get(agent_id, {}).get(version)
        return record.public_key_b64 if record is not None else None

    def get_status(self, agent_id: str) -> str:
        """Return the current agent key status."""
        version = self._active_versions.get(agent_id)
        if version is None:
            return "unknown"
        return self._keys[agent_id][version].status

    def revoke(self, agent_id: str, reason: str) -> None:
        """Revoke the active key while retaining it for audit verification."""
        version = self._active_versions.get(agent_id)
        if version is None:
            raise KeyError(f"Unknown agent: {agent_id}")
        record = self._keys[agent_id][version]
        record.status = "revoked"
        record.revoked_at = datetime.now(timezone.utc)
        record.revocation_reason = reason

    def rotate(self, agent_id: str, new_public_key_b64: str) -> str:
        """Create a new active version and mark the prior active version superseded."""
        old_version = self._active_versions.get(agent_id)
        if old_version is None:
            raise KeyError(f"Unknown agent: {agent_id}")
        versions = self._keys[agent_id]
        version_number = 1
        while f"v{version_number}" in versions:
            version_number += 1
        new_version = f"v{version_number}"
        versions[old_version].status = "superseded"
        self.register(agent_id, new_public_key_b64, new_version)
        return new_version
