"""Capability scope containment checks."""


def is_action_within_scope(action: str, granted_scopes: list[str]) -> bool:
    """Check scope membership: ``read:report`` matches exactly; ``read:report:daily``
    is a valid child; ``write:report`` is rejected; and ``read:report_extra`` is
    rejected because a colon boundary is required.
    """
    return any(
        action == granted_scope or action.startswith(f"{granted_scope}:")
        for granted_scope in granted_scopes
    )
