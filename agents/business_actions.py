"""Stub business-action registry executed by Agent B after verification.

These stubs simulate real work without causing any destructive side effects.
An unknown action reaching execute_action() is a BUG, not a normal case —
it means an unverified or mis-routed action slipped through. We fail loudly.
"""

from typing import Any


class UnknownActionError(RuntimeError):
    """Raised when an action not in the registry reaches execute_action().

    This should never happen in production: the verifier's scope check ensures
    Agent B only executes actions covered by its delegation token. If this
    fires it indicates a programming error in the routing layer.
    """


# Registry of stub actions Agent B can execute once verification passes.
# Keys are the canonical action strings used in delegation tokens and scope checks.
ACTIONS: dict[str, Any] = {
    "finance:report:generate": lambda params: (
        f"Report generated for period={params.get('period', 'N/A')}, "
        f"account={params.get('account_id', 'N/A')}"
    ),
    "finance:payment:refund": lambda params: (
        f"Refund processed: amount={params.get('amount', 'N/A')}, "
        f"account={params.get('account_id', 'N/A')}"
    ),
}


def execute_action(action: str, params: dict) -> str:
    """Look up and execute a stub business action.

    Args:
        action: The canonical action string (e.g. 'finance:report:generate').
        params: Arbitrary parameters accompanying the instruction, already
                signed and verified — the verifier guarantees they have not
                been tampered with en-route.

    Returns:
        A human-readable string confirming the (simulated) execution result.

    Raises:
        UnknownActionError: If the action is not in the registry. This is a
            programming error — a correctly verified instruction should only
            ever carry actions covered by the agent's delegation scope.
    """
    handler = ACTIONS.get(action)
    if handler is None:
        raise UnknownActionError(
            f"Action '{action}' is not in the business-action registry. "
            "This is a bug: only verified, in-scope actions should reach execution."
        )
    return handler(params)
