"""Shared ACT capability verification helper for Agentity framework integrations."""

from __future__ import annotations

from agentity.crypto import decode_token, _effective_capabilities
from agentity.exceptions import AgentityTokenError


def verify_capabilities(agent_token: str, required_capabilities: list[str]) -> list[str]:
    """Decode ACT and verify all required_capabilities are in effective caps.

    Args:
        agent_token: Base64url-encoded ACT token string.
        required_capabilities: List of capability strings that must be present.

    Returns:
        List of effective capabilities on success.

    Raises:
        AgentityTokenError: If token is invalid or missing required capabilities.
    """
    act = decode_token(agent_token)
    effective = _effective_capabilities(act.blocks)

    missing = set(required_capabilities) - effective
    if missing:
        raise AgentityTokenError(
            f"Token missing required capabilities: {sorted(missing)}. "
            f"Effective capabilities: {sorted(effective)}"
        )

    return sorted(effective)
