"""AutoGen integration for the Agentity Python SDK.

Provides AuthenticatedAssistant — a wrapper that verifies an Agentity ACT token
before delegating to an AutoGen ConversableAgent.
"""

from __future__ import annotations

from typing import Any

try:
    from autogen import ConversableAgent
except ImportError:
    ConversableAgent = object  # type: ignore[assignment,misc]

from agentity.exceptions import AgentityTokenError
from agentity.integrations._verify import verify_capabilities


class AuthenticatedAssistant:
    """Wraps AutoGen ConversableAgent with Agentity ACT verification.

    Usage::

        from agentity.integrations import autogen as agentity_ag

        assistant = agentity_ag.AuthenticatedAssistant(
            agent_token=token,
            capabilities=["code_exec"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        assistant.initiate_chat(user_proxy, message="...")

    Args:
        agent_token: Base64url-encoded ACT token.
        capabilities: Capabilities that must be present in the token.
        base_url: Agentity server base URL (reserved for future server-side calls).
        api_key: Agentity admin API key (reserved for future server-side calls).
        agent: Optional AutoGen ConversableAgent to delegate to after verification.
    """

    def __init__(
        self,
        agent_token: str,
        capabilities: list[str],
        base_url: str,
        api_key: str,
        agent: Any = None,
    ) -> None:
        self.agent_token = agent_token
        self.capabilities = capabilities
        self.base_url = base_url
        self.api_key = api_key
        self.agent = agent

    def wrap(self, agent: Any) -> "AuthenticatedAssistant":
        """Attach an AutoGen agent and return self for chaining.

        Args:
            agent: An AutoGen ConversableAgent to delegate to after verification.

        Returns:
            self, to allow fluent chaining.
        """
        self.agent = agent
        return self

    def initiate_chat(self, recipient: Any, message: str, **kwargs: Any) -> Any:
        """Verify the ACT token and initiate a chat with the wrapped agent.

        Args:
            recipient: The recipient agent passed to agent.initiate_chat().
            message: The initial message string.
            **kwargs: Extra keyword arguments forwarded to agent.initiate_chat().

        Returns:
            agent.initiate_chat() result if an agent is attached, otherwise a dict
            with ``{"verified": True, "capabilities": <effective_caps>}``.

        Raises:
            AgentityTokenError: If the token is invalid or lacks required capabilities.
        """
        effective_caps = verify_capabilities(self.agent_token, self.capabilities)

        if self.agent is not None:
            return self.agent.initiate_chat(recipient, message=message, **kwargs)

        return {"verified": True, "capabilities": effective_caps}
