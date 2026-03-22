"""LangChain integration for the Agentity Python SDK.

Provides AuthenticatedChain — a wrapper that verifies an Agentity ACT token
before delegating to any LangChain Runnable.
"""

from __future__ import annotations

from typing import Any

try:
    from langchain_core.runnables import Runnable
except ImportError:
    Runnable = object  # type: ignore[assignment,misc]

from agentity.exceptions import AgentityTokenError
from agentity.integrations._verify import verify_capabilities


class AuthenticatedChain:
    """Wraps a LangChain Runnable with Agentity ACT verification.

    Usage::

        from agentity.integrations import langchain as agentity_lc

        chain = agentity_lc.AuthenticatedChain(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        result = chain.invoke({"input": "..."})

    Args:
        agent_token: Base64url-encoded ACT token.
        capabilities: Capabilities that must be present in the token.
        base_url: Agentity server base URL (reserved for future server-side calls).
        api_key: Agentity admin API key (reserved for future server-side calls).
        chain: Optional LangChain Runnable to delegate to after verification.
    """

    def __init__(
        self,
        agent_token: str,
        capabilities: list[str],
        base_url: str,
        api_key: str,
        chain: Any = None,
    ) -> None:
        self.agent_token = agent_token
        self.capabilities = capabilities
        self.base_url = base_url
        self.api_key = api_key
        self.chain = chain

    def wrap(self, chain: Any) -> "AuthenticatedChain":
        """Attach a LangChain Runnable and return self for chaining.

        Args:
            chain: A LangChain Runnable to invoke after verification.

        Returns:
            self, to allow fluent chaining.
        """
        self.chain = chain
        return self

    def invoke(self, input: Any, **kwargs: Any) -> Any:
        """Verify the ACT token and invoke the wrapped chain.

        Args:
            input: Input passed through to the underlying chain.
            **kwargs: Extra keyword arguments forwarded to chain.invoke().

        Returns:
            chain.invoke() result if a chain is attached, otherwise a dict
            with ``{"verified": True, "capabilities": <effective_caps>}``.

        Raises:
            AgentityTokenError: If the token is invalid or lacks required capabilities.
        """
        effective_caps = verify_capabilities(self.agent_token, self.capabilities)

        if self.chain is not None:
            return self.chain.invoke(input, **kwargs)

        return {"verified": True, "capabilities": effective_caps}
