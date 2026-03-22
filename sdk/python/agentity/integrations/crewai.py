"""CrewAI integration for the Agentity Python SDK.

Provides AuthenticatedCrew — a wrapper that verifies an Agentity ACT token
before delegating to a CrewAI Crew.
"""

from __future__ import annotations

from typing import Any

try:
    from crewai import Crew
except ImportError:
    Crew = object  # type: ignore[assignment,misc]

from agentity.exceptions import AgentityTokenError
from agentity.integrations._verify import verify_capabilities


class AuthenticatedCrew:
    """Wraps CrewAI Crew execution with Agentity ACT verification.

    Usage::

        from agentity.integrations import crewai as agentity_crew

        crew = agentity_crew.AuthenticatedCrew(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        result = crew.kickoff(inputs={"topic": "..."})

    Args:
        agent_token: Base64url-encoded ACT token.
        capabilities: Capabilities that must be present in the token.
        base_url: Agentity server base URL (reserved for future server-side calls).
        api_key: Agentity admin API key (reserved for future server-side calls).
        crew: Optional CrewAI Crew to delegate to after verification.
    """

    def __init__(
        self,
        agent_token: str,
        capabilities: list[str],
        base_url: str,
        api_key: str,
        crew: Any = None,
    ) -> None:
        self.agent_token = agent_token
        self.capabilities = capabilities
        self.base_url = base_url
        self.api_key = api_key
        self.crew = crew

    def wrap(self, crew: Any) -> "AuthenticatedCrew":
        """Attach a CrewAI Crew and return self for chaining.

        Args:
            crew: A CrewAI Crew instance to kick off after verification.

        Returns:
            self, to allow fluent chaining.
        """
        self.crew = crew
        return self

    def kickoff(self, inputs: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """Verify the ACT token and kick off the wrapped crew.

        Args:
            inputs: Inputs passed through to crew.kickoff().
            **kwargs: Extra keyword arguments forwarded to crew.kickoff().

        Returns:
            crew.kickoff() result if a crew is attached, otherwise a dict
            with ``{"verified": True, "capabilities": <effective_caps>}``.

        Raises:
            AgentityTokenError: If the token is invalid or lacks required capabilities.
        """
        effective_caps = verify_capabilities(self.agent_token, self.capabilities)

        if self.crew is not None:
            return self.crew.kickoff(inputs=inputs, **kwargs)

        return {"verified": True, "capabilities": effective_caps}
