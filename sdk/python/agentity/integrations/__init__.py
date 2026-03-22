"""Agentity framework integrations.

Provides drop-in wrappers for popular AI orchestration frameworks that verify
Agentity ACT tokens before delegating to the underlying framework.

Each integration is imported with a try/except guard so the Agentity SDK remains
importable even when a given framework is not installed.

Available integrations:
    - langchain: :class:`~agentity.integrations.langchain.AuthenticatedChain`
    - crewai:    :class:`~agentity.integrations.crewai.AuthenticatedCrew`
    - autogen:   :class:`~agentity.integrations.autogen.AuthenticatedAssistant`
"""

from __future__ import annotations

try:
    from agentity.integrations.langchain import AuthenticatedChain
except Exception:  # pragma: no cover
    AuthenticatedChain = None  # type: ignore[assignment,misc]

try:
    from agentity.integrations.crewai import AuthenticatedCrew
except Exception:  # pragma: no cover
    AuthenticatedCrew = None  # type: ignore[assignment,misc]

try:
    from agentity.integrations.autogen import AuthenticatedAssistant
except Exception:  # pragma: no cover
    AuthenticatedAssistant = None  # type: ignore[assignment,misc]

__all__ = ["AuthenticatedChain", "AuthenticatedCrew", "AuthenticatedAssistant"]
