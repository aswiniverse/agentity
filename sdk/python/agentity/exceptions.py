"""Agentity SDK exceptions."""


class AgentityError(Exception):
    """Base exception for all Agentity SDK errors."""


class AgentityAPIError(AgentityError):
    """Raised when the Agentity API returns an error response."""

    def __init__(self, status_code: int, title: str, detail: str, problem_type: str = "") -> None:
        self.status_code = status_code
        self.title = title
        self.detail = detail
        self.problem_type = problem_type
        super().__init__(f"[{status_code}] {title}: {detail}")


class AgentityTokenError(AgentityError):
    """Raised when token creation, delegation, or verification fails locally."""


class AgentityKeyError(AgentityError):
    """Raised when a cryptographic key operation fails."""
