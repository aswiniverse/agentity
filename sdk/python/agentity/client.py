"""
Agentity Python SDK — HTTP client for the Agentity IAM API.

Usage:
    from agentity import AgentityClient

    client = AgentityClient(base_url="http://localhost:8080", api_key="your-admin-key")

    # Register an agent
    agent, private_key = client.register_agent(name="my-agent", model="claude-3-5-sonnet")

    # Issue a root token
    import time
    token, token_id = client.issue_token(
        agent_id=agent.id,
        capabilities=["read_file", "write_file"],
        expires_at=int(time.time()) + 3600,
    )

    # Delegate to a child agent (client-side signing — private key never leaves process)
    from agentity.crypto import delegate_token_locally
    child_token = delegate_token_locally(
        encoded_parent_token=token,
        child_agent_id=child_agent.id,
        capabilities=["read_file"],
        expires_at=int(time.time()) + 1800,
        parent_private_key_b64=private_key,
    )
    client.submit_delegated_token(child_token)
"""

from __future__ import annotations

from typing import Any

import httpx

from .exceptions import AgentityAPIError
from .models import Agent, VerifiedACT


class AgentityClient:
    """Synchronous HTTP client for the Agentity IAM API.

    Args:
        base_url: The Agentity server base URL (e.g. "http://localhost:8080").
        api_key: The admin API key for authenticated endpoints.
        timeout: Request timeout in seconds. Default: 30.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={"X-Admin-API-Key": api_key, "Content-Type": "application/json"},
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()

    def __enter__(self) -> AgentityClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        resp = self._client.request(method, path, **kwargs)
        if not resp.is_success:
            try:
                body = resp.json()
                raise AgentityAPIError(
                    status_code=resp.status_code,
                    title=body.get("title", "API Error"),
                    detail=body.get("detail", resp.text),
                    problem_type=body.get("type", ""),
                )
            except (ValueError, KeyError):
                raise AgentityAPIError(
                    status_code=resp.status_code,
                    title="API Error",
                    detail=resp.text,
                )
        if resp.status_code == 204:
            return None
        return resp.json()

    # ------------------------------------------------------------------ #
    # Agent Identity
    # ------------------------------------------------------------------ #

    def register_agent(
        self,
        name: str,
        *,
        description: str = "",
        version: str = "",
        system_prompt: str = "",
        tools: list[str] | None = None,
        model: str = "",
        parent_id: str = "",
        metadata: dict[str, str] | None = None,
    ) -> tuple[Agent, str]:
        """Register a new agent.

        Returns:
            (agent, private_key_b64) — the registered agent and its base64url
            Ed25519 private key. Store the private key securely; it is only
            returned once.
        """
        payload: dict[str, Any] = {"name": name}
        if description:
            payload["description"] = description
        if version:
            payload["version"] = version
        if system_prompt:
            payload["system_prompt"] = system_prompt
        if tools:
            payload["tools"] = tools
        if model:
            payload["model"] = model
        if parent_id:
            payload["parent_id"] = parent_id
        if metadata:
            payload["metadata"] = metadata

        body = self._request("POST", "/api/v1/agents", json=payload)
        return Agent.from_dict(body["agent"]), body["private_key"]

    def get_agent(self, agent_id: str) -> Agent:
        """Retrieve an agent by its full ID (e.g. "agent://uuid")."""
        uid = agent_id.removeprefix("agent://")
        body = self._request("GET", f"/api/v1/agents/{uid}")
        return Agent.from_dict(body)

    def list_agents(
        self,
        *,
        status: str = "",
        parent_id: str = "",
        model: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> list[Agent]:
        """List agents with optional filters."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if parent_id:
            params["parent_id"] = parent_id
        if model:
            params["model"] = model
        body = self._request("GET", "/api/v1/agents", params=params)
        return [Agent.from_dict(a) for a in body]

    def suspend_agent(self, agent_id: str) -> None:
        """Suspend an active agent."""
        uid = agent_id.removeprefix("agent://")
        self._request("POST", f"/api/v1/agents/{uid}/suspend")

    def revoke_agent(self, agent_id: str, cascade: bool = False) -> None:
        """Revoke an agent, optionally cascading to all descendants."""
        uid = agent_id.removeprefix("agent://")
        self._request("POST", f"/api/v1/agents/{uid}/revoke", json={"cascade": cascade})

    def rotate_key(self, agent_id: str) -> tuple[Agent, str]:
        """Rotate an agent's Ed25519 key pair.

        Returns:
            (updated_agent, new_private_key_b64)
        """
        uid = agent_id.removeprefix("agent://")
        body = self._request("POST", f"/api/v1/agents/{uid}/rotate-key")
        return Agent.from_dict(body["agent"]), body["private_key"]

    def get_delegation_tree(self, agent_id: str) -> dict[str, Any]:
        """Return the delegation tree rooted at agent_id."""
        uid = agent_id.removeprefix("agent://")
        return self._request("GET", f"/api/v1/agents/{uid}/tree")

    # ------------------------------------------------------------------ #
    # Tokens
    # ------------------------------------------------------------------ #

    def issue_token(
        self,
        agent_id: str,
        capabilities: list[str],
        expires_at: int,
        *,
        not_before: int = 0,
        max_delegations: int = 0,
        allowed_models: list[str] | None = None,
    ) -> tuple[str, str]:
        """Issue a root ACT token for an agent.

        Returns:
            (encoded_token, token_id)
        """
        conditions: dict[str, Any] = {"exp": expires_at}
        if not_before:
            conditions["nbf"] = not_before
        if max_delegations:
            conditions["max_deleg"] = max_delegations
        if allowed_models:
            conditions["models"] = allowed_models

        payload = {
            "agent_id": agent_id,
            "capabilities": capabilities,
            "conditions": conditions,
        }
        body = self._request("POST", "/api/v1/tokens/issue", json=payload)
        return body["token"], body["token_id"]

    def submit_delegated_token(self, delegated_token: str) -> dict[str, Any]:
        """Submit a pre-signed delegated token for server-side audit recording.

        The token must have been signed client-side using delegate_token_locally().
        The server verifies all signatures and records the event — it never
        receives private keys.

        Returns the server's verification response.
        """
        body = self._request(
            "POST",
            "/api/v1/tokens/delegate",
            json={"delegated_token": delegated_token},
        )
        return body

    def verify_token(self, encoded_token: str) -> VerifiedACT:
        """Verify an ACT token and return the decoded claims."""
        body = self._request("POST", "/api/v1/tokens/verify", json={"token": encoded_token})
        return VerifiedACT.from_dict(body)

    def revoke_token(self, token_id: str, reason: str = "") -> None:
        """Revoke a token by ID."""
        self._request(
            "POST",
            "/api/v1/tokens/revoke",
            json={"token_id": token_id, "reason": reason},
        )

    def get_token_chain(self, encoded_token: str) -> dict[str, Any]:
        """Return the full delegation chain for a token."""
        return self._request("GET", "/api/v1/tokens/chain", params={"token": encoded_token})

    # ------------------------------------------------------------------ #
    # Admin
    # ------------------------------------------------------------------ #

    def get_stats(self) -> dict[str, Any]:
        """Return server statistics."""
        return self._request("GET", "/api/v1/admin/stats")

    def list_policies(self) -> list[dict[str, Any]]:
        """List all CEL policies."""
        body = self._request("GET", "/api/v1/admin/policies")
        return body if isinstance(body, list) else []

    def create_policy(
        self, name: str, expression: str, action: str, priority: int = 0
    ) -> dict[str, Any]:
        """Create a CEL policy.

        Args:
            name: Human-readable policy name.
            expression: CEL expression evaluating to bool.
                Variables available: agent_id, agent_model, chain_depth,
                capabilities (list), resource, action, expires_at.
            action: "allow" or "deny".
            priority: Higher priority policies are evaluated first.
        """
        return self._request(
            "POST",
            "/api/v1/admin/policies",
            json={"name": name, "expression": expression, "action": action, "priority": priority},
        )

    def delete_policy(self, policy_id: str) -> None:
        """Delete a policy by ID."""
        self._request("DELETE", f"/api/v1/admin/policies/{policy_id}")

    def list_audit_entries(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Return audit log entries."""
        body = self._request("GET", "/api/v1/audit", params={"limit": limit, "offset": offset})
        return body if isinstance(body, list) else []


class AsyncAgentityClient:
    """Async HTTP client for the Agentity IAM API.

    Same interface as AgentityClient but all methods are async.

    Usage:
        async with AsyncAgentityClient(base_url=..., api_key=...) as client:
            agent, priv_key = await client.register_agent(name="my-agent")
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={"X-Admin-API-Key": self._api_key, "Content-Type": "application/json"},
                timeout=self._timeout,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> AsyncAgentityClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        client = await self._get_client()
        resp = await client.request(method, path, **kwargs)
        if not resp.is_success:
            try:
                body = resp.json()
                raise AgentityAPIError(
                    status_code=resp.status_code,
                    title=body.get("title", "API Error"),
                    detail=body.get("detail", resp.text),
                    problem_type=body.get("type", ""),
                )
            except (ValueError, KeyError):
                raise AgentityAPIError(
                    status_code=resp.status_code,
                    title="API Error",
                    detail=resp.text,
                )
        if resp.status_code == 204:
            return None
        return resp.json()

    async def register_agent(self, name: str, **kwargs: Any) -> tuple[Agent, str]:
        payload: dict[str, Any] = {"name": name, **{k: v for k, v in kwargs.items() if v}}
        body = await self._request("POST", "/api/v1/agents", json=payload)
        return Agent.from_dict(body["agent"]), body["private_key"]

    async def issue_token(
        self, agent_id: str, capabilities: list[str], expires_at: int, **kwargs: Any
    ) -> tuple[str, str]:
        conditions: dict[str, Any] = {"exp": expires_at}
        if kwargs.get("not_before"):
            conditions["nbf"] = kwargs["not_before"]
        if kwargs.get("max_delegations"):
            conditions["max_deleg"] = kwargs["max_delegations"]
        payload = {"agent_id": agent_id, "capabilities": capabilities, "conditions": conditions}
        body = await self._request("POST", "/api/v1/tokens/issue", json=payload)
        return body["token"], body["token_id"]

    async def submit_delegated_token(self, delegated_token: str) -> dict[str, Any]:
        return await self._request(
            "POST", "/api/v1/tokens/delegate", json={"delegated_token": delegated_token}
        )

    async def verify_token(self, encoded_token: str) -> VerifiedACT:
        body = await self._request("POST", "/api/v1/tokens/verify", json={"token": encoded_token})
        return VerifiedACT.from_dict(body)

    async def revoke_token(self, token_id: str, reason: str = "") -> None:
        await self._request(
            "POST", "/api/v1/tokens/revoke", json={"token_id": token_id, "reason": reason}
        )

    async def get_agent(self, agent_id: str) -> Agent:
        uid = agent_id.removeprefix("agent://")
        body = await self._request("GET", f"/api/v1/agents/{uid}")
        return Agent.from_dict(body)

    async def suspend_agent(self, agent_id: str) -> None:
        uid = agent_id.removeprefix("agent://")
        await self._request("POST", f"/api/v1/agents/{uid}/suspend")

    async def revoke_agent(self, agent_id: str, cascade: bool = False) -> None:
        uid = agent_id.removeprefix("agent://")
        await self._request("POST", f"/api/v1/agents/{uid}/revoke", json={"cascade": cascade})
