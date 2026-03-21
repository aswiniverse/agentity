"""
LangChain integration example for Agentity.

This example shows how to:
1. Register a LangChain agent with Agentity
2. Issue it an ACT token with specific tool capabilities
3. Delegate a narrowed token to a sub-agent (e.g. a tool-calling chain)
4. Verify tokens before executing sensitive tool calls

Requirements:
    pip install agentity langchain-core
"""

from __future__ import annotations

import time
from typing import Any

# --- Agentity SDK imports ---
from agentity import AgentityClient
from agentity.crypto import delegate_token_locally


AGENTITY_URL = "http://localhost:8080"
ADMIN_KEY = "dev-admin-key"


def create_agent_with_token() -> tuple[str, str, str]:
    """Register a LangChain agent and issue it a root ACT token.

    Returns:
        (agent_id, private_key, encoded_token)
    """
    with AgentityClient(base_url=AGENTITY_URL, api_key=ADMIN_KEY) as client:
        # Register the orchestrator agent.
        agent, private_key = client.register_agent(
            name="langchain-orchestrator",
            model="claude-3-5-sonnet-20241022",
            tools=["read_file", "write_file", "web_search", "code_exec"],
            description="LangChain orchestrator agent with full tool access",
        )
        print(f"Registered agent: {agent.id}")

        # Issue a root token valid for 1 hour with all capabilities.
        token, token_id = client.issue_token(
            agent_id=agent.id,
            capabilities=["read_file", "write_file", "web_search", "code_exec"],
            expires_at=int(time.time()) + 3600,
            max_delegations=3,  # Allow up to 3 levels of delegation
        )
        print(f"Issued token: {token_id}")
        return agent.id, private_key, token


def delegate_to_tool_agent(
    parent_token: str,
    parent_private_key: str,
    child_agent_id: str,
    allowed_tools: list[str],
) -> str:
    """Delegate a narrowed token to a tool-calling sub-agent.

    The parent agent signs the delegation block locally — the private key
    never leaves this process.
    """
    child_token = delegate_token_locally(
        encoded_parent_token=parent_token,
        child_agent_id=child_agent_id,
        capabilities=allowed_tools,           # subset of parent's capabilities
        expires_at=int(time.time()) + 1800,  # 30 minutes
        parent_private_key_b64=parent_private_key,
    )
    print(f"Delegated token to {child_agent_id} with caps: {allowed_tools}")
    return child_token


def verify_before_tool_call(client: AgentityClient, token: str, required_cap: str) -> bool:
    """Check that a token is valid and has the required capability before running a tool."""
    try:
        verified = client.verify_token(token)
        if required_cap not in verified.capabilities:
            print(f"Token lacks capability '{required_cap}'. Blocking tool call.")
            return False
        print(f"Token verified for {verified.agent_id} — cap '{required_cap}' granted.")
        return True
    except Exception as e:
        print(f"Token verification failed: {e}")
        return False


class AgentityToolGuard:
    """LangChain-compatible tool wrapper that enforces ACT token checks.

    Usage with a custom LangChain tool:

        @tool
        def read_sensitive_file(path: str) -> str:
            guard = AgentityToolGuard(client=client, agent_token=token, required_cap="read_file")
            if not guard.check():
                raise PermissionError("Insufficient capabilities")
            return open(path).read()
    """

    def __init__(self, client: AgentityClient, agent_token: str, required_cap: str) -> None:
        self._client = client
        self._token = agent_token
        self._required_cap = required_cap

    def check(self) -> bool:
        return verify_before_tool_call(self._client, self._token, self._required_cap)


def policy_based_access_control_example(client: AgentityClient) -> None:
    """Demonstrate adding a CEL policy to restrict deep delegation chains."""
    # Deny any token with chain_depth > 2 (prevents 3+ hop delegation).
    policy = client.create_policy(
        name="no-deep-delegation",
        expression="chain_depth <= 2",
        action="allow",
        priority=50,
    )
    print(f"Created policy: {policy['id']} — {policy['name']}")

    # Deny agents using deprecated models.
    deny_policy = client.create_policy(
        name="deny-deprecated-models",
        expression='agent_model != "gpt-3.5-turbo"',
        action="allow",
        priority=100,
    )
    print(f"Created policy: {deny_policy['id']} — {deny_policy['name']}")


def main() -> None:
    print("=== Agentity + LangChain Integration Example ===\n")

    with AgentityClient(base_url=AGENTITY_URL, api_key=ADMIN_KEY) as client:
        # 1. Register orchestrator agent.
        orchestrator, orch_key = client.register_agent(
            name="orchestrator",
            model="claude-3-5-sonnet-20241022",
            tools=["read_file", "web_search", "code_exec"],
        )
        print(f"Orchestrator: {orchestrator.id}")

        # 2. Register a sub-agent (read-only tool agent).
        reader_agent, _ = client.register_agent(
            name="reader-agent",
            parent_id=orchestrator.id,
            tools=["read_file"],
        )
        print(f"Reader sub-agent: {reader_agent.id}")

        # 3. Issue root token to orchestrator.
        token, token_id = client.issue_token(
            agent_id=orchestrator.id,
            capabilities=["read_file", "web_search", "code_exec"],
            expires_at=int(time.time()) + 3600,
            max_delegations=2,
        )
        print(f"Root token: {token_id}\n")

        # 4. Delegate read-only token to reader sub-agent (client-side signing).
        reader_token = delegate_to_tool_agent(
            parent_token=token,
            parent_private_key=orch_key,
            child_agent_id=reader_agent.id,
            allowed_tools=["read_file"],  # capability attenuation
        )

        # 5. Submit delegated token to server for audit recording.
        client.submit_delegated_token(reader_token)
        print("Delegated token recorded in audit log.\n")

        # 6. Simulate tool guard check before executing read_file.
        guard = AgentityToolGuard(client, reader_token, required_cap="read_file")
        if guard.check():
            print("Tool call permitted — executing read_file...\n")

        # 7. Verify the reader agent cannot use web_search (denied by attenuation).
        guard_web = AgentityToolGuard(client, reader_token, required_cap="web_search")
        if not guard_web.check():
            print("web_search correctly denied for reader agent.\n")

        # 8. Add CEL policies.
        policy_based_access_control_example(client)

        # 9. Show audit log.
        entries = client.list_audit_entries(limit=5)
        print(f"\nLast {len(entries)} audit entries:")
        for e in entries:
            print(f"  [{e.get('type')}] {e.get('actor')} → {e.get('subject')}")


if __name__ == "__main__":
    main()
