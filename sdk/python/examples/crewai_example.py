"""
CrewAI integration example for Agentity.

This example shows how to:
1. Register a CrewAI crew (orchestrator) and its role-based agents with Agentity
2. Issue a root ACT token to the crew with all capabilities
3. Delegate narrowed tokens to each role-specific agent (researcher, writer, reviewer)
4. Gate tool calls with capability checks so agents can only use what they were delegated
5. Cascade-revoke the entire crew on completion

Architecture:
    Crew (root token: web_search + read_file + write_file + code_exec)
      ├── Researcher  (delegated: web_search, read_file)
      ├── Writer      (delegated: write_file, read_file)
      └── Reviewer    (delegated: read_file)

Requirements:
    pip install agentity crewai crewai-tools
"""

from __future__ import annotations

import time
from typing import Any

from agentity import AgentityClient
from agentity.crypto import delegate_token_locally

AGENTITY_URL = "http://localhost:8080"
ADMIN_KEY = "dev-admin-key"


# ---------------------------------------------------------------------------
# Capability guard — wraps any CrewAI tool with an ACT token check
# ---------------------------------------------------------------------------

class AgentityCapabilityGuard:
    """Checks that an agent's ACT token grants a specific capability.

    Use this inside any CrewAI tool's `_run` method before executing
    sensitive operations.

    Example::

        class ReadFileTool(BaseTool):
            name = "read_file"
            description = "Reads a file from disk"
            token: str
            client: Any

            def _run(self, path: str) -> str:
                AgentityCapabilityGuard(self.client, self.token, "read_file").enforce()
                return open(path).read()
    """

    def __init__(self, client: AgentityClient, token: str, required_cap: str) -> None:
        self._client = client
        self._token = token
        self._required_cap = required_cap

    def check(self) -> bool:
        """Returns True if the token grants the required capability."""
        try:
            verified = self._client.verify_token(self._token)
            return self._required_cap in verified.capabilities
        except Exception:
            return False

    def enforce(self) -> None:
        """Raises PermissionError if the capability check fails."""
        if not self.check():
            raise PermissionError(
                f"Agent does not have capability '{self._required_cap}'. "
                "Token may be expired, revoked, or not delegated this capability."
            )


# ---------------------------------------------------------------------------
# Simulated CrewAI tools (replace with real crewai BaseTool subclasses)
# ---------------------------------------------------------------------------

class AgentityWebSearchTool:
    """A web search tool gated by an Agentity ACT token."""

    def __init__(self, client: AgentityClient, token: str) -> None:
        self._client = client
        self._token = token

    def run(self, query: str) -> str:
        AgentityCapabilityGuard(self._client, self._token, "web_search").enforce()
        # Replace with real search logic (e.g. SerperDevTool, DuckDuckGo).
        print(f"  [web_search] executing: {query!r}")
        return f"Search results for: {query}"


class AgentityReadFileTool:
    """A file read tool gated by an Agentity ACT token."""

    def __init__(self, client: AgentityClient, token: str) -> None:
        self._client = client
        self._token = token

    def run(self, path: str) -> str:
        AgentityCapabilityGuard(self._client, self._token, "read_file").enforce()
        print(f"  [read_file] reading: {path!r}")
        return f"Contents of {path}"


class AgentityWriteFileTool:
    """A file write tool gated by an Agentity ACT token."""

    def __init__(self, client: AgentityClient, token: str) -> None:
        self._client = client
        self._token = token

    def run(self, path: str, content: str) -> str:
        AgentityCapabilityGuard(self._client, self._token, "write_file").enforce()
        print(f"  [write_file] writing: {path!r}")
        return f"Written to {path}"


# ---------------------------------------------------------------------------
# Crew registration + token issuance
# ---------------------------------------------------------------------------

def register_crew(client: AgentityClient) -> tuple[str, str, str]:
    """Register the crew (orchestrator) with Agentity and issue a root token.

    Returns:
        (crew_agent_id, crew_private_key, root_token)
    """
    crew_agent, crew_key = client.register_agent(
        name="crewai-crew",
        model="claude-3-5-sonnet-20241022",
        tools=["web_search", "read_file", "write_file", "code_exec"],
        description="CrewAI crew orchestrator — delegates to role agents",
    )
    print(f"Registered crew: {crew_agent.id}")

    root_token, token_id = client.issue_token(
        agent_id=crew_agent.id,
        capabilities=["web_search", "read_file", "write_file", "code_exec"],
        expires_at=int(time.time()) + 7200,  # 2 hours
        max_delegations=3,
    )
    print(f"Root token issued: {token_id}")
    return crew_agent.id, crew_key, root_token


def register_role_agent(
    client: AgentityClient,
    name: str,
    role: str,
    parent_id: str,
    tools: list[str],
) -> tuple[str, str]:
    """Register a role-specific CrewAI agent as a child of the crew.

    Returns:
        (agent_id, agent_description)
    """
    agent, _ = client.register_agent(
        name=name,
        model="claude-3-5-sonnet-20241022",
        tools=tools,
        parent_id=parent_id,
        description=f"CrewAI {role} agent",
    )
    print(f"Registered {role}: {agent.id}")
    return agent.id, role


def delegate_role_token(
    client: AgentityClient,
    parent_token: str,
    parent_key: str,
    child_agent_id: str,
    capabilities: list[str],
    ttl_seconds: int = 3600,
) -> str:
    """Delegate a capability-narrowed token to a role agent.

    Signing happens locally — the parent private key never leaves this process.
    """
    child_token = delegate_token_locally(
        encoded_parent_token=parent_token,
        child_agent_id=child_agent_id,
        capabilities=capabilities,
        expires_at=int(time.time()) + ttl_seconds,
        parent_private_key_b64=parent_key,
    )
    # Submit to server for audit recording and cascade revocation support.
    client.submit_delegated_token(child_token)
    print(f"  Delegated token to {child_agent_id} with caps: {capabilities}")
    return child_token


# ---------------------------------------------------------------------------
# Simulated crew execution
# ---------------------------------------------------------------------------

def run_researcher(client: AgentityClient, token: str, topic: str) -> str:
    """Simulate the Researcher agent — can web_search and read_file only."""
    print("\n[Researcher] Starting research...")
    search = AgentityWebSearchTool(client, token)
    reader = AgentityReadFileTool(client, token)

    results = search.run(f"{topic} latest developments 2025")
    context = reader.run("data/background.txt")

    # Attempting write_file would raise PermissionError — researcher can't write.
    try:
        writer = AgentityWriteFileTool(client, token)
        writer.run("output/report.md", "draft")
    except PermissionError as e:
        print(f"  [Researcher] Correctly blocked from write_file: {e}")

    return f"Research complete: {results} | {context}"


def run_writer(client: AgentityClient, token: str, research: str) -> str:
    """Simulate the Writer agent — can write_file and read_file only."""
    print("\n[Writer] Drafting report...")
    reader = AgentityReadFileTool(client, token)
    writer = AgentityWriteFileTool(client, token)

    template = reader.run("templates/report_template.md")
    writer.run("output/report.md", f"# Report\n\n{research}\n\nTemplate: {template}")

    # Attempting web_search would raise PermissionError — writer can't search.
    try:
        search = AgentityWebSearchTool(client, token)
        search.run("additional sources")
    except PermissionError as e:
        print(f"  [Writer] Correctly blocked from web_search: {e}")

    return "Draft written to output/report.md"


def run_reviewer(client: AgentityClient, token: str) -> str:
    """Simulate the Reviewer agent — read_file only."""
    print("\n[Reviewer] Reviewing report...")
    reader = AgentityReadFileTool(client, token)
    draft = reader.run("output/report.md")
    return f"Review complete. Report looks good. Length: {len(draft)} chars."


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Agentity + CrewAI Integration Example ===\n")

    with AgentityClient(base_url=AGENTITY_URL, api_key=ADMIN_KEY) as client:

        # 1. Register crew and issue root token.
        crew_id, crew_key, root_token = register_crew(client)

        # 2. Register role agents as children of the crew.
        print("\nRegistering role agents...")
        researcher_id, _ = register_role_agent(
            client, "researcher", "Researcher", crew_id,
            tools=["web_search", "read_file"],
        )
        writer_id, _ = register_role_agent(
            client, "writer", "Writer", crew_id,
            tools=["write_file", "read_file"],
        )
        reviewer_id, _ = register_role_agent(
            client, "reviewer", "Reviewer", crew_id,
            tools=["read_file"],
        )

        # 3. Delegate narrowed tokens to each role agent.
        print("\nDelegating tokens...")
        researcher_token = delegate_role_token(
            client, root_token, crew_key, researcher_id,
            capabilities=["web_search", "read_file"],
        )
        writer_token = delegate_role_token(
            client, root_token, crew_key, writer_id,
            capabilities=["write_file", "read_file"],
        )
        reviewer_token = delegate_role_token(
            client, root_token, crew_key, reviewer_id,
            capabilities=["read_file"],
        )

        # 4. Add a CEL policy: no delegation chains deeper than 2 hops.
        client.create_policy(
            name="crew-max-depth",
            expression="chain_depth <= 2",
            action="allow",
            priority=50,
        )
        print("\nPolicy added: chain depth ≤ 2")

        # 5. Run crew tasks with capability enforcement.
        topic = "AI agent security in 2025"
        research = run_researcher(client, researcher_token, topic)
        draft   = run_writer(client, writer_token, research)
        review  = run_reviewer(client, reviewer_token)

        print(f"\n[Crew] Tasks complete: {review}")

        # 6. Show chain depths.
        for name, token in [
            ("researcher", researcher_token),
            ("writer", writer_token),
            ("reviewer", reviewer_token),
        ]:
            verified = client.verify_token(token)
            print(f"  {name}: chain_depth={verified.chain_depth}, caps={verified.capabilities}")

        # 7. Cascade-revoke the entire crew when done.
        print("\nRevoking crew (cascade)...")
        # This revokes crew_id and all child agents (researcher, writer, reviewer).
        # Any future verify call on their tokens will return 401.
        client.revoke_agent(crew_id, cascade=True)
        print("Crew and all role agents revoked.")

        # 8. Show audit trail.
        entries = client.list_audit_entries(limit=10)
        print(f"\nLast {len(entries)} audit entries:")
        for e in entries:
            print(f"  [{e.get('type')}] {e.get('actor')} → {e.get('subject')}")


if __name__ == "__main__":
    main()
