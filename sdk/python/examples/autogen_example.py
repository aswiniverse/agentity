"""
AutoGen integration example for Agentity.

This example shows how to:
1. Register an AutoGen multi-agent conversation group with Agentity
2. Issue a root ACT token to the UserProxyAgent (orchestrator)
3. Delegate narrowed tokens to AssistantAgents for each role
4. Gate function calls with capability checks before execution
5. Use an AgentityConversableAgent wrapper that auto-enforces tokens
6. Cascade-revoke all agents when the conversation ends

Architecture:
    UserProxy (root token: web_search + code_exec + read_file + write_file)
      ├── ResearchAssistant  (delegated: web_search, read_file)
      └── CoderAssistant     (delegated: code_exec, read_file, write_file)

Requirements:
    pip install agentity pyautogen
"""

from __future__ import annotations

import time
from typing import Any, Callable

from agentity import AgentityClient
from agentity.crypto import delegate_token_locally

AGENTITY_URL = "http://localhost:8080"
ADMIN_KEY = "dev-admin-key"


# ---------------------------------------------------------------------------
# Capability guard
# ---------------------------------------------------------------------------

class AgentityCapabilityGuard:
    """Enforces ACT token capability checks before function execution.

    Use this inside any AutoGen function map entry to ensure the calling
    agent's token grants the required capability.

    Example::

        def search_web(query: str, token: str) -> str:
            AgentityCapabilityGuard(client, token, "web_search").enforce()
            return real_search(query)
    """

    def __init__(self, client: AgentityClient, token: str, required_cap: str) -> None:
        self._client = client
        self._token = token
        self._required_cap = required_cap

    def check(self) -> bool:
        try:
            verified = self._client.verify_token(self._token)
            return self._required_cap in verified.capabilities
        except Exception:
            return False

    def enforce(self) -> None:
        if not self.check():
            raise PermissionError(
                f"Capability '{self._required_cap}' not granted by ACT token. "
                "Agent may be revoked or token lacks this capability."
            )


# ---------------------------------------------------------------------------
# AutoGen-compatible function registry with built-in ACT enforcement
# ---------------------------------------------------------------------------

class AgentityFunctionRegistry:
    """Builds an AutoGen function_map where every function is capability-gated.

    Usage::

        registry = AgentityFunctionRegistry(client, agent_token)
        registry.register("search_web", "web_search", search_impl)
        registry.register("run_code",   "code_exec",  exec_impl)

        # Pass to AutoGen agent:
        agent = ConversableAgent(..., function_map=registry.function_map)
    """

    def __init__(self, client: AgentityClient, token: str) -> None:
        self._client = client
        self._token = token
        self._map: dict[str, Callable] = {}

    def register(self, fn_name: str, required_cap: str, fn: Callable) -> "AgentityFunctionRegistry":
        """Register a function with a required ACT capability.

        Args:
            fn_name:      The function name AutoGen will call.
            required_cap: The ACT capability required to execute this function.
            fn:           The actual implementation to run.
        """
        guard = AgentityCapabilityGuard(self._client, self._token, required_cap)

        def gated(*args: Any, **kwargs: Any) -> Any:
            guard.enforce()
            return fn(*args, **kwargs)

        gated.__name__ = fn_name
        self._map[fn_name] = gated
        return self

    @property
    def function_map(self) -> dict[str, Callable]:
        return self._map


# ---------------------------------------------------------------------------
# Simulated agent functions (replace with real AutoGen tool implementations)
# ---------------------------------------------------------------------------

def _search_web(query: str) -> str:
    print(f"  [web_search] query: {query!r}")
    return f"Web results for '{query}': [result1, result2, result3]"


def _read_file(path: str) -> str:
    print(f"  [read_file] reading: {path!r}")
    return f"File contents of {path!r}"


def _write_file(path: str, content: str) -> str:
    print(f"  [write_file] writing to: {path!r}")
    return f"Written {len(content)} bytes to {path!r}"


def _execute_code(code: str) -> str:
    print(f"  [code_exec] running code snippet ({len(code)} chars)")
    return "Code executed. Output: [stdout output here]"


# ---------------------------------------------------------------------------
# Agent registration + token issuance
# ---------------------------------------------------------------------------

def setup_autogen_group(client: AgentityClient) -> dict[str, Any]:
    """Register the AutoGen group and issue all tokens.

    Returns a dict with agent IDs and their delegated tokens.
    """
    # Register UserProxy as the root orchestrator.
    user_proxy, proxy_key = client.register_agent(
        name="autogen-user-proxy",
        model="human",  # UserProxy represents the human-in-the-loop
        tools=["web_search", "code_exec", "read_file", "write_file"],
        description="AutoGen UserProxyAgent — orchestrates the conversation",
    )
    print(f"UserProxy registered: {user_proxy.id}")

    root_token, root_token_id = client.issue_token(
        agent_id=user_proxy.id,
        capabilities=["web_search", "code_exec", "read_file", "write_file"],
        expires_at=int(time.time()) + 7200,
        max_delegations=2,
    )
    print(f"Root token issued: {root_token_id}")

    # Register AssistantAgents as children of UserProxy.
    research_agent, _ = client.register_agent(
        name="autogen-research-assistant",
        model="claude-3-5-sonnet-20241022",
        tools=["web_search", "read_file"],
        parent_id=user_proxy.id,
        description="AutoGen AssistantAgent — research and web search",
    )
    print(f"ResearchAssistant registered: {research_agent.id}")

    coder_agent, _ = client.register_agent(
        name="autogen-coder-assistant",
        model="claude-3-5-sonnet-20241022",
        tools=["code_exec", "read_file", "write_file"],
        parent_id=user_proxy.id,
        description="AutoGen AssistantAgent — code execution and file I/O",
    )
    print(f"CoderAssistant registered: {coder_agent.id}")

    # Delegate narrowed tokens (client-side signing — proxy key never leaves).
    research_token = delegate_token_locally(
        encoded_parent_token=root_token,
        child_agent_id=research_agent.id,
        capabilities=["web_search", "read_file"],
        expires_at=int(time.time()) + 3600,
        parent_private_key_b64=proxy_key,
    )
    client.submit_delegated_token(research_token)
    print(f"  Delegated research token: web_search, read_file")

    coder_token = delegate_token_locally(
        encoded_parent_token=root_token,
        child_agent_id=coder_agent.id,
        capabilities=["code_exec", "read_file", "write_file"],
        expires_at=int(time.time()) + 3600,
        parent_private_key_b64=proxy_key,
    )
    client.submit_delegated_token(coder_token)
    print(f"  Delegated coder token: code_exec, read_file, write_file")

    return {
        "proxy_id":       user_proxy.id,
        "research_id":    research_agent.id,
        "coder_id":       coder_agent.id,
        "root_token":     root_token,
        "research_token": research_token,
        "coder_token":    coder_token,
    }


# ---------------------------------------------------------------------------
# Simulated AutoGen conversation with capability enforcement
# ---------------------------------------------------------------------------

def simulate_autogen_conversation(client: AgentityClient, group: dict[str, Any]) -> None:
    """Simulate an AutoGen multi-agent conversation with Agentity enforcement.

    In a real AutoGen setup you would:
      1. Build `function_map` from AgentityFunctionRegistry for each agent
      2. Pass `function_map` to `ConversableAgent(function_map=...)`
      3. AutoGen calls functions by name; Agentity enforces capabilities

    Here we simulate that flow directly.
    """
    print("\n--- Conversation Start ---")

    # Build function maps for each agent role.
    research_registry = (
        AgentityFunctionRegistry(client, group["research_token"])
        .register("search_web", "web_search", _search_web)
        .register("read_file",  "read_file",  _read_file)
    )

    coder_registry = (
        AgentityFunctionRegistry(client, group["coder_token"])
        .register("execute_code", "code_exec",   _execute_code)
        .register("read_file",    "read_file",   _read_file)
        .register("write_file",   "write_file",  _write_file)
    )

    # UserProxy initiates: "Research AI agent security, then write a code summary."
    print("\n[UserProxy] Task: research AI agent security, write a code summary.\n")

    # Turn 1: ResearchAssistant does web search.
    print("[ResearchAssistant] Calling search_web...")
    results = research_registry.function_map["search_web"]("AI agent security 2025")

    # Turn 2: ResearchAssistant reads a reference file.
    print("[ResearchAssistant] Calling read_file...")
    context = research_registry.function_map["read_file"]("data/security-notes.txt")

    # ResearchAssistant tries to execute code — BLOCKED (not in its capabilities).
    print("[ResearchAssistant] Attempting execute_code (should fail)...")
    try:
        research_registry.register("execute_code", "code_exec", _execute_code)
        research_registry.function_map["execute_code"]("print('hello')")
    except PermissionError as e:
        print(f"  Correctly blocked: {e}")

    # Turn 3: CoderAssistant writes the summary.
    print("\n[CoderAssistant] Calling execute_code...")
    output = coder_registry.function_map["execute_code"](
        f"summary = summarize({results!r})\nprint(summary)"
    )
    print("[CoderAssistant] Calling write_file...")
    coder_registry.function_map["write_file"]("output/security_summary.md", output)

    # CoderAssistant tries web_search — BLOCKED.
    print("[CoderAssistant] Attempting search_web (should fail)...")
    try:
        coder_registry.register("search_web", "web_search", _search_web)
        coder_registry.function_map["search_web"]("more sources")
    except PermissionError as e:
        print(f"  Correctly blocked: {e}")

    print("\n--- Conversation End ---")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== Agentity + AutoGen Integration Example ===\n")

    with AgentityClient(base_url=AGENTITY_URL, api_key=ADMIN_KEY) as client:

        # 1. Register agents and issue/delegate tokens.
        group = setup_autogen_group(client)

        # 2. Add a CEL policy — block any agent using a deprecated model.
        client.create_policy(
            name="no-deprecated-models",
            expression='agent_model != "gpt-3.5-turbo"',
            action="allow",
            priority=100,
        )
        print("\nPolicy added: no deprecated models")

        # 3. Simulate the AutoGen conversation.
        simulate_autogen_conversation(client, group)

        # 4. Verify token chain depths.
        print("\nToken chain depths:")
        for label, token in [
            ("root (UserProxy)",        group["root_token"]),
            ("research (ResearchAsst)", group["research_token"]),
            ("coder (CoderAsst)",       group["coder_token"]),
        ]:
            verified = client.verify_token(token)
            print(
                f"  {label}: "
                f"chain_depth={verified.chain_depth}, "
                f"caps={verified.capabilities}"
            )

        # 5. Cascade-revoke all agents when the conversation is done.
        print("\nRevoking AutoGen group (cascade)...")
        client.revoke_agent(group["proxy_id"], cascade=True)
        print("UserProxy and all AssistantAgents revoked.")

        # 6. Confirm revocation — verify should now fail.
        print("\nConfirming revocation...")
        for label, token in [
            ("research", group["research_token"]),
            ("coder",    group["coder_token"]),
        ]:
            try:
                client.verify_token(token)
                print(f"  [{label}] ERROR: token still valid after revocation!")
            except Exception as e:
                print(f"  [{label}] Correctly rejected: {e}")

        # 7. Print audit trail.
        entries = client.list_audit_entries(limit=10)
        print(f"\nLast {len(entries)} audit entries:")
        for e in entries:
            print(f"  [{e.get('type')}] {e.get('actor')} → {e.get('subject')}")


if __name__ == "__main__":
    main()
