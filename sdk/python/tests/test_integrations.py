"""Tests for Agentity framework integrations (LangChain, CrewAI, AutoGen).

All tests use unittest.mock — no real AI framework installation required.
ACT tokens are generated using agentity.crypto helpers.
"""

from __future__ import annotations

import json
import time
import unittest
from unittest.mock import MagicMock, patch

from agentity.crypto import (
    _b64url_encode,
    generate_key_pair,
    encode_token,
)
from agentity.exceptions import AgentityTokenError
from agentity.models import ACT, Block, BlockConditions
from agentity.integrations.langchain import AuthenticatedChain
from agentity.integrations.crewai import AuthenticatedCrew
from agentity.integrations.autogen import AuthenticatedAssistant
from agentity.integrations._verify import verify_capabilities


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_token(capabilities: list[str], expires_delta: int = 3600) -> str:
    """Build a minimal valid ACT token with the given capabilities."""
    priv_b64, pub_b64 = generate_key_pair()
    expires_at = int(time.time()) + expires_delta
    block = Block(
        index=0,
        issuer="agent://issuer",
        subject="agent://subject",
        capabilities=sorted(capabilities),
        conditions=BlockConditions(expires_at=expires_at),
        nonce="testnonce",
        issued_at=int(time.time()),
        signature="fakesig",
        signer_key_id="fakekid",
    )
    act = ACT(version=1, token_id="test-token-id", blocks=[block])
    return encode_token(act)


# ---------------------------------------------------------------------------
# TestVerifyCapabilities
# ---------------------------------------------------------------------------

class TestVerifyCapabilities(unittest.TestCase):

    def test_returns_effective_caps_when_all_present(self):
        token = _make_token(["read_file", "web_search"])
        result = verify_capabilities(token, ["read_file"])
        self.assertIn("read_file", result)
        self.assertIn("web_search", result)

    def test_raises_when_required_cap_missing(self):
        token = _make_token(["read_file"])
        with self.assertRaises(AgentityTokenError) as ctx:
            verify_capabilities(token, ["write_file"])
        self.assertIn("write_file", str(ctx.exception))

    def test_raises_on_invalid_token(self):
        with self.assertRaises(AgentityTokenError):
            verify_capabilities("not-a-valid-token!!!", ["read_file"])

    def test_empty_required_caps_always_passes(self):
        token = _make_token(["read_file"])
        result = verify_capabilities(token, [])
        self.assertIsInstance(result, list)

    def test_exact_match_passes(self):
        token = _make_token(["code_exec"])
        result = verify_capabilities(token, ["code_exec"])
        self.assertEqual(result, ["code_exec"])

    def test_multiple_required_caps_all_present(self):
        token = _make_token(["read_file", "write_file", "web_search"])
        result = verify_capabilities(token, ["read_file", "write_file"])
        self.assertIn("read_file", result)
        self.assertIn("write_file", result)

    def test_multiple_required_caps_one_missing(self):
        token = _make_token(["read_file"])
        with self.assertRaises(AgentityTokenError):
            verify_capabilities(token, ["read_file", "write_file"])

    def test_intersection_across_blocks(self):
        """Effective caps are intersection — multi-block token narrows caps."""
        priv_b64, pub_b64 = generate_key_pair()
        now = int(time.time())
        block0 = Block(
            index=0,
            issuer="agent://root",
            subject="agent://parent",
            capabilities=["read_file", "write_file"],
            conditions=BlockConditions(expires_at=now + 3600),
            nonce="n0",
            issued_at=now,
            signature="sig0",
            signer_key_id="kid0",
        )
        block1 = Block(
            index=1,
            issuer="agent://parent",
            subject="agent://child",
            capabilities=["read_file"],  # write_file dropped
            conditions=BlockConditions(expires_at=now + 1800),
            nonce="n1",
            issued_at=now,
            signature="sig1",
            signer_key_id="kid1",
        )
        act = ACT(version=1, token_id="multi-block", blocks=[block0, block1])
        token = encode_token(act)

        # read_file is in intersection
        result = verify_capabilities(token, ["read_file"])
        self.assertIn("read_file", result)

        # write_file is NOT in intersection
        with self.assertRaises(AgentityTokenError):
            verify_capabilities(token, ["write_file"])


# ---------------------------------------------------------------------------
# TestAuthenticatedChain
# ---------------------------------------------------------------------------

class TestAuthenticatedChain(unittest.TestCase):

    def test_invoke_with_matching_caps_no_chain(self):
        token = _make_token(["web_search"])
        chain = AuthenticatedChain(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        result = chain.invoke({"input": "hello"})
        self.assertTrue(result["verified"])
        self.assertIn("web_search", result["capabilities"])

    def test_invoke_delegates_to_chain_when_attached(self):
        token = _make_token(["web_search"])
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = {"answer": "42"}

        chain = AuthenticatedChain(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
            chain=mock_chain,
        )
        result = chain.invoke({"input": "hello"}, config={})
        mock_chain.invoke.assert_called_once_with({"input": "hello"}, config={})
        self.assertEqual(result, {"answer": "42"})

    def test_wrap_attaches_chain_and_returns_self(self):
        token = _make_token(["web_search"])
        mock_chain = MagicMock()
        ac = AuthenticatedChain(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        returned = ac.wrap(mock_chain)
        self.assertIs(returned, ac)
        self.assertIs(ac.chain, mock_chain)

    def test_invoke_raises_when_cap_missing(self):
        token = _make_token(["read_file"])
        chain = AuthenticatedChain(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        with self.assertRaises(AgentityTokenError):
            chain.invoke({"input": "hello"})

    def test_invoke_raises_on_invalid_token(self):
        chain = AuthenticatedChain(
            agent_token="garbage!!!",
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        with self.assertRaises(AgentityTokenError):
            chain.invoke({"input": "hello"})

    def test_chain_not_called_when_caps_missing(self):
        token = _make_token(["read_file"])
        mock_chain = MagicMock()
        chain = AuthenticatedChain(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
            chain=mock_chain,
        )
        with self.assertRaises(AgentityTokenError):
            chain.invoke({"input": "hello"})
        mock_chain.invoke.assert_not_called()


# ---------------------------------------------------------------------------
# TestAuthenticatedCrew
# ---------------------------------------------------------------------------

class TestAuthenticatedCrew(unittest.TestCase):

    def test_kickoff_with_matching_caps_no_crew(self):
        token = _make_token(["web_search"])
        crew = AuthenticatedCrew(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        result = crew.kickoff(inputs={"topic": "AI"})
        self.assertTrue(result["verified"])
        self.assertIn("web_search", result["capabilities"])

    def test_kickoff_delegates_to_crew_when_attached(self):
        token = _make_token(["web_search"])
        mock_crew = MagicMock()
        mock_crew.kickoff.return_value = "crew output"

        crew = AuthenticatedCrew(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
            crew=mock_crew,
        )
        result = crew.kickoff(inputs={"topic": "AI"})
        mock_crew.kickoff.assert_called_once_with(inputs={"topic": "AI"})
        self.assertEqual(result, "crew output")

    def test_wrap_attaches_crew_and_returns_self(self):
        token = _make_token(["web_search"])
        mock_crew = MagicMock()
        ac = AuthenticatedCrew(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        returned = ac.wrap(mock_crew)
        self.assertIs(returned, ac)
        self.assertIs(ac.crew, mock_crew)

    def test_kickoff_raises_when_cap_missing(self):
        token = _make_token(["read_file"])
        crew = AuthenticatedCrew(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        with self.assertRaises(AgentityTokenError):
            crew.kickoff(inputs={})

    def test_kickoff_raises_on_invalid_token(self):
        crew = AuthenticatedCrew(
            agent_token="bad-token!!!",
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        with self.assertRaises(AgentityTokenError):
            crew.kickoff()

    def test_crew_not_called_when_caps_missing(self):
        token = _make_token(["read_file"])
        mock_crew = MagicMock()
        crew = AuthenticatedCrew(
            agent_token=token,
            capabilities=["web_search"],
            base_url="http://localhost:8080",
            api_key="key",
            crew=mock_crew,
        )
        with self.assertRaises(AgentityTokenError):
            crew.kickoff()
        mock_crew.kickoff.assert_not_called()


# ---------------------------------------------------------------------------
# TestAuthenticatedAssistant
# ---------------------------------------------------------------------------

class TestAuthenticatedAssistant(unittest.TestCase):

    def test_initiate_chat_with_matching_caps_no_agent(self):
        token = _make_token(["code_exec"])
        assistant = AuthenticatedAssistant(
            agent_token=token,
            capabilities=["code_exec"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        result = assistant.initiate_chat(recipient=MagicMock(), message="hello")
        self.assertTrue(result["verified"])
        self.assertIn("code_exec", result["capabilities"])

    def test_initiate_chat_delegates_to_agent_when_attached(self):
        token = _make_token(["code_exec"])
        mock_agent = MagicMock()
        mock_agent.initiate_chat.return_value = "chat result"

        assistant = AuthenticatedAssistant(
            agent_token=token,
            capabilities=["code_exec"],
            base_url="http://localhost:8080",
            api_key="key",
            agent=mock_agent,
        )
        recipient = MagicMock()
        result = assistant.initiate_chat(recipient, message="run code", max_turns=3)
        mock_agent.initiate_chat.assert_called_once_with(recipient, message="run code", max_turns=3)
        self.assertEqual(result, "chat result")

    def test_wrap_attaches_agent_and_returns_self(self):
        token = _make_token(["code_exec"])
        mock_agent = MagicMock()
        aa = AuthenticatedAssistant(
            agent_token=token,
            capabilities=["code_exec"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        returned = aa.wrap(mock_agent)
        self.assertIs(returned, aa)
        self.assertIs(aa.agent, mock_agent)

    def test_initiate_chat_raises_when_cap_missing(self):
        token = _make_token(["read_file"])
        assistant = AuthenticatedAssistant(
            agent_token=token,
            capabilities=["code_exec"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        with self.assertRaises(AgentityTokenError):
            assistant.initiate_chat(recipient=MagicMock(), message="hello")

    def test_initiate_chat_raises_on_invalid_token(self):
        assistant = AuthenticatedAssistant(
            agent_token="invalid!!!",
            capabilities=["code_exec"],
            base_url="http://localhost:8080",
            api_key="key",
        )
        with self.assertRaises(AgentityTokenError):
            assistant.initiate_chat(recipient=MagicMock(), message="hello")

    def test_agent_not_called_when_caps_missing(self):
        token = _make_token(["read_file"])
        mock_agent = MagicMock()
        assistant = AuthenticatedAssistant(
            agent_token=token,
            capabilities=["code_exec"],
            base_url="http://localhost:8080",
            api_key="key",
            agent=mock_agent,
        )
        with self.assertRaises(AgentityTokenError):
            assistant.initiate_chat(recipient=MagicMock(), message="hello")
        mock_agent.initiate_chat.assert_not_called()


if __name__ == "__main__":
    unittest.main()
