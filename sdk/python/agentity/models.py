"""Data models for the Agentity Python SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentFingerprint:
    system_prompt_hash: str = ""
    tool_fingerprint: str = ""
    tools: list[str] = field(default_factory=list)
    model: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AgentFingerprint:
        return cls(
            system_prompt_hash=d.get("system_prompt_hash", ""),
            tool_fingerprint=d.get("tool_fingerprint", ""),
            tools=d.get("tools") or [],
            model=d.get("model", ""),
        )


@dataclass
class Agent:
    id: str
    name: str
    description: str
    version: str
    public_key: str
    key_id: str
    fingerprint: AgentFingerprint
    parent_id: str
    status: str
    metadata: dict[str, str]
    created_at: str
    updated_at: str

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Agent:
        return cls(
            id=d.get("id", ""),
            name=d.get("name", ""),
            description=d.get("description", ""),
            version=d.get("version", ""),
            public_key=d.get("public_key", ""),
            key_id=d.get("key_id", ""),
            fingerprint=AgentFingerprint.from_dict(d.get("fingerprint") or {}),
            parent_id=d.get("parent_id", ""),
            status=d.get("status", ""),
            metadata=d.get("metadata") or {},
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )


@dataclass
class BlockConditions:
    """Conditions for an ACT block."""
    expires_at: int
    not_before: int = 0
    max_delegations: int = 0
    allowed_models: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"exp": self.expires_at}
        if self.not_before:
            d["nbf"] = self.not_before
        if self.max_delegations:
            d["max_deleg"] = self.max_delegations
        if self.allowed_models:
            d["models"] = self.allowed_models
        return d


@dataclass
class Block:
    index: int
    issuer: str
    subject: str
    capabilities: list[str]
    conditions: BlockConditions
    nonce: str
    issued_at: int
    signature: str
    signer_key_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "idx": self.index,
            "iss": self.issuer,
            "sub": self.subject,
            "caps": self.capabilities,
            "cond": self.conditions.to_dict(),
            "nonce": self.nonce,
            "iat": self.issued_at,
            "sig": self.signature,
            "kid": self.signer_key_id,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Block:
        cond_raw = d.get("cond") or {}
        return cls(
            index=d.get("idx", 0),
            issuer=d.get("iss", ""),
            subject=d.get("sub", ""),
            capabilities=d.get("caps") or [],
            conditions=BlockConditions(
                expires_at=cond_raw.get("exp", 0),
                not_before=cond_raw.get("nbf", 0),
                max_delegations=cond_raw.get("max_deleg", 0),
                allowed_models=cond_raw.get("models") or [],
            ),
            nonce=d.get("nonce", ""),
            issued_at=d.get("iat", 0),
            signature=d.get("sig", ""),
            signer_key_id=d.get("kid", ""),
        )


@dataclass
class ACT:
    """AgentCapability Token."""
    version: int
    token_id: str
    blocks: list[Block]

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.version,
            "tid": self.token_id,
            "blocks": [b.to_dict() for b in self.blocks],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ACT:
        return cls(
            version=d.get("v", 1),
            token_id=d.get("tid", ""),
            blocks=[Block.from_dict(b) for b in (d.get("blocks") or [])],
        )


@dataclass
class VerifiedACT:
    token_id: str
    agent_id: str
    capabilities: list[str]
    expires_at: int
    chain_depth: int
    delegation_path: list[str]

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VerifiedACT:
        return cls(
            token_id=d.get("token_id", ""),
            agent_id=d.get("agent_id", ""),
            capabilities=d.get("capabilities") or [],
            expires_at=d.get("expires_at", 0),
            chain_depth=d.get("chain_depth", 0),
            delegation_path=d.get("delegation_path") or [],
        )
