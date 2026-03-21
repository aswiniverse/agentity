"""
Cryptographic utilities for the Agentity Python SDK.

Implements Ed25519 key generation and client-side ACT token delegation,
matching the Go server's signing format exactly:
- Keys: base64url (no padding) of raw Ed25519 bytes
- Key IDs: base64url (no padding) of SHA-256(public key)
- Signatures: Ed25519 over canonical JSON of block (excluding 'sig' field)
- Token encoding: base64url (no padding) of JSON
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .exceptions import AgentityKeyError, AgentityTokenError
from .models import ACT, Block, BlockConditions


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Base64url decode without padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def generate_key_pair() -> tuple[str, str]:
    """Generate an Ed25519 key pair.

    Returns:
        (private_key_b64, public_key_b64) — both base64url-encoded, no padding.
        The private key is 64 raw bytes (seed + public key), matching Go's format.
    """
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()  # 32-byte seed
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()  # 32-byte public key
    # Go's ed25519.PrivateKey is 64 bytes: seed || public key
    full_priv = priv_bytes + pub_bytes
    return _b64url_encode(full_priv), _b64url_encode(pub_bytes)


def compute_key_id(public_key_b64: str) -> str:
    """Compute the key ID for a base64url-encoded public key.

    Matches Go's agcrypto.ComputeKeyID: SHA-256(pubkey bytes), base64url.
    """
    pub_bytes = _b64url_decode(public_key_b64)
    digest = hashlib.sha256(pub_bytes).digest()
    return _b64url_encode(digest)


def _load_private_key(private_key_b64: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a base64url-encoded 64-byte string."""
    try:
        raw = _b64url_decode(private_key_b64)
    except Exception as e:
        raise AgentityKeyError(f"Failed to decode private key: {e}") from e
    if len(raw) == 64:
        seed = raw[:32]
    elif len(raw) == 32:
        seed = raw
    else:
        raise AgentityKeyError(f"Invalid private key length: {len(raw)} bytes (expected 64 or 32)")
    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    except Exception as e:
        raise AgentityKeyError(f"Failed to load Ed25519 private key: {e}") from e


def _canonical_json(obj: Any) -> bytes:
    """Produce canonical JSON with sorted keys and no extra whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sign_block(block_dict: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Sign a block dict (without the 'sig' field) using Ed25519.

    Returns base64url-encoded signature (no padding).
    """
    canonical = _canonical_json(block_dict)
    sig_bytes = private_key.sign(canonical)
    return _b64url_encode(sig_bytes)


def decode_token(encoded: str) -> ACT:
    """Decode a base64url-encoded ACT token string into an ACT object."""
    try:
        data = _b64url_decode(encoded)
        d = json.loads(data)
        return ACT.from_dict(d)
    except Exception as e:
        raise AgentityTokenError(f"Failed to decode token: {e}") from e


def encode_token(act: ACT) -> str:
    """Encode an ACT object to a base64url string."""
    try:
        data = json.dumps(act.to_dict(), sort_keys=False, separators=(",", ":")).encode()
        return _b64url_encode(data)
    except Exception as e:
        raise AgentityTokenError(f"Failed to encode token: {e}") from e


def _effective_capabilities(blocks: list[Block]) -> set[str]:
    """Compute effective capabilities as intersection across all blocks."""
    if not blocks:
        return set()
    caps = set(blocks[0].capabilities)
    for block in blocks[1:]:
        caps &= set(block.capabilities)
    return caps


def _generate_nonce() -> str:
    return _b64url_encode(os.urandom(16))


def delegate_token_locally(
    encoded_parent_token: str,
    child_agent_id: str,
    capabilities: list[str],
    expires_at: int,
    parent_private_key_b64: str,
    max_delegations: int = 0,
    not_before: int = 0,
) -> str:
    """Create a delegated ACT token by appending a new signed block.

    This is a pure client-side operation — the parent agent's private key
    never leaves the process. The returned encoded token can be submitted to
    POST /api/v1/tokens/delegate for audit recording, or used directly.

    Args:
        encoded_parent_token: The base64url-encoded parent ACT.
        child_agent_id: The agent URI of the delegate (e.g. "agent://uuid").
        capabilities: Capabilities to grant. Must be a subset of the parent's
            effective capabilities (capability amplification is denied).
        expires_at: Unix timestamp for this block's expiry. Must be <= parent expiry.
        parent_private_key_b64: The parent agent's 64-byte Ed25519 private key,
            base64url-encoded (as returned by register_agent()).
        max_delegations: Optional cap on further delegation depth.
        not_before: Optional Unix timestamp before which the block is invalid.

    Returns:
        Base64url-encoded delegated ACT token.

    Raises:
        AgentityTokenError: If capability amplification is detected, expiry
            monotonicity is violated, or max delegation depth is exceeded.
    """
    parent = decode_token(encoded_parent_token)
    if not parent.blocks:
        raise AgentityTokenError("Parent token has no blocks")

    # Capability subset check.
    effective = _effective_capabilities(parent.blocks)
    requested = set(capabilities)
    amplified = requested - effective
    if amplified:
        raise AgentityTokenError(
            f"Capability amplification denied: {amplified} not in parent effective capabilities {effective}"
        )

    # Expiry monotonicity.
    last_block = parent.blocks[-1]
    if expires_at > last_block.conditions.expires_at:
        raise AgentityTokenError(
            f"Delegation expiry ({expires_at}) must be <= parent expiry ({last_block.conditions.expires_at})"
        )

    # Max delegations check.
    root_block = parent.blocks[0]
    current_depth = len(parent.blocks)
    for check_block in (last_block, root_block):
        if check_block.conditions.max_delegations > 0:
            if current_depth >= check_block.conditions.max_delegations + 1:
                raise AgentityTokenError(
                    f"Max delegation depth reached: {check_block.conditions.max_delegations}"
                )

    priv_key = _load_private_key(parent_private_key_b64)
    pub_bytes = priv_key.public_key().public_bytes_raw()
    pub_b64 = _b64url_encode(pub_bytes)
    kid = compute_key_id(pub_b64)

    sorted_caps = sorted(capabilities)
    nonce = _generate_nonce()
    issued_at = int(time.time())

    cond = BlockConditions(
        expires_at=expires_at,
        not_before=not_before,
        max_delegations=max_delegations,
    )

    # Build block dict for signing (no 'sig' field).
    block_for_signing: dict[str, Any] = {
        "idx": current_depth,
        "iss": last_block.subject,
        "sub": child_agent_id,
        "caps": sorted_caps,
        "cond": cond.to_dict(),
        "nonce": nonce,
        "iat": issued_at,
        "kid": kid,
    }
    signature = _sign_block(block_for_signing, priv_key)

    new_block = Block(
        index=current_depth,
        issuer=last_block.subject,
        subject=child_agent_id,
        capabilities=sorted_caps,
        conditions=cond,
        nonce=nonce,
        issued_at=issued_at,
        signature=signature,
        signer_key_id=kid,
    )

    delegated = ACT(
        version=parent.version,
        token_id=parent.token_id,
        blocks=parent.blocks + [new_block],
    )
    return encode_token(delegated)
