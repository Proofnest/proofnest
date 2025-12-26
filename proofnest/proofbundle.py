"""
ProofBundle v0.1 Implementation

Portable, verifiable proof format for AI decisions and agent communication.
Uses post-quantum signatures (Dilithium/ML-DSA-65) and SHA3-256 hashing.

Spec: docs/PROOFBUNDLE_v0.1.md
Schema: schemas/proofbundle.v0.1.schema.json

Copyright 2025 Stellanium Ltd. Licensed under Apache 2.0.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path

# JCS canonicalization - RFC 8785
try:
    import jcs
    HAS_JCS = True
except ImportError:
    HAS_JCS = False

# JSON Schema validation
try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

# Internal imports
from .crypto.dilithium import (
    generate_ml_dsa_keypair,
    ml_dsa_sign,
    ml_dsa_verify,
    DilithiumError,
)
from .crypto.constants import AlgorithmID

__all__ = [
    'ProofBundle',
    'ProofBundleType',
    'AnchorStatus',
    'AnchorMethod',
    'MessageType',
    'BroadcastScope',
    'RevocationReason',
    'AttestationMethod',
    'create_proofbundle',
    'verify_proofbundle',
    'verify_proofbundle_standalone',
]

# =============================================================================
# SECURITY CONSTANTS (v2.16.0 hardening)
# =============================================================================

import os

# Maximum JSON size - default 1MB, configurable via env for enterprise
# Security: 10MB was too large - jsonschema + large JSON = CPU/memory DoS
_DEFAULT_MAX_JSON_SIZE = 1 * 1024 * 1024  # 1MB
_env_max_size = os.environ.get("PROOFNEST_MAX_JSON_SIZE", "")
MAX_JSON_SIZE = int(_env_max_size) if _env_max_size.isdigit() else _DEFAULT_MAX_JSON_SIZE

# Maximum file size for from_file() (same as JSON)
MAX_FILE_SIZE = MAX_JSON_SIZE

# Allowed hash algorithms (whitelist approach)
ALLOWED_HASH_ALGORITHMS = frozenset({'sha3-256'})

# Maximum number of anchors per bundle
MAX_ANCHORS = 10

# Valid timestamp year range
MIN_TIMESTAMP_YEAR = 2020
MAX_TIMESTAMP_YEAR = 2100

# Maximum clock skew for future timestamps (5 minutes)
MAX_FUTURE_SECONDS = 300


# =============================================================================
# ENUMS
# =============================================================================

class ProofBundleType(Enum):
    """Type of proof in the bundle."""
    DECISION = "decision"
    DOCUMENT = "document"
    ENVELOPE = "envelope"
    ATTESTATION = "attestation"
    REVOCATION = "revocation"


class AnchorStatus(Enum):
    """Status of blockchain anchor."""
    PENDING = "pending"
    CONFIRMED = "confirmed"


class AnchorMethod(Enum):
    """Method used for anchoring."""
    OPENTIMESTAMPS = "opentimestamps"
    MERKLE = "merkle"
    DIRECT = "direct"


class MessageType(Enum):
    """Type of envelope message (AI-to-AI)."""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"


class BroadcastScope(Enum):
    """Scope for broadcast messages."""
    LOCAL = "local"
    MESH = "mesh"
    PUBLIC = "public"


class RevocationReason(Enum):
    """Reason for key revocation."""
    SCHEDULED_ROTATION = "scheduled_rotation"
    COMPROMISE = "compromise"
    SUPERSEDED = "superseded"
    CESSATION = "cessation"


class AttestationMethod(Enum):
    """Method for privacy-preserving attestation."""
    COMMITMENT = "commitment"
    ZK_SNARK = "zk_snark"
    ZK_STARK = "zk_stark"
    REDACTED = "redacted"


# =============================================================================
# HASH UTILITIES
# =============================================================================

def sha3_256(data: bytes) -> bytes:
    """Compute SHA3-256 hash."""
    return hashlib.sha3_256(data).digest()


def sha3_256_hex(data: bytes) -> str:
    """Compute SHA3-256 hash and return as hex string."""
    return hashlib.sha3_256(data).hexdigest()


def format_hash(hash_bytes: bytes, algorithm: str = "sha3-256") -> str:
    """Format hash as 'algorithm:hex' string."""
    return f"{algorithm}:{hash_bytes.hex()}"


def parse_hash(hash_str: str, strict: bool = True) -> Tuple[str, bytes]:
    """
    Parse 'algorithm:hex' string into (algorithm, bytes).

    Args:
        hash_str: Hash string in format 'algorithm:hex'
        strict: If True, only allow algorithms in ALLOWED_HASH_ALGORITHMS

    Raises:
        ValueError: If format is invalid or algorithm not allowed (when strict=True)
    """
    if ':' not in hash_str:
        raise ValueError(f"Invalid hash format: {hash_str}")

    algorithm, hex_value = hash_str.split(':', 1)

    # Security: Whitelist approach - only allow approved algorithms
    if strict and algorithm not in ALLOWED_HASH_ALGORITHMS:
        raise ValueError(
            f"Hash algorithm '{algorithm}' not allowed. "
            f"Allowed: {', '.join(sorted(ALLOWED_HASH_ALGORITHMS))}"
        )

    # Validate hex string format and length
    if not re.match(r'^[a-f0-9]{64}$', hex_value):
        raise ValueError(f"Invalid SHA3-256 hash: must be 64 hex characters")

    return algorithm, bytes.fromhex(hex_value)


def validate_hash_format(hash_str: str) -> bool:
    """Validate hash string format."""
    pattern = r'^sha3-256:[a-f0-9]{64}$'
    return bool(re.match(pattern, hash_str))


# =============================================================================
# JCS CANONICALIZATION (RFC 8785)
# =============================================================================

def jcs_canonicalize(obj: Any) -> bytes:
    """
    Canonicalize JSON object per RFC 8785 (JSON Canonicalization Scheme).

    If jcs library not available, falls back to deterministic JSON.
    """
    if HAS_JCS:
        return jcs.canonicalize(obj)
    else:
        # Fallback: sorted keys, no whitespace, ensure_ascii=False for UTF-8
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=False
        ).encode('utf-8')


# =============================================================================
# TIMESTAMP UTILITIES
# =============================================================================

def iso_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format with milliseconds."""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def parse_timestamp(ts: str) -> datetime:
    """
    Parse ISO 8601 timestamp with security validation.

    Raises:
        ValueError: If timestamp is invalid, missing timezone, outside valid range,
                   or too far in the future
    """
    # Handle both 'Z' and '+00:00' suffixes
    if ts.endswith('Z'):
        ts = ts[:-1] + '+00:00'

    parsed = datetime.fromisoformat(ts)

    # Security: Require timezone (naive timestamps are ambiguous)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include timezone (e.g., 'Z' or '+00:00')")

    # Security: Validate year range to prevent edge cases
    if parsed.year < MIN_TIMESTAMP_YEAR or parsed.year > MAX_TIMESTAMP_YEAR:
        raise ValueError(
            f"Timestamp year {parsed.year} outside valid range "
            f"({MIN_TIMESTAMP_YEAR}-{MAX_TIMESTAMP_YEAR})"
        )

    # Security: Reject timestamps too far in the future (clock skew protection)
    now = datetime.now(timezone.utc)
    max_future = now + timedelta(seconds=MAX_FUTURE_SECONDS)
    if parsed > max_future:
        raise ValueError(
            f"Timestamp {ts} is too far in the future "
            f"(max {MAX_FUTURE_SECONDS}s clock skew allowed)"
        )

    return parsed


# =============================================================================
# KEY ID UTILITIES
# =============================================================================

def compute_key_id(public_key: bytes, length: int = 8) -> str:
    """
    Compute key_id from public key.

    key_id = first N bytes of SHA3-256(public_key), as hex
    Default: 8 bytes = 16 hex characters
    """
    hash_bytes = sha3_256(public_key)
    return hash_bytes[:length].hex()


def compute_public_key_hash(public_key: bytes) -> str:
    """Compute full public key hash in format 'sha3-256:hex'."""
    return format_hash(sha3_256(public_key))


# =============================================================================
# PAYLOAD DATACLASS
# =============================================================================

@dataclass
class Payload:
    """Payload section of ProofBundle."""
    hash: str
    hash_algorithm: str = "sha3-256"
    content: Optional[Any] = None
    content_type: str = "application/json"
    content_url: Optional[str] = None
    commitment_only: bool = False

    @classmethod
    def from_content(cls, content: Any, content_type: str = "application/json") -> 'Payload':
        """Create payload from content, computing hash automatically."""
        if isinstance(content, bytes):
            content_bytes = content
        elif isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = jcs_canonicalize(content)

        content_hash = format_hash(sha3_256(content_bytes))

        return cls(
            hash=content_hash,
            hash_algorithm="sha3-256",
            content=content,
            content_type=content_type,
            commitment_only=False
        )

    @classmethod
    def commitment(cls, content: Any, content_type: str = "application/json") -> 'Payload':
        """Create commitment-only payload (hash without content)."""
        if isinstance(content, bytes):
            content_bytes = content
        elif isinstance(content, str):
            content_bytes = content.encode('utf-8')
        else:
            content_bytes = jcs_canonicalize(content)

        content_hash = format_hash(sha3_256(content_bytes))

        return cls(
            hash=content_hash,
            hash_algorithm="sha3-256",
            content=None,
            content_type=content_type,
            commitment_only=True
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hash": self.hash,
            "hash_algorithm": self.hash_algorithm,
            "content": self.content,
            "content_type": self.content_type,
            "content_url": self.content_url,
            "commitment_only": self.commitment_only
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Payload':
        """Create from dictionary."""
        return cls(
            hash=data["hash"],
            hash_algorithm=data.get("hash_algorithm", "sha3-256"),
            content=data.get("content"),
            content_type=data.get("content_type", "application/json"),
            content_url=data.get("content_url"),
            commitment_only=data.get("commitment_only", False)
        )

    def verify_content(self) -> bool:
        """Verify that content matches hash."""
        if self.content is None:
            return True  # No content to verify (commitment_only)

        if isinstance(self.content, bytes):
            content_bytes = self.content
        elif isinstance(self.content, str):
            content_bytes = self.content.encode('utf-8')
        else:
            content_bytes = jcs_canonicalize(self.content)

        computed_hash = format_hash(sha3_256(content_bytes))
        return computed_hash == self.hash


# =============================================================================
# SIGNER DATACLASS
# =============================================================================

@dataclass
class Signer:
    """Signer section of ProofBundle."""
    key_id: str
    key_version: int
    algorithm: str
    public_key_hash: str
    did: str

    @classmethod
    def from_public_key(
        cls,
        public_key: bytes,
        key_version: int = 1,
        algorithm: str = "dilithium3"
    ) -> 'Signer':
        """Create signer from public key bytes."""
        key_id = compute_key_id(public_key)
        public_key_hash = compute_public_key_hash(public_key)
        did = f"did:honest:{key_id}"

        return cls(
            key_id=key_id,
            key_version=key_version,
            algorithm=algorithm,
            public_key_hash=public_key_hash,
            did=did
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "key_version": self.key_version,
            "algorithm": self.algorithm,
            "public_key_hash": self.public_key_hash,
            "did": self.did
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Signer':
        """Create from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_version=data["key_version"],
            algorithm=data["algorithm"],
            public_key_hash=data["public_key_hash"],
            did=data["did"]
        )


# =============================================================================
# SIGNATURE DATACLASS
# =============================================================================

@dataclass
class Signature:
    """Signature section of ProofBundle."""
    algorithm: str
    signing_root: str
    value: str  # Base64 encoded
    signed_at: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "algorithm": self.algorithm,
            "signing_root": self.signing_root,
            "value": self.value,
            "signed_at": self.signed_at
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Signature':
        """Create from dictionary."""
        return cls(
            algorithm=data["algorithm"],
            signing_root=data["signing_root"],
            value=data["value"],
            signed_at=data["signed_at"]
        )


# =============================================================================
# ANCHOR DATACLASS
# =============================================================================

@dataclass
class Anchor:
    """Blockchain anchor for timestamp proof."""
    chain: str
    method: str
    status: str
    submitted_at: str
    confirmed_at: Optional[str] = None
    block_height: Optional[int] = None
    tx_id: Optional[str] = None
    proof: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chain": self.chain,
            "method": self.method,
            "status": self.status,
            "submitted_at": self.submitted_at,
            "confirmed_at": self.confirmed_at,
            "block_height": self.block_height,
            "tx_id": self.tx_id,
            "proof": self.proof
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Anchor':
        """Create from dictionary."""
        return cls(
            chain=data["chain"],
            method=data["method"],
            status=data["status"],
            submitted_at=data["submitted_at"],
            confirmed_at=data.get("confirmed_at"),
            block_height=data.get("block_height"),
            tx_id=data.get("tx_id"),
            proof=data.get("proof")
        )

    @classmethod
    def bitcoin_ots(cls) -> 'Anchor':
        """Create pending Bitcoin OpenTimestamps anchor."""
        return cls(
            chain="bitcoin",
            method="opentimestamps",
            status="pending",
            submitted_at=iso_timestamp()
        )


# =============================================================================
# ENVELOPE DATACLASS (AI-to-AI)
# =============================================================================

@dataclass
class Envelope:
    """Envelope section for AI-to-AI messages."""
    from_agent_id: str
    from_key_id: str
    to_mode: str  # "unicast" or "broadcast"
    message_type: str
    to_agent_id: Optional[str] = None
    broadcast_scope: Optional[str] = None
    ttl_seconds: Optional[int] = None
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "from": {
                "agent_id": self.from_agent_id,
                "key_id": self.from_key_id
            },
            "to": {
                "mode": self.to_mode,
                "agent_id": self.to_agent_id
            },
            "broadcast_scope": self.broadcast_scope,
            "ttl_seconds": self.ttl_seconds,
            "message_type": self.message_type,
            "correlation_id": self.correlation_id,
            "reply_to": self.reply_to
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Envelope':
        """Create from dictionary."""
        return cls(
            from_agent_id=data["from"]["agent_id"],
            from_key_id=data["from"]["key_id"],
            to_mode=data["to"]["mode"],
            to_agent_id=data["to"].get("agent_id"),
            broadcast_scope=data.get("broadcast_scope"),
            ttl_seconds=data.get("ttl_seconds"),
            message_type=data["message_type"],
            correlation_id=data.get("correlation_id"),
            reply_to=data.get("reply_to")
        )

    @classmethod
    def unicast(
        cls,
        from_agent_id: str,
        from_key_id: str,
        to_agent_id: str,
        message_type: str = "request",
        correlation_id: Optional[str] = None
    ) -> 'Envelope':
        """Create unicast envelope (one recipient)."""
        return cls(
            from_agent_id=from_agent_id,
            from_key_id=from_key_id,
            to_mode="unicast",
            to_agent_id=to_agent_id,
            message_type=message_type,
            correlation_id=correlation_id
        )

    @classmethod
    def broadcast(
        cls,
        from_agent_id: str,
        from_key_id: str,
        message_type: str = "notification",
        scope: str = "local",
        ttl_seconds: int = 3600
    ) -> 'Envelope':
        """Create broadcast envelope (multiple recipients)."""
        return cls(
            from_agent_id=from_agent_id,
            from_key_id=from_key_id,
            to_mode="broadcast",
            broadcast_scope=scope,
            ttl_seconds=ttl_seconds,
            message_type=message_type
        )


# =============================================================================
# REVOCATION DATACLASS
# =============================================================================

@dataclass
class Revocation:
    """Revocation section for key revocation."""
    target_key_id: str
    target_key_version: int
    reason: str
    effective_at: str
    successor_key_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target_key_id": self.target_key_id,
            "target_key_version": self.target_key_version,
            "reason": self.reason,
            "successor_key_id": self.successor_key_id,
            "effective_at": self.effective_at
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Revocation':
        """Create from dictionary."""
        return cls(
            target_key_id=data["target_key_id"],
            target_key_version=data["target_key_version"],
            reason=data["reason"],
            effective_at=data["effective_at"],
            successor_key_id=data.get("successor_key_id")
        )


# =============================================================================
# ATTESTATION DATACLASS
# =============================================================================

@dataclass
class Attestation:
    """Attestation section for privacy-preserving claims."""
    claim: str
    method: str
    proof_data: Optional[str] = None
    verifier_hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "claim": self.claim,
            "method": self.method,
            "proof_data": self.proof_data,
            "verifier_hint": self.verifier_hint
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Attestation':
        """Create from dictionary."""
        return cls(
            claim=data["claim"],
            method=data["method"],
            proof_data=data.get("proof_data"),
            verifier_hint=data.get("verifier_hint")
        )


# =============================================================================
# PROOFBUNDLE MAIN CLASS
# =============================================================================

@dataclass
class ProofBundle:
    """
    ProofBundle v0.1 - Portable, verifiable proof format.

    Example usage:
        # Create a decision proof
        bundle = ProofBundle.decision(
            content={"action": "approve", "reason": "All criteria met"},
            private_key=my_private_key,
            public_key=my_public_key
        )

        # Serialize to JSON
        json_str = bundle.to_json()

        # Verify a bundle
        is_valid = bundle.verify(public_key=my_public_key)
    """

    proofbundle_version: str
    proof_id: str
    type: str
    payload: Payload
    signer: Signer
    timestamp: str
    signature: Signature
    anchors: List[Anchor] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    envelope: Optional[Envelope] = None
    revocation: Optional[Revocation] = None
    attestation: Optional[Attestation] = None

    # -------------------------------------------------------------------------
    # Factory Methods
    # -------------------------------------------------------------------------

    @classmethod
    def decision(
        cls,
        content: Any,
        private_key: bytes,
        public_key: bytes,
        key_version: int = 1,
        metadata: Optional[Dict[str, Any]] = None
    ) -> 'ProofBundle':
        """Create a decision ProofBundle."""
        return cls._create(
            bundle_type="decision",
            content=content,
            private_key=private_key,
            public_key=public_key,
            key_version=key_version,
            metadata=metadata
        )

    @classmethod
    def document(
        cls,
        content: Any,
        private_key: bytes,
        public_key: bytes,
        key_version: int = 1,
        content_type: str = "application/json",
        metadata: Optional[Dict[str, Any]] = None
    ) -> 'ProofBundle':
        """Create a document ProofBundle."""
        return cls._create(
            bundle_type="document",
            content=content,
            private_key=private_key,
            public_key=public_key,
            key_version=key_version,
            content_type=content_type,
            metadata=metadata
        )

    @classmethod
    def envelope_message(
        cls,
        content: Any,
        envelope: Envelope,
        private_key: bytes,
        public_key: bytes,
        key_version: int = 1,
        metadata: Optional[Dict[str, Any]] = None
    ) -> 'ProofBundle':
        """Create an envelope ProofBundle (AI-to-AI message)."""
        return cls._create(
            bundle_type="envelope",
            content=content,
            private_key=private_key,
            public_key=public_key,
            key_version=key_version,
            envelope=envelope,
            metadata=metadata
        )

    @classmethod
    def key_revocation(
        cls,
        revocation: Revocation,
        private_key: bytes,
        public_key: bytes,
        key_version: int = 1,
        metadata: Optional[Dict[str, Any]] = None
    ) -> 'ProofBundle':
        """Create a key revocation ProofBundle."""
        # Payload is the revocation itself
        content = revocation.to_dict()

        return cls._create(
            bundle_type="revocation",
            content=content,
            private_key=private_key,
            public_key=public_key,
            key_version=key_version,
            revocation=revocation,
            metadata=metadata
        )

    @classmethod
    def attest(
        cls,
        attestation: Attestation,
        private_key: bytes,
        public_key: bytes,
        key_version: int = 1,
        metadata: Optional[Dict[str, Any]] = None
    ) -> 'ProofBundle':
        """Create an attestation ProofBundle (privacy-preserving claim)."""
        content = attestation.to_dict()

        return cls._create(
            bundle_type="attestation",
            content=content,
            private_key=private_key,
            public_key=public_key,
            key_version=key_version,
            attestation=attestation,
            commitment_only=True,  # Attestations are typically commitment-only
            metadata=metadata
        )

    @classmethod
    def _create(
        cls,
        bundle_type: str,
        content: Any,
        private_key: bytes,
        public_key: bytes,
        key_version: int = 1,
        content_type: str = "application/json",
        commitment_only: bool = False,
        envelope: Optional[Envelope] = None,
        revocation: Optional[Revocation] = None,
        attestation: Optional[Attestation] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> 'ProofBundle':
        """Internal factory method."""

        # Create payload
        if commitment_only:
            payload = Payload.commitment(content, content_type)
        else:
            payload = Payload.from_content(content, content_type)

        # Create signer
        signer = Signer.from_public_key(
            public_key=public_key,
            key_version=key_version,
            algorithm="dilithium3"
        )

        # Create timestamp
        timestamp = iso_timestamp()

        # Build signing payload (everything except signature, proof_id, anchor proofs)
        signing_payload = {
            "proofbundle_version": "0.1",
            "type": bundle_type,
            "payload": payload.to_dict(),
            "signer": signer.to_dict(),
            "timestamp": timestamp,
            "anchors": [],
            "metadata": metadata or {}
        }

        if envelope:
            signing_payload["envelope"] = envelope.to_dict()
        if revocation:
            signing_payload["revocation"] = revocation.to_dict()
        if attestation:
            signing_payload["attestation"] = attestation.to_dict()

        # Compute signing_root = SHA3-256(JCS(signing_payload))
        canonical_bytes = jcs_canonicalize(signing_payload)
        signing_root_bytes = sha3_256(canonical_bytes)
        signing_root = format_hash(signing_root_bytes)

        # Compute proof_id = SHA3-256(signing_root)
        proof_id_bytes = sha3_256(signing_root_bytes)
        proof_id = format_hash(proof_id_bytes)

        # Sign with Dilithium3
        signature_bytes = ml_dsa_sign(private_key, signing_root_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode('ascii')

        signature = Signature(
            algorithm="dilithium3",
            signing_root=signing_root,
            value=signature_b64,
            signed_at=timestamp
        )

        return cls(
            proofbundle_version="0.1",
            proof_id=proof_id,
            type=bundle_type,
            payload=payload,
            signer=signer,
            timestamp=timestamp,
            signature=signature,
            anchors=[],
            metadata=metadata or {},
            envelope=envelope,
            revocation=revocation,
            attestation=attestation
        )

    # -------------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "proofbundle_version": self.proofbundle_version,
            "proof_id": self.proof_id,
            "type": self.type,
            "payload": self.payload.to_dict(),
            "signer": self.signer.to_dict(),
            "timestamp": self.timestamp,
            "signature": self.signature.to_dict(),
            "anchors": [a.to_dict() for a in self.anchors],
            "metadata": self.metadata
        }

        if self.envelope:
            result["envelope"] = self.envelope.to_dict()
        if self.revocation:
            result["revocation"] = self.revocation.to_dict()
        if self.attestation:
            result["attestation"] = self.attestation.to_dict()

        return result

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_json_canonical(self) -> bytes:
        """Convert to canonical JSON bytes (for hashing)."""
        return jcs_canonicalize(self.to_dict())

    def to_file(self, path: Union[str, Path]) -> None:
        """
        Save bundle to file.

        Args:
            path: File path to write to

        Security:
            - Writes atomically (temp file + rename)
            - Creates parent directories if needed
        """
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: write to temp, then rename
        temp_path = p.with_suffix('.tmp')
        try:
            temp_path.write_text(self.to_json(), encoding='utf-8')
            temp_path.rename(p)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProofBundle':
        """Create from dictionary."""
        return cls(
            proofbundle_version=data["proofbundle_version"],
            proof_id=data["proof_id"],
            type=data["type"],
            payload=Payload.from_dict(data["payload"]),
            signer=Signer.from_dict(data["signer"]),
            timestamp=data["timestamp"],
            signature=Signature.from_dict(data["signature"]),
            anchors=[Anchor.from_dict(a) for a in data.get("anchors", [])],
            metadata=data.get("metadata", {}),
            envelope=Envelope.from_dict(data["envelope"]) if "envelope" in data else None,
            revocation=Revocation.from_dict(data["revocation"]) if "revocation" in data else None,
            attestation=Attestation.from_dict(data["attestation"]) if "attestation" in data else None
        )

    @classmethod
    def from_json(cls, json_str: str) -> 'ProofBundle':
        """
        Create from JSON string.

        Security: Size limit enforced to prevent memory exhaustion DoS.

        Raises:
            ValueError: If JSON exceeds MAX_JSON_SIZE
        """
        # Security: Check BYTE size (not char count) - Unicode could bypass len()
        byte_size = len(json_str.encode('utf-8'))
        if byte_size > MAX_JSON_SIZE:
            raise ValueError(
                f"JSON size {byte_size} bytes exceeds maximum "
                f"allowed {MAX_JSON_SIZE} bytes"
            )

        data = json.loads(json_str)
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> 'ProofBundle':
        """
        Load from file.

        Security:
        - File size limit enforced to prevent memory exhaustion DoS
        - Symlinks rejected to prevent path traversal
        - Only regular files allowed (no /proc, device files, etc.)

        Raises:
            ValueError: If file exceeds MAX_FILE_SIZE or security check fails
        """
        path = Path(path)

        # Security: Reject symlinks (could point anywhere)
        if path.is_symlink():
            raise ValueError(f"Symlinks not allowed: {path}")

        # Check file exists (before is_file check for clearer error)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Security: Only allow regular files (not /proc, devices, etc.)
        if not path.is_file():
            raise ValueError(f"Not a regular file: {path}")

        # Security: Check file size BEFORE reading
        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise ValueError(
                f"File size {file_size} bytes exceeds maximum "
                f"allowed {MAX_FILE_SIZE} bytes"
            )

        with path.open('r', encoding='utf-8') as f:
            return cls.from_json(f.read())

    def save(self, path: Union[str, Path]) -> None:
        """Save to file."""
        path = Path(path)
        with path.open('w', encoding='utf-8') as f:
            f.write(self.to_json())

    # -------------------------------------------------------------------------
    # Verification
    # -------------------------------------------------------------------------

    def verify(self, public_key: bytes) -> bool:
        """
        Verify the ProofBundle signature.

        Args:
            public_key: The public key bytes to verify against

        Returns:
            True if signature is valid, False otherwise

        Note:
            Security: Only catches expected verification failures.
            Programming errors will raise exceptions.
        """
        try:
            return self._verify_internal(public_key)
        except (ValueError, TypeError, KeyError, binascii.Error, DilithiumError):
            # Expected failures: bad encoding, missing fields, invalid format,
            # wrong key size, invalid Dilithium key/signature
            return False
        # Note: Other exceptions (programming errors) propagate up

    def _verify_internal(self, public_key: bytes) -> bool:
        """Internal verification with exception propagation."""

        # 1. Reconstruct signing_payload
        signing_payload = self._extract_signing_payload()

        # 2. Compute signing_root
        canonical_bytes = jcs_canonicalize(signing_payload)
        computed_root = sha3_256(canonical_bytes)
        computed_root_str = format_hash(computed_root)

        # 3. Verify signing_root matches
        if computed_root_str != self.signature.signing_root:
            return False

        # 4. Verify proof_id
        computed_proof_id = format_hash(sha3_256(computed_root))
        if computed_proof_id != self.proof_id:
            return False

        # 5. Verify Dilithium signature
        signature_bytes = base64.b64decode(self.signature.value)
        if not ml_dsa_verify(public_key, computed_root, signature_bytes):
            return False

        # 6. Verify payload hash (if content provided)
        if not self.payload.verify_content():
            return False

        # 7. Verify signer public_key_hash matches
        computed_pk_hash = compute_public_key_hash(public_key)
        if computed_pk_hash != self.signer.public_key_hash:
            return False

        return True

    def _extract_signing_payload(self) -> Dict[str, Any]:
        """Extract the signing_payload (excludes signature, proof_id, anchor proofs)."""

        # Start with minimal anchors (without proof and tx_id)
        anchors = []
        for a in self.anchors:
            anchors.append({
                "chain": a.chain,
                "method": a.method,
                "status": a.status,
                "submitted_at": a.submitted_at
                # NOTE: proof, tx_id, confirmed_at, block_height excluded
            })

        signing_payload = {
            "proofbundle_version": self.proofbundle_version,
            "type": self.type,
            "payload": self.payload.to_dict(),
            "signer": self.signer.to_dict(),
            "timestamp": self.timestamp,
            "anchors": anchors,
            "metadata": self.metadata
        }

        if self.envelope:
            signing_payload["envelope"] = self.envelope.to_dict()
        if self.revocation:
            signing_payload["revocation"] = self.revocation.to_dict()
        if self.attestation:
            signing_payload["attestation"] = self.attestation.to_dict()

        return signing_payload

    # -------------------------------------------------------------------------
    # Anchoring
    # -------------------------------------------------------------------------

    def add_anchor(self, anchor: Anchor) -> None:
        """
        Add a blockchain anchor.

        Security: Anchor count limited to prevent DoS via unlimited anchors.

        Raises:
            ValueError: If MAX_ANCHORS limit exceeded
        """
        if len(self.anchors) >= MAX_ANCHORS:
            raise ValueError(
                f"Maximum anchor limit ({MAX_ANCHORS}) reached. "
                f"Cannot add more anchors."
            )
        self.anchors.append(anchor)

    def confirm_anchor(
        self,
        chain: str,
        tx_id: str,
        block_height: int,
        proof: Optional[str] = None
    ) -> bool:
        """
        Confirm an anchor with transaction details.

        Returns True if anchor was found and updated.
        """
        for anchor in self.anchors:
            if anchor.chain == chain and anchor.status == "pending":
                anchor.status = "confirmed"
                anchor.confirmed_at = iso_timestamp()
                anchor.tx_id = tx_id
                anchor.block_height = block_height
                if proof:
                    anchor.proof = proof
                return True
        return False

    # -------------------------------------------------------------------------
    # Schema Validation
    # -------------------------------------------------------------------------

    def validate_schema(self, require_schema: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Validate against JSON Schema.

        Args:
            require_schema: If True (default), fail when jsonschema unavailable.
                           Security: Fail-closed approach prevents invalid data.

        Returns:
            (is_valid, error_message)

        Note:
            Security: With require_schema=True (default), validation fails if
            jsonschema library is not installed. This prevents silently
            accepting invalid data.
        """
        if not HAS_JSONSCHEMA:
            if require_schema:
                return False, "jsonschema library not installed (required for validation)"
            return True, None  # Only skip if explicitly allowed

        schema_path = Path(__file__).parent.parent / "schemas" / "proofbundle.v0.1.schema.json"
        if not schema_path.exists():
            if require_schema:
                return False, f"Schema file not found: {schema_path}"
            return True, None  # Only skip if explicitly allowed

        with schema_path.open('r') as f:
            schema = json.load(f)

        try:
            jsonschema.validate(self.to_dict(), schema)
            return True, None
        except jsonschema.ValidationError as e:
            return False, str(e.message)


# =============================================================================
# STANDALONE FUNCTIONS
# =============================================================================

def create_proofbundle(
    content: Any,
    bundle_type: str,
    private_key: bytes,
    public_key: bytes,
    **kwargs
) -> ProofBundle:
    """
    Create a ProofBundle.

    Args:
        content: The content to include in the proof
        bundle_type: One of "decision", "document", "envelope", "attestation", "revocation"
        private_key: Dilithium3 private key bytes
        public_key: Dilithium3 public key bytes
        **kwargs: Additional arguments (key_version, metadata, envelope, etc.)

    Returns:
        ProofBundle instance
    """
    if bundle_type == "decision":
        return ProofBundle.decision(content, private_key, public_key, **kwargs)
    elif bundle_type == "document":
        return ProofBundle.document(content, private_key, public_key, **kwargs)
    elif bundle_type == "envelope":
        return ProofBundle.envelope_message(content, kwargs.pop('envelope'), private_key, public_key, **kwargs)
    else:
        raise ValueError(f"Unknown bundle_type: {bundle_type}")


def verify_proofbundle(bundle: ProofBundle, public_key: bytes) -> bool:
    """
    Verify a ProofBundle signature.

    Args:
        bundle: The ProofBundle to verify
        public_key: The public key bytes

    Returns:
        True if valid, False otherwise
    """
    return bundle.verify(public_key)


def verify_proofbundle_standalone(
    bundle_json: str,
    public_key: bytes,
    require_schema: bool = False
) -> Tuple[bool, Optional[str]]:
    """
    Verify a ProofBundle from JSON string (standalone verification).

    This is the "2-minute verification" entry point.

    Args:
        bundle_json: JSON string of the ProofBundle
        public_key: The public key bytes
        require_schema: If True, require jsonschema library for validation.
                       Default False for easier adoption (signature is verified).

    Returns:
        (is_valid, error_message)

    Security notes:
        - JSON size limit enforced (MAX_JSON_SIZE)
        - Signature ALWAYS verified with post-quantum Dilithium3
        - Schema validation optional but recommended
    """
    try:
        bundle = ProofBundle.from_json(bundle_json)

        # Schema validation (optional for standalone, but recommended)
        schema_valid, schema_error = bundle.validate_schema(require_schema=require_schema)
        if not schema_valid:
            return False, f"Schema validation failed: {schema_error}"

        # Signature verification (ALWAYS required)
        if not bundle.verify(public_key):
            return False, "Signature verification failed"

        return True, None

    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"
    except ValueError as e:
        return False, f"Validation error: {e}"
    except (TypeError, KeyError) as e:
        return False, f"Malformed bundle: {e}"
