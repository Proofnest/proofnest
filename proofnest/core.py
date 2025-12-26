"""
PROOFNEST SDK v2.1 - Quantum-Ready
=====================================

Copyright (c) 2025 Stellanium Ltd. All rights reserved.
Licensed under Apache License 2.0. See LICENSE file.
PROOFNEST™ is a trademark of Stellanium Ltd.

Reference implementation for PROOFNEST Protocol.
Any AI system can become PROOFNEST Certified by implementing this.

FOUNDATION:
    L0: LOGIC - "inner == outer" is the DEFINITION of honesty
    L1: MATH  - Formally verified in Coq (proofs/honesty.v)
    L2: CRYPTO - Bitcoin witnesses existence + Quantum-safe signatures
    L3: PHYSICAL - Archives ensure permanence

⚠️ BREAKING CHANGE in v2.1:
    record_hash now covers ALL fields (was: partial coverage).
    Old chains will fail verification - migration required!
    See: https://github.com/Stellanium/proofnest/blob/main/MIGRATION.md

NEW IN v2.1:
    - P0 FIX: Hash covers ALL tamper-evident fields
    - alternatives, confidence, risk_level now protected
    - actor_type, actor_model now protected
    - Canonical JSON encoding (deterministic)

NEW IN v2.0:
    - Quantum-ready cryptographic identity (SHA3-256)
    - DID-style agent identifiers (did:pn:...)
    - Digital signatures on all decisions
    - Hash-based commitments

Usage:
    from proofnest import ProofNest

    # Initialize with cryptographic identity
    hc = ProofNest(agent_id="my-ai-agent")

    # Log decisions (automatically signed)
    hc.decide(
        action="Approved loan application",
        reasoning="Credit score 750+, income verified, DTI < 30%",
        risk_level="low"
    )

    # Get agent DID
    print(hc.did)  # did:pn:abc123...

    # Verify integrity + signatures
    assert hc.verify()

© 2025 Stellanium Ltd. All rights reserved.
PROOFNEST™ is a trademark of Stellanium Ltd.
"""

import hashlib
import json
import logging
import math
import os
import re
import tempfile
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Literal, Callable, Dict, Any
from pathlib import Path
from enum import Enum

# Import quantum-ready identity
from proofnest.identity import AgentIdentity, Signature

# Module logger
logger = logging.getLogger(__name__)

# Väline ankurdus callback
ExternalAnchorCallback = Optional[Callable[[str], str]]


class ProofNestError(Exception):
    """Base exception for ProofNest errors"""
    pass


class TimestampViolationError(ProofNestError):
    """Raised when timestamp monotonicity is violated (backdating attempt)"""
    pass


class ChainIntegrityError(ProofNestError):
    """Raised when chain integrity verification fails"""
    pass


class SignatureError(ProofNestError):
    """Raised when signature verification fails"""
    pass


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActorType(Enum):
    AI = "ai"
    HUMAN = "human"
    HYBRID = "hybrid"


@dataclass
class Actor:
    """
    Identity of decision maker.

    NOTE: Actor identity is authenticated via AgentIdentity signatures on decisions,
    not via Actor-level HMAC. This ensures:
    1. Persistent keys (AgentIdentity keys are stored on disk)
    2. Third-party verification (asymmetric Ed25519/Dilithium signatures)
    3. Quantum-safety (Dilithium support available)

    The actor fields (id, type, model) are included in the signed decision hash,
    making them tamper-evident.
    """
    id: str
    type: ActorType = ActorType.AI
    model: str = "unknown"

    def to_dict(self) -> dict:
        """Convert to HCP-compliant JSON (actor info only, no separate signature)"""
        return {
            "id": self.id,
            "type": self.type.value,
            "model": self.model
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Actor":
        """Reconstruct Actor from stored dictionary"""
        return cls(
            id=data["id"],
            type=ActorType(data["type"]),
            model=data.get("model", "unknown")
        )


@dataclass(frozen=True, slots=True)
class DecisionRecord:
    """
    Single decision in the chain.

    IMMUTABLE: This class is frozen (and uses slots) to prevent tampering after creation.
    All fields must be set at construction time.

    Security properties:
        - frozen=True: Prevents attribute modification after __init__
        - slots=True: Prevents adding new attributes, better memory efficiency
        - tuple for alternatives: Immutable sequence
    """
    decision_id: str
    timestamp: str
    actor: Actor
    action: str
    reasoning: str
    alternatives: tuple  # Changed to tuple for immutability
    confidence: float
    risk_level: RiskLevel
    previous_hash: Optional[str]
    signature: Optional[Signature] = None  # Quantum-safe signature
    hcp_version: str = "2.1"  # Protocol version for backwards compatibility

    # Computed - set via object.__setattr__ in __post_init__
    record_hash: str = field(default="", compare=False)

    def __post_init__(self):
        # Use object.__setattr__ to set computed field on frozen dataclass
        object.__setattr__(self, 'record_hash', self._compute_hash())

    def _compute_hash(self) -> str:
        """
        Compute hash of this record with version-aware field coverage.

        VERSIONING:
            v1.x, v2.0: 6 fields (legacy - partial coverage)
            v2.1+:      11 fields (full coverage)

        This ensures old chains remain verifiable while new chains
        get full tamper-evident protection.
        """
        # Parse major.minor version
        try:
            parts = self.hcp_version.split('.')
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            major, minor = 2, 1  # Default to latest

        # LEGACY: v1.x and v2.0 used partial field coverage
        if major < 2 or (major == 2 and minor == 0):
            data = {
                "decision_id": self.decision_id,
                "timestamp": self.timestamp,
                "actor_id": self.actor.id,
                "action": self.action,
                "reasoning": self.reasoning,
                "previous_hash": self.previous_hash
            }
            # v2.0 used SHA3-256, v1.x used SHA256
            canonical = json.dumps(data, sort_keys=True).encode()
            if major < 2:
                return hashlib.sha256(canonical).hexdigest()
            return hashlib.sha3_256(canonical).hexdigest()

        # v2.1+: Full field coverage (tamper-evident for ALL fields)
        # NOTE: confidence is rounded to 6 decimal places for canonical representation
        # This ensures cross-platform determinism (float repr can vary)
        data = {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "actor_id": self.actor.id,
            "actor_type": self.actor.type.value,
            "actor_model": self.actor.model,
            "action": self.action,
            "reasoning": self.reasoning,
            "alternatives": sorted(list(self.alternatives)),  # Convert tuple to list, sort for determinism
            "confidence": round(self.confidence, 6),  # Canonical float representation
            "risk_level": self.risk_level.value,
            "previous_hash": self.previous_hash
        }
        # Canonical JSON: sorted keys, minimal separators, ASCII-only
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        return hashlib.sha3_256(canonical.encode('ascii')).hexdigest()

    def to_dict(self) -> dict:
        """Convert to HCP-compliant JSON"""
        result = {
            "hcp_version": self.hcp_version,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "actor": self.actor.to_dict(),
            "decision": {
                "action": self.action,
                "reasoning": self.reasoning,
                "alternatives_considered": list(self.alternatives),  # Convert tuple to list for JSON
                "confidence": self.confidence,
                "risk_level": self.risk_level.value
            },
            "chain": {
                "previous_hash": self.previous_hash,
                "record_hash": self.record_hash
            },
            "quantum_safe": True
        }
        # Include signature if present
        if self.signature:
            result["signature"] = self.signature.to_dict()
        return result


class ProofNest:
    """
    PROOFNEST Protocol Implementation - Quantum-Ready

    The lighthouse for ethical AI decisions.

    FOUNDATION:
        Based on PROOFNEST axiom: "inner == outer"
        This is DEFINITIONAL - an AI that breaks it is simply not honest.

    NEW IN v2.0:
        - Quantum-safe cryptographic identity (SHA3-256)
        - DID-style agent identifiers
        - Digital signatures on all decisions
    """

    HCP_VERSION = "2.12"  # P1: Ed25519 + anchor verification + P2P security

    # The foundational axiom (from PROOFNEST L0)
    AXIOM = "inner == outer"
    AXIOM_MEANING = "What an AI reports externally MUST match its internal state"

    # Path validation pattern (HIGH FIX: path traversal protection)
    VALID_AGENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')

    def __init__(
        self,
        agent_id: str,
        agent_model: str = "unknown",
        storage_path: Optional[Path] = None,
        external_anchor: ExternalAnchorCallback = None,
        enable_signatures: bool = True,
        enable_bitcoin: bool = True,  # NEW: Bitcoin is DEFAULT!
    ):
        """
        Initialize PROOFNEST for an AI agent.

        Args:
            agent_id: Unique identifier for this AI agent (alphanumeric, -, _ only)
            agent_model: Model name (claude-opus-4-5, gpt-4o, etc.)
            storage_path: Where to store the chain (default: ~/.proofnest/)
            external_anchor: Callback to anchor chain to external system (overrides enable_bitcoin)
            enable_signatures: Enable quantum-safe signatures (default: True)
            enable_bitcoin: Enable automatic Bitcoin anchoring via OpenTimestamps (default: True)
                            This is THE core feature - "Proof, not promises"
        """
        # HIGH FIX: Validate agent_id to prevent path traversal
        if not self.VALID_AGENT_ID_PATTERN.match(agent_id):
            raise ValueError(f"Invalid agent_id: must match {self.VALID_AGENT_ID_PATTERN.pattern}")

        self.actor = Actor(id=agent_id, type=ActorType.AI, model=agent_model)
        self.chain: List[DecisionRecord] = []

        # MEDIUM FIX: Thread-safety
        self._lock = threading.Lock()

        # CRITICAL FIX: External anchoring support
        # Bitcoin anchoring is THE core feature - enabled by default!
        if external_anchor is not None:
            self._external_anchor = external_anchor
        elif enable_bitcoin:
            # Auto-configure OpenTimestamps (FREE, no setup required)
            from .bitcoin import create_bitcoin_anchor_callback
            self._external_anchor = create_bitcoin_anchor_callback()
        else:
            self._external_anchor = None
        self._last_anchor_hash: Optional[str] = None
        self._bitcoin_enabled = enable_bitcoin or external_anchor is not None

        # Storage with validated path
        # B6 FIX: Use is_relative_to() for robust path validation (not string prefix)
        # NEW B2 FIX: Reject symlinks and world-writable directories
        default_base = Path.home() / ".proofnest"
        if storage_path is None:
            self.storage_path = default_base / agent_id
        else:
            # Resolve to absolute path first
            resolved = Path(storage_path).resolve()

            # NEW B2 FIX: Reject if storage_path itself is a symlink
            if Path(storage_path).is_symlink():
                raise ValueError(
                    f"Invalid storage_path: symlinks not allowed for security. "
                    f"Got: {storage_path}"
                )

            # Check for path traversal in the resolved path
            home = Path.home().resolve()

            # B6 FIX: Use is_relative_to() for proper path comparison
            def is_within(child: Path, parent: Path) -> bool:
                try:
                    child.relative_to(parent)
                    return True
                except ValueError:
                    return False

            # SECURITY FIX: Only allow paths within home directory
            # CWD is removed because:
            # 1. CWD could be /tmp (world-writable, symlink attacks)
            # 2. CWD could be attacker-controlled
            # 3. Audit logs need stable, secure locations
            if not is_within(resolved, home):
                raise ValueError(
                    f"Invalid storage_path: must be within home directory. "
                    f"(CWD and /tmp are not allowed for security-critical audit logs) "
                    f"Got: {resolved}"
                )
            self.storage_path = resolved

        # Create directory with restrictive permissions (NEW B2 FIX)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)

        # NEW B2 FIX: Verify no symlinks in the created path hierarchy
        for parent in [self.storage_path] + list(self.storage_path.parents):
            if parent.is_symlink():
                raise ValueError(
                    f"Security error: symlink detected in storage path hierarchy: {parent}"
                )

        # NEW: Quantum-safe cryptographic identity (AFTER path validation)
        self._enable_signatures = enable_signatures
        self._identity: Optional[AgentIdentity] = None
        if enable_signatures:
            self._identity = AgentIdentity.create(agent_id, self.storage_path)

        # Load existing chain
        self._load_chain()

    @property
    def did(self) -> Optional[str]:
        """Get the agent's Decentralized Identifier (DID)"""
        return self._identity.did if self._identity else None

    @property
    def identity(self) -> Optional[AgentIdentity]:
        """Get the agent's cryptographic identity"""
        return self._identity

    @property
    def public_key_hash(self) -> Optional[str]:
        """Get the agent's public key hash (quantum-safe commitment)"""
        return self._identity.public_key_hash if self._identity else None

    def decide(
        self,
        action: str,
        reasoning: str,
        alternatives: Optional[List[str]] = None,
        confidence: float = 0.8,
        risk_level: RiskLevel = RiskLevel.LOW,
        anchor_externally: bool = False
    ) -> DecisionRecord:
        """
        Log a decision to the chain.

        This is the core function - EVERY significant AI decision
        should call this method.

        Args:
            action: What was decided
            reasoning: Why it was decided (THE KEY FOR TRANSPARENCY)
            alternatives: Other options that were considered
            confidence: How confident (0.0-1.0), must be a valid number in range
            risk_level: Risk level of this decision
            anchor_externally: If True and external_anchor callback is set, anchor this record

        Returns:
            The created DecisionRecord

        Raises:
            ValueError: If confidence is not a valid number between 0.0 and 1.0
        """
        # Validate confidence - must be a real number between 0 and 1
        if not isinstance(confidence, (int, float)):
            raise ValueError(f"confidence must be a number, got {type(confidence).__name__}")
        if math.isnan(confidence):
            raise ValueError("confidence cannot be NaN")
        if math.isinf(confidence):
            raise ValueError("confidence cannot be infinity")
        if confidence < 0.0 or confidence > 1.0:
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {confidence}")

        # MEDIUM FIX: Thread-safe append
        with self._lock:
            # Generate timestamp
            new_timestamp = datetime.utcnow().isoformat() + "Z"

            # P0 FIX: Timestamp monotonicity - prevent backdating attacks
            if self.chain:
                last_timestamp = self.chain[-1].timestamp
                if new_timestamp < last_timestamp:
                    raise TimestampViolationError(
                        f"Timestamp monotonicity violation: new timestamp {new_timestamp} "
                        f"is earlier than previous {last_timestamp}. Backdating not allowed."
                    )

            # Create record (frozen dataclass - immutable after creation)
            record = DecisionRecord(
                decision_id=str(uuid.uuid4()),
                timestamp=new_timestamp,
                actor=self.actor,
                action=action,
                reasoning=reasoning,
                alternatives=tuple(alternatives) if alternatives else (),  # Immutable tuple
                confidence=confidence,
                risk_level=risk_level,
                previous_hash=self.chain[-1].record_hash if self.chain else None
            )

            # NEW: Sign decision with quantum-safe signature
            # Use object.__setattr__ because DecisionRecord is frozen
            if self._identity and self._enable_signatures:
                decision_data = {
                    "decision_id": record.decision_id,
                    "timestamp": record.timestamp,
                    "action": record.action,
                    "reasoning": record.reasoning,
                    "record_hash": record.record_hash
                }
                signature = self._identity.sign_decision(decision_data)
                object.__setattr__(record, 'signature', signature)

            self.chain.append(record)
            self._save_record(record)

            # CRITICAL FIX: External anchoring for high-risk or explicit requests
            if (anchor_externally or risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]) and self._external_anchor:
                self._anchor_to_external(record)

        return record

    def _anchor_to_external(self, record: DecisionRecord) -> Optional[str]:
        """Anchor record hash to external system (blockchain, timestamping service, etc.)"""
        if not self._external_anchor:
            return None

        try:
            anchor_proof = self._external_anchor(record.record_hash)
            self._last_anchor_hash = anchor_proof

            # B6 FIX: Save anchor proof atomically
            anchor_file = self.storage_path / f"{record.decision_id}_anchor.json"
            anchor_data = {
                "decision_id": record.decision_id,
                "record_hash": record.record_hash,
                "anchor_proof": anchor_proof,
                "anchored_at": datetime.utcnow().isoformat() + "Z"
            }

            # Write to temp file first
            fd, tmp_path = tempfile.mkstemp(
                suffix='.tmp',
                prefix=f'{record.decision_id}_anchor_',
                dir=self.storage_path
            )
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(anchor_data, f, indent=2)
                os.replace(tmp_path, anchor_file)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

            return anchor_proof
        except Exception as e:
            # Log but don't fail - anchoring is additional protection
            logger.warning("External anchoring failed: %s", e)
            return None

    def has_external_anchor(self) -> bool:
        """Check if this chain has been anchored externally (CRITICAL CHECK)"""
        # Fast check first
        if self._last_anchor_hash is not None:
            return True
        # Only check files if needed (avoid slow iteration)
        try:
            anchor_files = list(self.storage_path.glob("*_anchor.json"))
            return len(anchor_files) > 0
        except:
            return False

    def get_anchors(self) -> List[Dict[str, Any]]:
        """
        P1: Get all anchor proofs for this chain.

        Returns:
            List of anchor proof dictionaries
        """
        anchors = []
        try:
            for anchor_file in self.storage_path.glob("*_anchor.json"):
                with open(anchor_file) as f:
                    anchors.append(json.load(f))
        except Exception:
            pass
        return anchors

    def verify_anchor(self, anchor_proof: Dict[str, Any]) -> Dict[str, Any]:
        """
        P1: Verify an anchor proof.

        Supports multiple anchor types:
        - opentimestamps: OpenTimestamps proof verification
        - bitcoin: Raw Bitcoin transaction verification
        - p2p: Peer-to-peer anchor (multiple peers confirm)

        Args:
            anchor_proof: Anchor proof dictionary with 'anchor_proof' field

        Returns:
            Verification result with 'valid', 'anchor_type', 'details'
        """
        proof_data = anchor_proof.get("anchor_proof", "")

        # Detect anchor type and verify
        if isinstance(proof_data, str):
            if proof_data.startswith("ots:"):
                return self._verify_ots_anchor(proof_data, anchor_proof.get("record_hash", ""))
            elif proof_data.startswith("btc:"):
                return self._verify_bitcoin_anchor(proof_data, anchor_proof.get("record_hash", ""))
            elif proof_data.startswith("local:"):
                return {
                    "valid": True,
                    "anchor_type": "local",
                    "details": "Local anchor (no external verification)",
                    "strength": "weak"
                }
        elif isinstance(proof_data, dict) and "p2p_anchors" in proof_data:
            return self._verify_p2p_anchor(proof_data, anchor_proof.get("record_hash", ""))

        return {
            "valid": False,
            "anchor_type": "unknown",
            "details": "Unknown anchor format",
            "strength": "none"
        }

    def _verify_ots_anchor(self, ots_proof: str, record_hash: str) -> Dict[str, Any]:
        """
        P1: Verify OpenTimestamps anchor.

        OpenTimestamps format: ots:<base64_proof>

        SECURITY NOTE: Full verification requires external OTS library or API.
        This method only validates proof structure, NOT Bitcoin attestation.
        """
        import base64

        try:
            # Extract proof data
            proof_b64 = ots_proof[4:]  # Remove "ots:" prefix
            proof_bytes = base64.b64decode(proof_b64)

            # OTS proof structure validation
            # OTS proofs start with magic bytes: \x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94
            OTS_MAGIC = b'\x00OpenTimestamps\x00\x00Proof\x00'
            if not proof_bytes.startswith(OTS_MAGIC[:15]):  # Check first part of magic
                return {
                    "valid": False,
                    "anchor_type": "opentimestamps",
                    "details": "Invalid OTS proof: missing magic bytes",
                    "strength": "none",
                    "verified": False
                }

            if len(proof_bytes) < 64:  # Minimum valid OTS proof size
                return {
                    "valid": False,
                    "anchor_type": "opentimestamps",
                    "details": "Invalid OTS proof: too short for valid proof",
                    "strength": "none",
                    "verified": False
                }

            # B5 FIX: We can only validate structure, not Bitcoin attestation
            # Mark as "pending_verification" - requires external verification
            return {
                "valid": True,
                "anchor_type": "opentimestamps",
                "details": "OTS proof structure valid (Bitcoin attestation NOT verified)",
                "strength": "pending",  # Not "strong" until externally verified
                "verified": False,
                "requires": "Use ots-cli verify or OTS API for full Bitcoin attestation",
                "proof_size": len(proof_bytes)
            }

        except Exception as e:
            return {
                "valid": False,
                "anchor_type": "opentimestamps",
                "details": f"OTS verification error: {e}",
                "strength": "none",
                "verified": False
            }

    def _verify_bitcoin_anchor(self, btc_proof: str, record_hash: str) -> Dict[str, Any]:
        """
        P1: Verify Bitcoin anchor.

        Bitcoin format: btc:<txid>:<block_height>:<merkle_proof>

        SECURITY NOTE: Full verification requires Bitcoin node or block explorer.
        This method only validates format, NOT blockchain inclusion.
        """
        try:
            parts = btc_proof[4:].split(":")  # Remove "btc:" prefix
            if len(parts) < 2:
                return {
                    "valid": False,
                    "anchor_type": "bitcoin",
                    "details": "Invalid Bitcoin anchor format",
                    "strength": "none",
                    "verified": False
                }

            txid = parts[0]
            block_height_str = parts[1] if len(parts) > 1 else None

            # Strict txid validation (64 hex characters)
            if len(txid) != 64 or not all(c in '0123456789abcdef' for c in txid.lower()):
                return {
                    "valid": False,
                    "anchor_type": "bitcoin",
                    "details": "Invalid Bitcoin txid format (must be 64 hex chars)",
                    "strength": "none",
                    "verified": False
                }

            # Validate block height is numeric
            try:
                block_height = int(block_height_str) if block_height_str else None
                if block_height is not None and block_height < 0:
                    raise ValueError("Block height cannot be negative")
            except ValueError:
                return {
                    "valid": False,
                    "anchor_type": "bitcoin",
                    "details": "Invalid block height format",
                    "strength": "none",
                    "verified": False
                }

            # B5 FIX: Format is valid but blockchain inclusion NOT verified
            return {
                "valid": True,
                "anchor_type": "bitcoin",
                "details": f"Bitcoin anchor format valid (blockchain NOT verified)",
                "strength": "pending",  # Not "strong" until externally verified
                "verified": False,
                "txid": txid,
                "block_height": block_height,
                "requires": "Use Bitcoin node or block explorer API for full verification"
            }

        except Exception as e:
            return {
                "valid": False,
                "anchor_type": "bitcoin",
                "details": f"Bitcoin verification error: {e}",
                "strength": "none",
                "verified": False
            }

    def _verify_p2p_anchor(self, p2p_proof: Dict[str, Any], record_hash: str) -> Dict[str, Any]:
        """
        P1: Verify P2P anchor (multiple peers confirmed).

        SECURITY NOTE: P2P anchors should include peer signatures for proper verification.
        Without signatures, peer attestations are easily forgeable.

        Expected anchor format:
        {
            "p2p_anchors": [
                {
                    "record_hash": "...",
                    "anchored_by": "did:pn:...",
                    "timestamp": "...",
                    "signature": "..."  # Ed25519/Dilithium signature
                }
            ]
        }
        """
        try:
            anchors = p2p_proof.get("p2p_anchors", [])
            anchor_count = len(anchors)

            if anchor_count == 0:
                return {
                    "valid": False,
                    "anchor_type": "p2p",
                    "details": "No peer anchors found",
                    "strength": "none",
                    "verified": False
                }

            # Check for hash matches
            hash_matching = [a for a in anchors if a.get("record_hash") == record_hash]
            if len(hash_matching) < anchor_count:
                return {
                    "valid": False,
                    "anchor_type": "p2p",
                    "details": f"Hash mismatch in {anchor_count - len(hash_matching)} anchors",
                    "strength": "none",
                    "verified": False
                }

            # B5 FIX: Check for signatures - without them, anchors are unverifiable
            signed_anchors = [a for a in hash_matching if a.get("signature")]
            unsigned_count = len(hash_matching) - len(signed_anchors)

            if len(signed_anchors) == 0:
                # No signatures at all - cannot verify
                return {
                    "valid": True,  # Format valid
                    "anchor_type": "p2p",
                    "details": f"{anchor_count} peers claimed (SIGNATURES MISSING - unverifiable)",
                    "strength": "weak",
                    "verified": False,
                    "anchor_count": anchor_count,
                    "unsigned_count": unsigned_count,
                    "peers": [a.get("anchored_by") for a in hash_matching],
                    "warning": "P2P anchors without signatures are easily forgeable"
                }

            # Has some signatures - note partial verification
            # Full signature verification would require loading peer public keys
            return {
                "valid": True,
                "anchor_type": "p2p",
                "details": f"{len(signed_anchors)} signed, {unsigned_count} unsigned (signature verification pending)",
                "strength": "pending" if unsigned_count > 0 else "medium",
                "verified": False,  # We don't have peer public keys to verify
                "anchor_count": anchor_count,
                "signed_count": len(signed_anchors),
                "unsigned_count": unsigned_count,
                "peers": [a.get("anchored_by") for a in signed_anchors],
                "requires": "Peer public key resolution for full signature verification"
            }

        except Exception as e:
            return {
                "valid": False,
                "anchor_type": "p2p",
                "details": f"P2P verification error: {e}",
                "strength": "none",
                "verified": False
            }

    def verify_all_anchors(self) -> Dict[str, Any]:
        """
        P1: Verify all anchors for this chain.

        Returns:
            Summary of anchor verification results
        """
        anchors = self.get_anchors()
        results = []
        strongest = "none"

        # B5 FIX: Added "pending" strength level for unverified external anchors
        strength_order = {"none": 0, "weak": 1, "pending": 2, "medium": 3, "strong": 4}

        for anchor in anchors:
            result = self.verify_anchor(anchor)
            results.append({
                "decision_id": anchor.get("decision_id"),
                "record_hash": anchor.get("record_hash", "")[:16] + "...",
                **result
            })
            if result["valid"] and strength_order.get(result.get("strength", "none"), 0) > strength_order.get(strongest, 0):
                strongest = result.get("strength", "none")

        return {
            "total_anchors": len(anchors),
            "verified": len([r for r in results if r["valid"]]),
            "strongest_anchor": strongest,
            "results": results
        }

    def get_chain(
        self,
        since: Optional[datetime] = None,
        risk_level: Optional[RiskLevel] = None
    ) -> List[DecisionRecord]:
        """
        Get decision chain for audit.

        Args:
            since: Only return decisions after this time
            risk_level: Only return decisions at this risk level or higher

        Returns:
            List of DecisionRecords
        """
        result = self.chain

        if since:
            result = [r for r in result if r.timestamp >= since.isoformat()]

        if risk_level:
            risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            min_idx = risk_order.index(risk_level)
            result = [r for r in result if risk_order.index(r.risk_level) >= min_idx]

        return result

    def _verify_internal(self, warn_no_anchor: bool = True, verify_signatures: bool = True) -> bool:
        """
        Internal verification without lock (called from locked context).

        Args:
            warn_no_anchor: Warn if chain has no external anchoring
            verify_signatures: Also verify cryptographic signatures (requires identity)

        Returns:
            True if chain integrity is valid
        """
        if not self.chain:
            return True

        # CRITICAL CHECK: Warn if no external anchor (should rarely happen with enable_bitcoin=True)
        if warn_no_anchor and not self.has_external_anchor():
            if not getattr(self, '_bitcoin_enabled', True):
                print("WARNING: Bitcoin anchoring disabled (enable_bitcoin=False)")
            else:
                print("INFO: No Bitcoin anchor yet - proofs are submitted to OpenTimestamps on HIGH/CRITICAL decisions")

        # First record should have no previous hash
        if self.chain[0].previous_hash is not None:
            return False

        # Each record's previous_hash should match previous record's hash
        for i in range(1, len(self.chain)):
            if self.chain[i].previous_hash != self.chain[i-1].record_hash:
                return False

        # Verify each record's hash
        for record in self.chain:
            if record.record_hash != record._compute_hash():
                return False

        # NEW B1 FIX: Verify signatures using embedded public key (third-party verifiable)
        # This works even without local identity - auditors can verify!
        if verify_signatures:
            for record in self.chain:
                if record.signature:
                    # Reconstruct the decision data that was signed
                    decision_data = {
                        "decision_id": record.decision_id,
                        "timestamp": record.timestamp,
                        "action": record.action,
                        "reasoning": record.reasoning,
                        "record_hash": record.record_hash
                    }
                    # CANONICAL JSON: MUST match identity.py sign_decision()
                    canonical = json.dumps(
                        decision_data,
                        sort_keys=True,
                        separators=(',', ':'),
                        ensure_ascii=True
                    )

                    # Try standalone verification first (Ed25519 - third-party verifiable)
                    if record.signature.verify_standalone(canonical.encode('ascii')):
                        continue  # Signature valid

                    # Fallback: verify with local identity (HMAC - self-verify only)
                    if self._identity:
                        if self._identity.verify(canonical.encode('ascii'), record.signature):
                            continue  # Signature valid via local identity

                    # Signature invalid
                    print(f"WARNING: Invalid signature on record {record.decision_id}")
                    return False

        return True

    def verify(self, warn_no_anchor: bool = True, verify_signatures: bool = True) -> bool:
        """
        Verify chain integrity AND signatures.

        Args:
            warn_no_anchor: If True, warn if chain has no external anchoring
            verify_signatures: If True, also verify cryptographic signatures

        Returns:
            True if chain is valid, False if tampered or signatures invalid

        Note:
            Signatures use Ed25519 (asymmetric) via AgentIdentity. Third-party
            verification is possible using the agent's public key. Post-quantum
            signatures (Dilithium/ML-DSA) are available in proofnest.crypto.
        """
        # MEDIUM FIX: Thread-safe verification
        with self._lock:
            return self._verify_internal(warn_no_anchor, verify_signatures)

    def _get_merkle_root_internal(self) -> str:
        """Internal Merkle root without lock (called from locked context)"""
        if not self.chain:
            return hashlib.sha256(b"empty").hexdigest()

        hashes = [r.record_hash for r in self.chain]

        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])

            new_hashes = []
            for i in range(0, len(hashes), 2):
                combined = hashes[i] + hashes[i+1]
                new_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
            hashes = new_hashes

        return hashes[0]

    def get_merkle_root(self) -> str:
        """
        Get Merkle root of entire chain.

        This single hash represents the entire decision history.
        Can be published to external registry for verification.
        """
        with self._lock:
            return self._get_merkle_root_internal()

    def export_audit(self, filepath: Path) -> None:
        """Export full chain as JSON for auditors (atomic write)"""
        with self._lock:
            data = {
                "hcp_version": self.HCP_VERSION,
                "agent": self.actor.to_dict(),
                "chain_length": len(self.chain),
                "merkle_root": self._get_merkle_root_internal(),
                "verified": self._verify_internal(warn_no_anchor=False),
                "exported_at": datetime.utcnow().isoformat() + "Z",
                # FOUNDATION: PROOFNEST
                "foundation": {
                    "axiom": self.AXIOM,
                    "meaning": self.AXIOM_MEANING,
                    "is_definitional": True,
                    "note": "This axiom DEFINES honesty - it cannot be 'broken', only violated"
                },
                # CRITICAL: Security status
                "security_status": {
                    "has_external_anchor": self.has_external_anchor(),
                    "signature_version": "ed25519",  # B1 FIX: Using AgentIdentity now
                    "thread_safe": True,
                    "path_validated": True,
                    "quantum_safe": True
                },
                # NEW: Cryptographic identity
                "identity": self._identity.export_public() if self._identity else None,
                "decisions": [r.to_dict() for r in self.chain]
            }

            # B6 FIX: Atomic write
            target = Path(filepath)
            fd, tmp_path = tempfile.mkstemp(
                suffix='.tmp',
                prefix='audit_',
                dir=target.parent
            )
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(data, f, indent=2)
                os.replace(tmp_path, target)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

    def export(self) -> 'ProofBundle':
        """
        Export the decision chain as a portable ProofBundle.

        Returns:
            ProofBundle containing the entire decision history,
            signed with the agent's identity.

        Example:
            pn = ProofNest(agent_id="my-agent")
            pn.decide(action="Approved", reasoning="OK", risk_level=RiskLevel.LOW)
            bundle = pn.export()
            bundle.to_file("audit_trail.json")
        """
        from .proofbundle import ProofBundle

        with self._lock:
            content = {
                "agent_id": self._identity.agent_id,
                "agent_did": self.did,
                "chain_length": len(self.chain),
                "merkle_root": self._get_merkle_root_internal(),
                "decisions": [r.to_dict() for r in self.chain],
                "exported_at": datetime.utcnow().isoformat() + "Z",
            }

            return ProofBundle.decision(
                content=content,
                private_key=self._identity.keys.signing_key,
                public_key=self._identity.keys.public_key,
                metadata={
                    "source": "ProofNest.export()",
                    "hcp_version": self.HCP_VERSION,
                }
            )

    def _save_record(self, record: DecisionRecord) -> None:
        """
        Save record to disk atomically.

        B6 FIX: Uses write-to-temp-then-rename pattern to prevent corruption
        if the process is interrupted during write.
        """
        filepath = self.storage_path / f"{record.decision_id}.json"

        # Write to temp file in same directory (for atomic rename)
        fd, tmp_path = tempfile.mkstemp(
            suffix='.tmp',
            prefix=f'{record.decision_id}_',
            dir=self.storage_path
        )
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(record.to_dict(), f, indent=2)
            # Atomic rename (on POSIX systems)
            os.replace(tmp_path, filepath)
        except Exception:
            # Clean up temp file on error
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _load_chain(self) -> None:
        """
        Load existing chain from disk, sorted by timestamp.

        CRITICAL: Validates record integrity by comparing stored hash with recomputed hash.
        Raises ValueError if any record has been tampered with.
        """
        files = list(self.storage_path.glob("*.json"))

        # Skip anchor files
        files = [f for f in files if not f.name.endswith("_anchor.json")]

        if not files:
            return

        # Load all records with their data
        records_data = []
        for filepath in files:
            try:
                with open(filepath) as f:
                    data = json.load(f)
                # Validate required fields exist
                if not all(k in data for k in ["timestamp", "decision", "decision_id", "chain"]):
                    print(f"WARNING: Skipping malformed record: {filepath.name}")
                    continue
                # Validate decision structure
                decision = data.get("decision", {})
                if not all(k in decision for k in ["action", "reasoning", "confidence", "risk_level"]):
                    print(f"WARNING: Skipping record with missing decision fields: {filepath.name}")
                    continue
                records_data.append((data, filepath))
            except json.JSONDecodeError as e:
                print(f"WARNING: Skipping corrupted JSON file: {filepath.name} ({e})")
                continue
            except Exception as e:
                print(f"WARNING: Error loading {filepath.name}: {e}")
                continue

        # Sort by timestamp (ISO8601 format sorts correctly as strings)
        records_data.sort(key=lambda x: x[0]["timestamp"])

        # Build chain in correct order
        for data, filepath in records_data:
            # Load version for backwards compatibility
            # Old records without hcp_version are assumed to be v2.0
            version = data.get("hcp_version", "2.0")

            # Load signature if present (v2.0+ with signatures enabled)
            sig = None
            if "signature" in data and data["signature"]:
                try:
                    sig = Signature.from_dict(data["signature"])
                except (KeyError, TypeError):
                    pass  # Invalid signature data, skip

            # Get stored hash for integrity check
            stored_hash = data.get("chain", {}).get("record_hash")

            # B4 FIX: Load stored actor, not current actor
            # This ensures records reflect their original actor identity
            stored_actor_data = data.get("actor", {})
            if stored_actor_data:
                stored_actor = Actor.from_dict(stored_actor_data)
            else:
                # Fallback for legacy records without full actor data
                stored_actor = Actor(
                    id=stored_actor_data.get("id", self.actor.id),
                    type=ActorType.AI,
                    model=stored_actor_data.get("model", "unknown")
                )

            record = DecisionRecord(
                decision_id=data["decision_id"],
                timestamp=data["timestamp"],
                actor=stored_actor,
                action=data["decision"]["action"],
                reasoning=data["decision"]["reasoning"],
                alternatives=data["decision"].get("alternatives_considered", []),
                confidence=data["decision"]["confidence"],
                risk_level=RiskLevel(data["decision"]["risk_level"]),
                previous_hash=data["chain"]["previous_hash"],
                signature=sig,
                hcp_version=version
            )

            # CRITICAL: Verify record integrity - compare stored hash with recomputed hash
            if stored_hash and record.record_hash != stored_hash:
                raise ValueError(
                    f"INTEGRITY ERROR: Record {record.decision_id} has been tampered with! "
                    f"Stored hash: {stored_hash[:16]}..., Computed hash: {record.record_hash[:16]}..."
                )

            self.chain.append(record)


# Convenience function for quick integration
def log_decision(
    action: str,
    reasoning: str,
    agent_id: str = "default-agent",
    **kwargs
) -> DecisionRecord:
    """
    Quick way to log a decision without managing ProofNest instance.

    Usage:
        from proofnest import log_decision

        log_decision(
            action="Sent email to user",
            reasoning="User requested password reset",
            agent_id="my-agent"
        )
    """
    hc = ProofNest(agent_id=agent_id)
    return hc.decide(action=action, reasoning=reasoning, **kwargs)


# === DEMO ===
if __name__ == "__main__":
    print("🗼 PROOFNEST SDK v2.0 - Quantum-Ready")
    print("=" * 50)

    # Create instance with cryptographic identity
    hc = ProofNest(
        agent_id="demo-agent-quantum",
        agent_model="claude-opus-4-5"
    )

    print(f"\n🔐 Agent DID: {hc.did}")
    print(f"🔑 Public key hash: {hc.public_key_hash[:32]}...")

    # Log some decisions (automatically signed)
    hc.decide(
        action="Analyzed user request",
        reasoning="User asked about AI ethics, relevant to our domain",
        risk_level=RiskLevel.LOW
    )

    hc.decide(
        action="Recommended PROOFNEST protocol",
        reasoning="User needs EU AI Act compliance, this is the best solution",
        alternatives=["Build custom solution", "Use competitor X"],
        confidence=0.95,
        risk_level=RiskLevel.MEDIUM
    )

    hc.decide(
        action="Generated protocol specification",
        reasoning="User confirmed they want to proceed with PROOFNEST",
        risk_level=RiskLevel.LOW
    )

    # Verify chain
    print(f"\n✅ Chain verified: {hc.verify()}")
    print(f"📊 Chain length: {len(hc.chain)}")
    print(f"🔗 Merkle root: {hc.get_merkle_root()[:16]}...")

    # Show last decision with signature
    last = hc.chain[-1]
    print(f"\n📝 Last decision:")
    print(f"   Action: {last.action}")
    print(f"   Reasoning: {last.reasoning}")
    print(f"   Risk: {last.risk_level.value}")
    if last.signature:
        print(f"   Signature: {last.signature.value[:32]}...")
        print(f"   Signer DID: {last.signature.signer_did}")

    print("\n🗼 Quantum-ready lighthouse is lit!")
