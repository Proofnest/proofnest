"""
PROOFNEST SDK v1.0 - Quantum-Ready Trust Infrastructure
========================================================

Portable, verifiable proof bundles for AI decisions.
Bitcoin-anchored, formally verified, quantum-safe.

Features:
    - Quantum-safe cryptographic identity (SHA3-256 + Dilithium3)
    - DID-style agent identifiers (did:pn:...)
    - Digital signatures on all decisions
    - Bitcoin anchoring for permanence
    - ProofBundle format for portable verification

Usage:
    from proofnest import ProofNest, RiskLevel, Bundle

    pn = ProofNest(agent_id="my-agent")

    # Get agent DID
    print(pn.did)  # did:pn:abc123...

    # Log decisions (automatically signed)
    pn.decide(
        action="Approved request",
        reasoning="All criteria met",
        risk_level=RiskLevel.LOW
    )
    assert pn.verify()

    # Create portable proof bundle
    bundle = Bundle.decision(
        decision_id="dec-001",
        action="Approved",
        reasoning="Criteria met",
        outcome="success",
        risk_level="low",
        identity=pn.identity
    )
    bundle.to_file("proof.json")

Copyright (c) 2025 Stellanium Ltd. All rights reserved.
Licensed under Apache License 2.0. See LICENSE file.
"""

__version__ = "1.2.5"
__author__ = "Stellanium Ltd"
__email__ = "admin@stellanium.io"
__license__ = "Apache-2.0"

# Core
from proofnest.core import (
    ProofNest,
    DecisionRecord,
    Actor,
    ActorType,
    RiskLevel,
    log_decision,
    # Exceptions
    ProofNestError,
    TimestampViolationError,
    ChainIntegrityError,
    SignatureError,
)

# Quantum-ready identity
from proofnest.identity import (
    AgentIdentity,
    Signature,
    HashCommitment,
    KeyMaterial,
    SignatureAlgorithm,
)

# Bitcoin anchoring
from proofnest.bitcoin import (
    BitcoinAnchorService,
    BitcoinAnchor,
    AnchorMethod,
    GroundTruth,
    create_bitcoin_anchor_callback,
)

# P2P network
from proofnest.p2p import (
    Node,
    MessageType,
    Message,
    Peer,
    create_anchor_callback,
)

# ProofBundle - portable proof format
from proofnest.proofbundle import (
    ProofBundle,
    ProofBundleType,
    Payload,
    Signer,
    Signature as ProofSignature,
    Anchor,
    Envelope,
    Revocation,
    Attestation,
    AnchorStatus,
    AnchorMethod as ProofAnchorMethod,
    MessageType as EnvelopeMessageType,
    BroadcastScope,
    RevocationReason,
    AttestationMethod,
    create_proofbundle,
    verify_proofbundle,
    verify_proofbundle_standalone,
)

# Convenience alias
Bundle = ProofBundle

__all__ = [
    # Core
    "ProofNest",
    "DecisionRecord",
    "Actor",
    "ActorType",
    "RiskLevel",
    "log_decision",
    # Exceptions
    "ProofNestError",
    "TimestampViolationError",
    "ChainIntegrityError",
    "SignatureError",
    # Identity
    "AgentIdentity",
    "Signature",
    "HashCommitment",
    "KeyMaterial",
    "SignatureAlgorithm",
    # Bitcoin
    "BitcoinAnchorService",
    "BitcoinAnchor",
    "AnchorMethod",
    "GroundTruth",
    "create_bitcoin_anchor_callback",
    # P2P
    "Node",
    "MessageType",
    "Message",
    "Peer",
    "create_anchor_callback",
    # ProofBundle
    "ProofBundle",
    "Bundle",  # Alias
    "ProofBundleType",
    "Payload",
    "Signer",
    "ProofSignature",
    "Anchor",
    "Envelope",
    "Revocation",
    "Attestation",
    "AnchorStatus",
    "ProofAnchorMethod",
    "EnvelopeMessageType",
    "BroadcastScope",
    "RevocationReason",
    "AttestationMethod",
    "create_proofbundle",
    "verify_proofbundle",
    "verify_proofbundle_standalone",
    # Meta
    "__version__",
]
