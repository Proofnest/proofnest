"""
HONEST Chain - State Management Module

Implements minimal L1 state with:
- Verkle tree for efficient proofs
- State rent and expiry
- Commitment storage
- Archival snapshots

Per GPT-5.2:
    "Avoid a single universal trie for everything.
     Use minimal L1 state with commitments,
     push application state to rollups."
"""

from .verkle import (
    VerkleTree,
    VerkleNode,
    VerkleProof,
    StateCommitment,
    hash_key,
    EMPTY_ROOT,
)

__all__ = [
    'VerkleTree',
    'VerkleNode',
    'VerkleProof',
    'StateCommitment',
    'hash_key',
    'EMPTY_ROOT',
]
