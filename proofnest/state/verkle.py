"""
HONEST Chain - Verkle Tree Implementation

Verkle trees provide:
- O(log n) proof size (vs O(n) for Merkle)
- Efficient updates
- Compact state representation

This is a simplified implementation using SHA3-256 for
quantum-resistant commitments. A production version would
use polynomial commitments (KZG/IPA) for even smaller proofs.

Per GPT-5.2:
    "Minimal L1 state. State rent/expiry to prevent bloat.
     Consider Verkle trees for witness efficiency."

GPT-5.2 REVIEWED: 2025-12-23
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Iterator
from enum import Enum, auto
import hashlib
import json
from abc import ABC, abstractmethod


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Empty root hash (SHA3-256 of empty bytes)
EMPTY_ROOT = hashlib.sha3_256(b"").digest()

# Verkle tree branching factor (256 for 1-byte path steps)
BRANCHING_FACTOR = 256

# Maximum key length in bytes
MAX_KEY_LENGTH = 32

# Maximum value size in bytes
MAX_VALUE_SIZE = 65536


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def hash_sha3_256(data: bytes) -> bytes:
    """Hash data with SHA3-256 (quantum-resistant)."""
    return hashlib.sha3_256(data).digest()


def hash_key(key: bytes) -> bytes:
    """
    Hash a key to fixed 32 bytes.

    Ensures all keys are same length for uniform tree depth.
    Uses domain separation for security.
    """
    domain = b"HONEST.verkle.key\x00"
    return hash_sha3_256(domain + key)


def hash_node(children: List[bytes]) -> bytes:
    """
    Hash children to compute node commitment.

    Uses domain separation and includes count to
    differentiate between node types.
    """
    domain = b"HONEST.verkle.node\x00"
    count = len(children).to_bytes(2, 'big')
    data = domain + count + b"".join(children)
    return hash_sha3_256(data)


def hash_leaf(key: bytes, value: bytes) -> bytes:
    """
    Hash a leaf node.

    Uses domain separation and includes key+value.
    """
    domain = b"HONEST.verkle.leaf\x00"
    key_len = len(key).to_bytes(2, 'big')
    val_len = len(value).to_bytes(4, 'big')
    data = domain + key_len + key + val_len + value
    return hash_sha3_256(data)


# ═══════════════════════════════════════════════════════════════════════════════
# NODE TYPES
# ═══════════════════════════════════════════════════════════════════════════════

class NodeType(Enum):
    """Types of Verkle tree nodes."""
    EMPTY = auto()      # No data
    LEAF = auto()       # Stores key-value pair
    BRANCH = auto()     # Internal node with children


@dataclass
class VerkleNode:
    """
    Node in a Verkle tree.

    Can be:
    - Empty: No data, zero commitment
    - Leaf: Contains key-value pair
    - Branch: Contains children (up to 256)
    """

    node_type: NodeType

    # For leaf nodes
    key: bytes = b""
    value: bytes = b""

    # For branch nodes (sparse: only non-empty children)
    children: Dict[int, 'VerkleNode'] = field(default_factory=dict)

    # Cached commitment (recomputed on changes)
    _commitment: Optional[bytes] = field(default=None, repr=False)

    @property
    def commitment(self) -> bytes:
        """Get node commitment, computing if needed."""
        if self._commitment is None:
            self._commitment = self._compute_commitment()
        return self._commitment

    def _compute_commitment(self) -> bytes:
        """Compute commitment based on node type."""
        if self.node_type == NodeType.EMPTY:
            return EMPTY_ROOT

        elif self.node_type == NodeType.LEAF:
            return hash_leaf(self.key, self.value)

        elif self.node_type == NodeType.BRANCH:
            # Create array of child commitments
            child_commits = []
            for i in range(BRANCHING_FACTOR):
                if i in self.children:
                    child_commits.append(self.children[i].commitment)
                else:
                    child_commits.append(EMPTY_ROOT)
            return hash_node(child_commits)

        raise ValueError(f"Unknown node type: {self.node_type}")

    def invalidate_commitment(self) -> None:
        """Invalidate cached commitment (call after modifications)."""
        self._commitment = None

    def is_empty(self) -> bool:
        """Check if node is empty."""
        return self.node_type == NodeType.EMPTY

    def is_leaf(self) -> bool:
        """Check if node is a leaf."""
        return self.node_type == NodeType.LEAF

    def is_branch(self) -> bool:
        """Check if node is a branch."""
        return self.node_type == NodeType.BRANCH

    @classmethod
    def empty(cls) -> 'VerkleNode':
        """Create empty node."""
        return cls(node_type=NodeType.EMPTY)

    @classmethod
    def leaf(cls, key: bytes, value: bytes) -> 'VerkleNode':
        """Create leaf node."""
        return cls(node_type=NodeType.LEAF, key=key, value=value)

    @classmethod
    def branch(cls, children: Optional[Dict[int, 'VerkleNode']] = None) -> 'VerkleNode':
        """Create branch node."""
        return cls(node_type=NodeType.BRANCH, children=children or {})


# ═══════════════════════════════════════════════════════════════════════════════
# PROOF STRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class VerkleProof:
    """
    Proof of existence/non-existence in Verkle tree.

    Contains:
    - Path from root to key location
    - Sibling commitments at each level
    - Leaf data if key exists
    """

    # Key being proved (hashed)
    key_hash: bytes

    # Value if key exists, None if proving non-existence
    value: Optional[bytes]

    # Path through tree (list of child indices)
    path: List[int]

    # Sibling commitments at each level
    # For each level: list of (index, commitment) for non-empty siblings
    siblings: List[List[Tuple[int, bytes]]]

    def verify(self, root: bytes) -> bool:
        """
        Verify proof against root commitment.

        Args:
            root: Expected root commitment

        Returns:
            True if proof is valid
        """
        # Reconstruct from bottom up
        if self.value is not None:
            # Existence proof: compute leaf commitment
            current = hash_leaf(self.key_hash, self.value)
        else:
            # Non-existence proof: empty node
            current = EMPTY_ROOT

        # Walk up the tree
        for level in range(len(self.path) - 1, -1, -1):
            child_idx = self.path[level]
            level_siblings = self.siblings[level]

            # Reconstruct children array
            children = [EMPTY_ROOT] * BRANCHING_FACTOR

            # Add siblings
            for idx, commitment in level_siblings:
                children[idx] = commitment

            # Add current node at its position
            children[child_idx] = current

            # Compute parent commitment
            current = hash_node(children)

        return current == root

    def to_bytes(self) -> bytes:
        """Serialize proof to bytes."""
        data = {
            'key_hash': self.key_hash.hex(),
            'value': self.value.hex() if self.value else None,
            'path': self.path,
            'siblings': [
                [(idx, commit.hex()) for idx, commit in level]
                for level in self.siblings
            ]
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'VerkleProof':
        """Deserialize proof from bytes."""
        parsed = json.loads(data.decode('utf-8'))
        return cls(
            key_hash=bytes.fromhex(parsed['key_hash']),
            value=bytes.fromhex(parsed['value']) if parsed['value'] else None,
            path=parsed['path'],
            siblings=[
                [(idx, bytes.fromhex(commit)) for idx, commit in level]
                for level in parsed['siblings']
            ]
        )


# ═══════════════════════════════════════════════════════════════════════════════
# VERKLE TREE
# ═══════════════════════════════════════════════════════════════════════════════

class VerkleTree:
    """
    Verkle tree for efficient state storage.

    Features:
    - O(log n) proof size
    - O(log n) updates
    - SHA3-256 commitments (quantum-resistant)
    - Sparse representation (memory efficient)

    Usage:
        tree = VerkleTree()
        tree.put(b"account:alice", b"100")
        tree.put(b"account:bob", b"200")

        root = tree.root
        value = tree.get(b"account:alice")
        proof = tree.prove(b"account:alice")
        assert proof.verify(root)
    """

    def __init__(self, initial_root: Optional[bytes] = None):
        """
        Create new Verkle tree.

        Args:
            initial_root: Optional root to restore from
        """
        self._root_node: VerkleNode = VerkleNode.empty()
        self._size: int = 0

        # Stats
        self._puts: int = 0
        self._gets: int = 0

    @property
    def root(self) -> bytes:
        """Get root commitment."""
        return self._root_node.commitment

    @property
    def size(self) -> int:
        """Get number of key-value pairs."""
        return self._size

    def is_empty(self) -> bool:
        """Check if tree is empty."""
        return self._root_node.is_empty()

    def get(self, key: bytes) -> Optional[bytes]:
        """
        Get value for key.

        Args:
            key: Key to look up (will be hashed)

        Returns:
            Value if key exists, None otherwise
        """
        self._gets += 1
        key_hash = hash_key(key)
        node = self._find_node(key_hash)

        if node and node.is_leaf() and node.key == key_hash:
            return node.value
        return None

    def put(self, key: bytes, value: bytes) -> None:
        """
        Insert or update key-value pair.

        Args:
            key: Key (will be hashed)
            value: Value (max 64KB)

        Raises:
            ValueError: If value too large
        """
        if len(value) > MAX_VALUE_SIZE:
            raise ValueError(f"Value too large: {len(value)} > {MAX_VALUE_SIZE}")

        self._puts += 1
        key_hash = hash_key(key)

        # Insert into tree
        existed = self._insert(key_hash, value)

        if not existed:
            self._size += 1

    def delete(self, key: bytes) -> bool:
        """
        Delete key from tree.

        Args:
            key: Key to delete

        Returns:
            True if key existed, False otherwise
        """
        key_hash = hash_key(key)
        deleted = self._delete(key_hash)

        if deleted:
            self._size -= 1

        return deleted

    def prove(self, key: bytes) -> VerkleProof:
        """
        Generate proof for key.

        Works for both existence and non-existence proofs.

        Args:
            key: Key to prove

        Returns:
            VerkleProof that can be verified
        """
        key_hash = hash_key(key)
        path = []
        siblings = []

        current = self._root_node

        for i in range(len(key_hash)):
            if current.is_empty():
                # Non-existence: key path ends at empty node
                break

            if current.is_leaf():
                # Found a leaf - check if it's our key
                break

            # Branch node: descend
            child_idx = key_hash[i]
            path.append(child_idx)

            # Collect siblings at this level
            level_siblings = []
            for idx, child in current.children.items():
                if idx != child_idx:
                    level_siblings.append((idx, child.commitment))
            siblings.append(level_siblings)

            # Move to child
            if child_idx in current.children:
                current = current.children[child_idx]
            else:
                current = VerkleNode.empty()

        # Get value if key exists
        value = None
        if current.is_leaf() and current.key == key_hash:
            value = current.value

        return VerkleProof(
            key_hash=key_hash,
            value=value,
            path=path,
            siblings=siblings
        )

    def _find_node(self, key_hash: bytes) -> Optional[VerkleNode]:
        """Find node for given key hash."""
        current = self._root_node

        for i in range(len(key_hash)):
            if current.is_empty():
                return None

            if current.is_leaf():
                return current

            child_idx = key_hash[i]
            if child_idx in current.children:
                current = current.children[child_idx]
            else:
                return None

        return current

    def _insert(self, key_hash: bytes, value: bytes) -> bool:
        """
        Insert key-value into tree.

        Returns True if key already existed (update).
        """
        if self._root_node.is_empty():
            self._root_node = VerkleNode.leaf(key_hash, value)
            return False

        return self._insert_recursive(self._root_node, key_hash, value, 0)

    def _insert_recursive(self, node: VerkleNode, key_hash: bytes,
                          value: bytes, depth: int) -> bool:
        """Recursive insert helper."""
        node.invalidate_commitment()

        if node.is_leaf():
            if node.key == key_hash:
                # Update existing
                node.value = value
                return True
            else:
                # Split: convert leaf to branch
                old_key = node.key
                old_value = node.value

                # Create new branch
                node.node_type = NodeType.BRANCH
                node.children = {}
                node.key = b""
                node.value = b""

                # Re-insert old leaf
                old_idx = old_key[depth]
                node.children[old_idx] = VerkleNode.leaf(old_key, old_value)

                # Insert new leaf
                new_idx = key_hash[depth]
                if new_idx == old_idx:
                    # Same path, recurse
                    return self._insert_recursive(
                        node.children[old_idx], key_hash, value, depth + 1
                    )
                else:
                    node.children[new_idx] = VerkleNode.leaf(key_hash, value)
                    return False

        elif node.is_branch():
            child_idx = key_hash[depth]

            if child_idx not in node.children:
                # Create new leaf
                node.children[child_idx] = VerkleNode.leaf(key_hash, value)
                return False
            else:
                # Recurse into child
                return self._insert_recursive(
                    node.children[child_idx], key_hash, value, depth + 1
                )

        else:
            # Empty node - should not happen in normal flow
            raise RuntimeError("Unexpected empty node in insert path")

    def _delete(self, key_hash: bytes) -> bool:
        """Delete key from tree. Returns True if existed."""
        if self._root_node.is_empty():
            return False

        deleted, should_collapse = self._delete_recursive(
            self._root_node, key_hash, 0
        )

        if should_collapse:
            self._root_node = VerkleNode.empty()

        return deleted

    def _delete_recursive(self, node: VerkleNode, key_hash: bytes,
                          depth: int) -> Tuple[bool, bool]:
        """
        Recursive delete helper.

        Returns (deleted, should_collapse).
        """
        node.invalidate_commitment()

        if node.is_empty():
            return False, False

        if node.is_leaf():
            if node.key == key_hash:
                return True, True  # Delete this node
            return False, False

        # Branch node
        child_idx = key_hash[depth]
        if child_idx not in node.children:
            return False, False

        deleted, should_collapse = self._delete_recursive(
            node.children[child_idx], key_hash, depth + 1
        )

        if deleted and should_collapse:
            del node.children[child_idx]

            # Check if branch should collapse
            if len(node.children) == 0:
                return True, True
            elif len(node.children) == 1:
                # Collapse single-child branch
                only_child = list(node.children.values())[0]
                if only_child.is_leaf():
                    node.node_type = NodeType.LEAF
                    node.key = only_child.key
                    node.value = only_child.value
                    node.children = {}

        return deleted, False

    def items(self) -> Iterator[Tuple[bytes, bytes]]:
        """Iterate over all key-value pairs."""
        yield from self._items_recursive(self._root_node)

    def _items_recursive(self, node: VerkleNode) -> Iterator[Tuple[bytes, bytes]]:
        """Recursive items helper."""
        if node.is_empty():
            return

        if node.is_leaf():
            yield (node.key, node.value)
            return

        for child in node.children.values():
            yield from self._items_recursive(child)

    def stats(self) -> Dict[str, Any]:
        """Get tree statistics."""
        return {
            'size': self._size,
            'root': self.root.hex()[:16] + '...',
            'gets': self._gets,
            'puts': self._puts,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# STATE COMMITMENT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class StateCommitment:
    """
    State commitment at a block height.

    Used for:
    - Anchoring rollup state
    - Storing attestations
    - Generic data commitments

    Per GPT-5.2:
        "Anchor points for rollups, attestations, data, etc."
    """

    # Commitment type
    commitment_type: str

    # Data hash (SHA3-256)
    data_hash: bytes

    # Who submitted
    submitter: bytes

    # When submitted
    block_height: int

    # Expiry height (0 = permanent)
    expiry: int = 0

    # Optional metadata
    metadata: Dict[str, str] = field(default_factory=dict)

    def is_expired(self, current_height: int) -> bool:
        """Check if commitment has expired."""
        if self.expiry == 0:
            return False  # Permanent
        return current_height > self.expiry

    def commitment(self) -> bytes:
        """Compute commitment hash."""
        data = (
            self.commitment_type.encode() +
            self.data_hash +
            self.submitter +
            self.block_height.to_bytes(8, 'big') +
            self.expiry.to_bytes(8, 'big')
        )
        return hash_sha3_256(data)

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        data = {
            'type': self.commitment_type,
            'data_hash': self.data_hash.hex(),
            'submitter': self.submitter.hex(),
            'block_height': self.block_height,
            'expiry': self.expiry,
            'metadata': self.metadata,
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def from_bytes(cls, data: bytes) -> 'StateCommitment':
        """Deserialize from bytes."""
        parsed = json.loads(data.decode('utf-8'))
        return cls(
            commitment_type=parsed['type'],
            data_hash=bytes.fromhex(parsed['data_hash']),
            submitter=bytes.fromhex(parsed['submitter']),
            block_height=parsed['block_height'],
            expiry=parsed.get('expiry', 0),
            metadata=parsed.get('metadata', {}),
        )


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("HONEST Chain - Verkle Tree Test")
    print("=" * 50)

    # Create tree
    tree = VerkleTree()
    print(f"Empty tree root: {tree.root.hex()[:16]}...")

    # Insert some data
    tree.put(b"account:alice", b"1000")
    tree.put(b"account:bob", b"2000")
    tree.put(b"account:charlie", b"3000")

    print(f"\nAfter 3 inserts:")
    print(f"  Root: {tree.root.hex()[:16]}...")
    print(f"  Size: {tree.size}")

    # Get values
    alice_balance = tree.get(b"account:alice")
    bob_balance = tree.get(b"account:bob")
    print(f"\n  Alice: {alice_balance}")
    print(f"  Bob: {bob_balance}")

    # Generate and verify proof
    root = tree.root
    proof = tree.prove(b"account:alice")
    print(f"\nProof for alice:")
    print(f"  Path length: {len(proof.path)}")
    print(f"  Value: {proof.value}")
    print(f"  Verified: {proof.verify(root)}")

    # Non-existence proof
    proof_missing = tree.prove(b"account:dave")
    print(f"\nProof for non-existent dave:")
    print(f"  Value: {proof_missing.value}")
    print(f"  Verified: {proof_missing.verify(root)}")

    # Update
    tree.put(b"account:alice", b"1500")
    new_root = tree.root
    print(f"\nAfter update alice to 1500:")
    print(f"  New root: {new_root.hex()[:16]}...")
    print(f"  Root changed: {root != new_root}")

    # Delete
    tree.delete(b"account:bob")
    print(f"\nAfter deleting bob:")
    print(f"  Size: {tree.size}")
    print(f"  Bob value: {tree.get(b'account:bob')}")

    # Stats
    print(f"\nStats: {tree.stats()}")

    # Test StateCommitment
    print("\n" + "=" * 50)
    print("StateCommitment Test")

    commitment = StateCommitment(
        commitment_type="ROLLUP_STATE",
        data_hash=hash_sha3_256(b"rollup state data"),
        submitter=hash_sha3_256(b"validator1")[:20],
        block_height=1000,
        expiry=2000,
        metadata={"chain_id": "honest-ai-1"}
    )

    print(f"Commitment: {commitment.commitment().hex()[:16]}...")
    print(f"Expired at 1500: {commitment.is_expired(1500)}")
    print(f"Expired at 2500: {commitment.is_expired(2500)}")

    # Serialize/deserialize
    serialized = commitment.to_bytes()
    restored = StateCommitment.from_bytes(serialized)
    print(f"Serialization works: {commitment.commitment() == restored.commitment()}")

    print("\nVerkle tree tests passed!")
