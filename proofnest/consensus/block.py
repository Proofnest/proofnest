"""
HONEST Chain - Block Structure

Minimal block structure for PoS + BFT consensus.

Per GPT-5.2 Blueprint:
    - Version, height, timestamp, prev_hash (header)
    - state_root, tx_root, receipt_root (state)
    - proposer, proposer_signature (consensus)
    - commit_signatures (BFT finality)
    - vrf_output, vrf_proof (randomness)

GPT-5.2 REVIEWED: 2025-12-23
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum, auto
import hashlib
import json
import time


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Block version (increment on protocol changes)
BLOCK_VERSION = 1

# Genesis timestamp (2025-01-01 00:00:00 UTC)
GENESIS_TIMESTAMP = 1735689600

# Maximum transactions per block
MAX_TRANSACTIONS_PER_BLOCK = 10000

# Target block time in seconds
TARGET_BLOCK_TIME = 6

# Finality threshold (2/3 of stake)
FINALITY_THRESHOLD = 2 / 3


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def hash_sha3_256(data: bytes) -> bytes:
    """Hash data with SHA3-256."""
    return hashlib.sha3_256(data).digest()


def merkle_root(hashes: List[bytes]) -> bytes:
    """
    Compute Merkle root of hashes.

    Uses domain separation for security.
    """
    if not hashes:
        return hash_sha3_256(b"HONEST.merkle.empty")

    if len(hashes) == 1:
        return hashes[0]

    # Pad to even length
    if len(hashes) % 2 == 1:
        hashes = hashes + [hashes[-1]]

    # Compute next level
    next_level = []
    for i in range(0, len(hashes), 2):
        combined = b"HONEST.merkle.node\x00" + hashes[i] + hashes[i + 1]
        next_level.append(hash_sha3_256(combined))

    return merkle_root(next_level)


# ═══════════════════════════════════════════════════════════════════════════════
# TRANSACTION TYPES
# ═══════════════════════════════════════════════════════════════════════════════

class TransactionType(Enum):
    """Types of transactions."""

    # BASIC
    TRANSFER = 1              # Token transfer

    # STAKING
    STAKE = 10                # Stake tokens
    UNSTAKE = 11              # Unstake tokens
    DELEGATE = 12             # Delegate to validator
    UNDELEGATE = 13           # Remove delegation

    # GOVERNANCE
    PROPOSE = 20              # Create proposal
    VOTE = 21                 # Vote on proposal

    # ATTESTATION
    ATTEST = 30               # Create attestation
    REVOKE = 31               # Revoke attestation

    # COMMITMENT
    COMMIT = 40               # Submit commitment (rollup state, data, etc.)

    # MARKETPLACE
    POST_TASK = 50            # Post compute task
    CLAIM_TASK = 51           # Claim task result
    DISPUTE_TASK = 52         # Dispute task result


class ReceiptStatus(Enum):
    """Transaction execution status."""
    SUCCESS = 0
    FAILURE = 1
    OUT_OF_GAS = 2
    INVALID_SIGNATURE = 3
    INSUFFICIENT_BALANCE = 4
    NONCE_MISMATCH = 5


# ═══════════════════════════════════════════════════════════════════════════════
# TRANSACTION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Transaction:
    """
    Transaction in HONEST Chain.

    Uses Dilithium signatures for quantum resistance.
    """

    # TYPE
    tx_type: TransactionType

    # SENDER
    sender: bytes                 # 32-byte sender address
    nonce: int                    # Replay protection

    # RECIPIENT (optional for some tx types)
    recipient: Optional[bytes] = None

    # VALUE
    value: int = 0                # Token amount (for transfers, stakes)

    # DATA
    data: bytes = b""             # Type-specific data

    # GAS
    gas_limit: int = 21000        # Maximum gas units
    gas_price: int = 1            # Price per gas unit

    # SIGNATURE (Dilithium)
    signature: bytes = b""        # Quantum-resistant signature
    signature_algo: bytes = b"DL3\x00"  # Algorithm ID from registry

    # CACHED HASH
    _hash: Optional[bytes] = field(default=None, repr=False)

    @property
    def hash(self) -> bytes:
        """Get transaction hash."""
        if self._hash is None:
            self._hash = self._compute_hash()
        return self._hash

    def _compute_hash(self) -> bytes:
        """Compute transaction hash (excludes signature)."""
        data = (
            b"HONEST.tx\x00" +
            self.tx_type.value.to_bytes(2, 'big') +
            self.sender +
            self.nonce.to_bytes(8, 'big') +
            (self.recipient or b"\x00" * 32) +
            self.value.to_bytes(32, 'big') +
            len(self.data).to_bytes(4, 'big') +
            self.data +
            self.gas_limit.to_bytes(8, 'big') +
            self.gas_price.to_bytes(8, 'big')
        )
        return hash_sha3_256(data)

    def signing_hash(self) -> bytes:
        """Get hash that needs to be signed."""
        return self._compute_hash()

    def is_signed(self) -> bool:
        """Check if transaction is signed."""
        return len(self.signature) > 0

    def gas_cost(self) -> int:
        """Calculate maximum gas cost."""
        return self.gas_limit * self.gas_price

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'tx_type': self.tx_type.value,
            'sender': self.sender.hex(),
            'nonce': self.nonce,
            'recipient': self.recipient.hex() if self.recipient else None,
            'value': self.value,
            'data': self.data.hex(),
            'gas_limit': self.gas_limit,
            'gas_price': self.gas_price,
            'signature': self.signature.hex(),
            'signature_algo': self.signature_algo.hex(),
            'hash': self.hash.hex(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        """Create from dictionary."""
        return cls(
            tx_type=TransactionType(data['tx_type']),
            sender=bytes.fromhex(data['sender']),
            nonce=data['nonce'],
            recipient=bytes.fromhex(data['recipient']) if data.get('recipient') else None,
            value=data.get('value', 0),
            data=bytes.fromhex(data.get('data', '')),
            gas_limit=data.get('gas_limit', 21000),
            gas_price=data.get('gas_price', 1),
            signature=bytes.fromhex(data.get('signature', '')),
            signature_algo=bytes.fromhex(data.get('signature_algo', '444c3300')),
        )


@dataclass
class Receipt:
    """
    Transaction execution receipt.

    Contains execution result and gas usage.
    """

    tx_hash: bytes                # Transaction hash
    status: ReceiptStatus         # Execution status
    gas_used: int                 # Actual gas consumed
    block_height: int             # Block this was included in
    tx_index: int                 # Index in block

    # LOGS
    logs: List[Dict[str, Any]] = field(default_factory=list)

    # ERROR
    error_message: str = ""       # Human-readable error

    @property
    def hash(self) -> bytes:
        """Get receipt hash."""
        data = (
            b"HONEST.receipt\x00" +
            self.tx_hash +
            self.status.value.to_bytes(1, 'big') +
            self.gas_used.to_bytes(8, 'big')
        )
        return hash_sha3_256(data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'tx_hash': self.tx_hash.hex(),
            'status': self.status.value,
            'gas_used': self.gas_used,
            'block_height': self.block_height,
            'tx_index': self.tx_index,
            'logs': self.logs,
            'error_message': self.error_message,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# BLOCK STRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class BlockHeader:
    """
    Block header - contains metadata and commitments.

    Designed for light client verification.
    """

    # METADATA
    version: int                  # Protocol version
    height: int                   # Block height
    timestamp: int                # Unix timestamp

    # CHAIN
    prev_hash: bytes              # Previous block hash

    # STATE ROOTS
    state_root: bytes             # Verkle tree root
    tx_root: bytes                # Transaction merkle root
    receipt_root: bytes           # Receipt merkle root

    # CONSENSUS
    proposer: bytes               # Proposer public key (Dilithium)
    proposer_signature: bytes = b""  # Block signature

    # RANDOMNESS (for leader selection)
    vrf_output: bytes = b""       # Verifiable random output
    vrf_proof: bytes = b""        # VRF proof

    # CACHED
    _hash: Optional[bytes] = field(default=None, repr=False)

    @property
    def hash(self) -> bytes:
        """Get block hash (excludes proposer_signature for signing)."""
        if self._hash is None:
            self._hash = self._compute_hash()
        return self._hash

    def _compute_hash(self) -> bytes:
        """Compute block header hash."""
        data = (
            b"HONEST.block\x00" +
            self.version.to_bytes(4, 'big') +
            self.height.to_bytes(8, 'big') +
            self.timestamp.to_bytes(8, 'big') +
            self.prev_hash +
            self.state_root +
            self.tx_root +
            self.receipt_root +
            self.proposer +
            self.vrf_output
        )
        return hash_sha3_256(data)

    def invalidate_hash(self) -> None:
        """Invalidate cached hash after modification."""
        self._hash = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'version': self.version,
            'height': self.height,
            'timestamp': self.timestamp,
            'prev_hash': self.prev_hash.hex(),
            'state_root': self.state_root.hex(),
            'tx_root': self.tx_root.hex(),
            'receipt_root': self.receipt_root.hex(),
            'proposer': self.proposer.hex(),
            'proposer_signature': self.proposer_signature.hex(),
            'vrf_output': self.vrf_output.hex() if self.vrf_output else '',
            'vrf_proof': self.vrf_proof.hex() if self.vrf_proof else '',
            'hash': self.hash.hex(),
        }


@dataclass
class BlockBody:
    """
    Block body - contains transactions and BFT commits.
    """

    # TRANSACTIONS
    transactions: List[Transaction] = field(default_factory=list)

    # RECEIPTS
    receipts: List[Receipt] = field(default_factory=list)

    # BFT FINALITY
    # List of (validator_pubkey, signature) for 2/3+ finality
    commit_signatures: List[tuple] = field(default_factory=list)

    def tx_count(self) -> int:
        """Get transaction count."""
        return len(self.transactions)

    def compute_tx_root(self) -> bytes:
        """Compute transaction merkle root."""
        if not self.transactions:
            return hash_sha3_256(b"HONEST.tx.empty")
        tx_hashes = [tx.hash for tx in self.transactions]
        return merkle_root(tx_hashes)

    def compute_receipt_root(self) -> bytes:
        """Compute receipt merkle root."""
        if not self.receipts:
            return hash_sha3_256(b"HONEST.receipt.empty")
        receipt_hashes = [r.hash for r in self.receipts]
        return merkle_root(receipt_hashes)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'transactions': [tx.to_dict() for tx in self.transactions],
            'receipts': [r.to_dict() for r in self.receipts],
            'commit_signatures': [
                {'validator': v.hex(), 'signature': s.hex()}
                for v, s in self.commit_signatures
            ],
        }


@dataclass
class Block:
    """
    Complete block in HONEST Chain.

    Combines header (for light clients) with body (full nodes).
    """

    header: BlockHeader
    body: BlockBody

    @property
    def hash(self) -> bytes:
        """Get block hash."""
        return self.header.hash

    @property
    def height(self) -> int:
        """Get block height."""
        return self.header.height

    @property
    def timestamp(self) -> int:
        """Get block timestamp."""
        return self.header.timestamp

    @property
    def prev_hash(self) -> bytes:
        """Get previous block hash."""
        return self.header.prev_hash

    @property
    def tx_count(self) -> int:
        """Get transaction count."""
        return self.body.tx_count()

    def is_signed(self) -> bool:
        """Check if block is signed by proposer."""
        return len(self.header.proposer_signature) > 0

    def is_finalized(self, validators: List[tuple], threshold: float = FINALITY_THRESHOLD) -> bool:
        """
        Check if block has BFT finality.

        Args:
            validators: List of (pubkey, stake) tuples
            threshold: Required fraction of stake (default 2/3)

        Returns:
            True if 2/3+ stake has signed
        """
        if not self.body.commit_signatures:
            return False

        total_stake = sum(stake for _, stake in validators)
        if total_stake == 0:
            return False

        # Build validator lookup
        validator_stakes = {pubkey: stake for pubkey, stake in validators}

        # Sum signed stake
        signed_stake = 0
        for validator_pubkey, signature in self.body.commit_signatures:
            if validator_pubkey in validator_stakes:
                # TODO: Verify signature
                signed_stake += validator_stakes[validator_pubkey]

        return signed_stake >= (total_stake * threshold)

    def validate_structure(self) -> tuple:
        """
        Validate block structure (not signatures).

        Returns:
            (is_valid, error_message)
        """
        # Check version
        if self.header.version != BLOCK_VERSION:
            return False, f"Invalid version: {self.header.version}"

        # Check timestamp
        if self.header.timestamp < GENESIS_TIMESTAMP:
            return False, "Timestamp before genesis"

        if self.header.timestamp > time.time() + 60:  # 60s clock drift
            return False, "Timestamp too far in future"

        # Check tx count
        if len(self.body.transactions) > MAX_TRANSACTIONS_PER_BLOCK:
            return False, f"Too many transactions: {len(self.body.transactions)}"

        # Check tx root
        computed_tx_root = self.body.compute_tx_root()
        if computed_tx_root != self.header.tx_root:
            return False, "TX root mismatch"

        # Check receipt root
        computed_receipt_root = self.body.compute_receipt_root()
        if computed_receipt_root != self.header.receipt_root:
            return False, "Receipt root mismatch"

        return True, ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'header': self.header.to_dict(),
            'body': self.body.to_dict(),
        }

    def to_bytes(self) -> bytes:
        """Serialize to bytes (JSON)."""
        return json.dumps(self.to_dict()).encode('utf-8')

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Create block from dictionary."""
        header_data = data['header']
        body_data = data['body']

        header = BlockHeader(
            version=header_data['version'],
            height=header_data['height'],
            timestamp=header_data['timestamp'],
            prev_hash=bytes.fromhex(header_data['prev_hash']),
            state_root=bytes.fromhex(header_data['state_root']),
            tx_root=bytes.fromhex(header_data['tx_root']),
            receipt_root=bytes.fromhex(header_data['receipt_root']),
            proposer=bytes.fromhex(header_data['proposer']),
            proposer_signature=bytes.fromhex(header_data.get('proposer_signature', '')),
            vrf_output=bytes.fromhex(header_data.get('vrf_output', '')),
            vrf_proof=bytes.fromhex(header_data.get('vrf_proof', '')),
        )

        body = BlockBody(
            transactions=[Transaction.from_dict(tx) for tx in body_data.get('transactions', [])],
            receipts=[],  # Simplified for now
            commit_signatures=[
                (bytes.fromhex(cs['validator']), bytes.fromhex(cs['signature']))
                for cs in body_data.get('commit_signatures', [])
            ],
        )

        return cls(header=header, body=body)


# ═══════════════════════════════════════════════════════════════════════════════
# GENESIS BLOCK
# ═══════════════════════════════════════════════════════════════════════════════

def create_genesis_block(
    proposer: bytes = b"\x00" * 32,
    initial_state_root: bytes = b"\x00" * 32
) -> Block:
    """
    Create genesis block.

    Args:
        proposer: Genesis proposer public key
        initial_state_root: Initial state root (empty tree)

    Returns:
        Genesis block
    """
    # Empty merkle roots
    empty_tx_root = hash_sha3_256(b"HONEST.tx.empty")
    empty_receipt_root = hash_sha3_256(b"HONEST.receipt.empty")

    header = BlockHeader(
        version=BLOCK_VERSION,
        height=0,
        timestamp=GENESIS_TIMESTAMP,
        prev_hash=b"\x00" * 32,  # No previous block
        state_root=initial_state_root,
        tx_root=empty_tx_root,
        receipt_root=empty_receipt_root,
        proposer=proposer,
    )

    body = BlockBody()

    return Block(header=header, body=body)


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("HONEST Chain - Block Structure Test")
    print("=" * 50)

    # Create genesis block
    genesis = create_genesis_block()
    print(f"\nGenesis block:")
    print(f"  Height: {genesis.height}")
    print(f"  Hash: {genesis.hash.hex()[:16]}...")
    print(f"  Timestamp: {genesis.timestamp} ({GENESIS_TIMESTAMP})")

    # Validate genesis
    valid, error = genesis.validate_structure()
    print(f"  Valid structure: {valid}")

    # Create a transaction
    tx = Transaction(
        tx_type=TransactionType.TRANSFER,
        sender=bytes.fromhex("a" * 64),
        nonce=0,
        recipient=bytes.fromhex("b" * 64),
        value=1000,
    )
    print(f"\nTransaction:")
    print(f"  Type: {tx.tx_type.name}")
    print(f"  Hash: {tx.hash.hex()[:16]}...")
    print(f"  Value: {tx.value}")

    # Create block with transaction
    header = BlockHeader(
        version=BLOCK_VERSION,
        height=1,
        timestamp=int(time.time()),
        prev_hash=genesis.hash,
        state_root=bytes.fromhex("c" * 64),
        tx_root=b"",  # Will be computed
        receipt_root=b"",
        proposer=bytes.fromhex("d" * 64),
    )

    body = BlockBody(transactions=[tx])
    header.tx_root = body.compute_tx_root()
    header.receipt_root = body.compute_receipt_root()
    header.invalidate_hash()

    block1 = Block(header=header, body=body)
    print(f"\nBlock 1:")
    print(f"  Height: {block1.height}")
    print(f"  Hash: {block1.hash.hex()[:16]}...")
    print(f"  TX count: {block1.tx_count}")
    print(f"  Prev hash matches genesis: {block1.prev_hash == genesis.hash}")

    # Validate block 1
    valid, error = block1.validate_structure()
    print(f"  Valid structure: {valid}")
    if not valid:
        print(f"  Error: {error}")

    # Serialize and deserialize
    serialized = block1.to_bytes()
    restored = Block.from_dict(json.loads(serialized))
    print(f"\nSerialization:")
    print(f"  Size: {len(serialized)} bytes")
    print(f"  Hash preserved: {restored.hash == block1.hash}")

    # Test finality check
    validators = [
        (bytes.fromhex("01" + "00" * 31), 100),
        (bytes.fromhex("02" + "00" * 31), 100),
        (bytes.fromhex("03" + "00" * 31), 100),
    ]

    # Add signatures for 2/3 finality
    block1.body.commit_signatures = [
        (validators[0][0], b"sig1"),
        (validators[1][0], b"sig2"),
    ]

    is_final = block1.is_finalized(validators)
    print(f"\nFinality (2/3 stake signed): {is_final}")

    print("\nBlock structure tests passed!")
