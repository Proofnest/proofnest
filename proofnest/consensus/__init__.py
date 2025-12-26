"""
HONEST Chain - Consensus Module

Implements PoS + BFT consensus as recommended by GPT-5.2:
    "Use a conservative base: PoS with BFT finality.
     Implement PoUW as a task marketplace, not consensus weight."

Key components:
- Block structure with Dilithium signatures
- Validator management with staking
- BFT finality gadget (2/3+ stake)
- VRF for leader selection
- Slashing for misbehavior
"""

from .block import (
    Block,
    BlockHeader,
    BlockBody,
    Transaction,
    TransactionType,
    Receipt,
    ReceiptStatus,
    create_genesis_block,
    GENESIS_TIMESTAMP,
)

__all__ = [
    'Block',
    'BlockHeader',
    'BlockBody',
    'Transaction',
    'TransactionType',
    'Receipt',
    'ReceiptStatus',
    'create_genesis_block',
    'GENESIS_TIMESTAMP',
]
