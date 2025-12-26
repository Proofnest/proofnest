"""
HONEST Chain Cryptography Module

Implements quantum-proof cryptography per DILITHIUM_SPEC_v1.5.
GPT-5.2 APPROVED: 2025-12-23
"""

from .constants import (
    AlgorithmID,
    CONTAINER_SIZES,
    DILITHIUM_SIZES,
    MAGIC,
    VERSION,
)
from .container import SignatureContainer
from .kdf import HonestKDF
from .dilithium import (
    generate_ml_dsa_keypair,
    ml_dsa_sign,
    ml_dsa_verify,
)

__all__ = [
    "AlgorithmID",
    "CONTAINER_SIZES",
    "DILITHIUM_SIZES",
    "MAGIC",
    "VERSION",
    "SignatureContainer",
    "HonestKDF",
    "generate_ml_dsa_keypair",
    "ml_dsa_sign",
    "ml_dsa_verify",
]
