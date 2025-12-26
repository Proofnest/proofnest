"""
HONEST Chain Cryptography Constants

Per DILITHIUM_SPEC_v1.5 (GPT-5.2 APPROVED)

============================================================================
COMPLIANCE AND VALIDATION STATUS
============================================================================

THIS IS NOT A FIPS-VALIDATED IMPLEMENTATION.

- Ed25519: Uses PyNaCl/libsodium (NOT FIPS 140-3 validated)
- Dilithium: Uses dilithium-py (CRYSTALS-Dilithium, NOT FIPS 204 ML-DSA)
- cSHAKE256/SHAKE256: Uses pycryptodome (NOT FIPS 140-3 validated)

The algorithm IDs use "ML_DSA" naming for forward compatibility with NIST
FIPS 204, but the current backend is CRYSTALS-Dilithium (the academic scheme
that ML-DSA is based on). There may be minor encoding/parameter differences
between CRYSTALS-Dilithium and finalized FIPS 204 ML-DSA.

MIGRATION PATH:
When vetted FIPS 204 ML-DSA implementations become available:
1. New ALG_IDs will be added for FIPS 204 variants
2. Existing ML_DSA_* IDs will remain for backward compatibility
3. Protocol layer will enforce which ALG_IDs are accepted

DO NOT claim FIPS 140-3 or FIPS 204 compliance without replacing backends
with validated implementations.

============================================================================

ALGORITHM ID MAPPING:
- ML_DSA_65 = CRYSTALS-Dilithium3 (NIST Security Level 3)
- ML_DSA_87 = CRYSTALS-Dilithium5 (NIST Security Level 5)

CONTAINER LAYOUT NOTE (§3.1):
The 116-byte fixed header ALWAYS contains Ed25519 pk+sig fields, even for
ML-DSA-only modes (where they are zero-filled). This design provides:
1. Fixed header parsing across all algorithm types
2. Wire-format stability for future algorithm additions
3. Simpler consensus validation logic

For ML-DSA-only containers, Ed25519 fields at offsets 16-47 (pk) and 48-111 (sig)
MUST be all zeros. For HYBRID containers, they MUST be valid non-zero values.
"""

from enum import IntEnum
from types import MappingProxyType
from typing import Dict, Tuple

# Magic bytes (fixed sequence, NOT little-endian integer)
MAGIC = bytes([0x48, 0x4F, 0x4E, 0x53])  # "HONS"

# Container version
VERSION = 0x01


class AlgorithmID(IntEnum):
    """Algorithm identifiers per spec §2.1"""
    ED25519_ONLY = 0x01
    ML_DSA_65 = 0x02  # Dilithium3 / NIST Level 3
    ML_DSA_87 = 0x03  # Dilithium5 / NIST Level 5
    HYBRID_ED25519_DILITHIUM3 = 0x10
    HYBRID_ED25519_DILITHIUM5 = 0x11


class ObjectType(IntEnum):
    """Object types for signing"""
    TRANSACTION = 0x01
    BLOCK = 0x02
    IDENTITY = 0x03


# Container sizes per ALG_ID (spec §2.1)
# CONSENSUS-CRITICAL: Wrapped in MappingProxyType to prevent runtime mutation
CONTAINER_SIZES: MappingProxyType = MappingProxyType({
    AlgorithmID.ED25519_ONLY: 116,
    AlgorithmID.ML_DSA_65: 5361,
    AlgorithmID.ML_DSA_87: 7303,  # 116 + 2592 + 4595
    AlgorithmID.HYBRID_ED25519_DILITHIUM3: 5361,
    AlgorithmID.HYBRID_ED25519_DILITHIUM5: 7303,  # 116 + 2592 + 4595
})

# Dilithium field sizes (pk_len, sig_len) per ALG_ID (spec §3.2)
# CONSENSUS-CRITICAL: Wrapped in MappingProxyType to prevent runtime mutation
DILITHIUM_SIZES: MappingProxyType = MappingProxyType({
    AlgorithmID.ED25519_ONLY: (0, 0),
    AlgorithmID.ML_DSA_65: (1952, 3293),
    AlgorithmID.ML_DSA_87: (2592, 4595),  # CRYSTALS-Dilithium5 (not ML-DSA-87)
    AlgorithmID.HYBRID_ED25519_DILITHIUM3: (1952, 3293),
    AlgorithmID.HYBRID_ED25519_DILITHIUM5: (2592, 4595),  # CRYSTALS-Dilithium5
})

# ML-DSA parameter set mapping (spec §2.2)
# Maps ALG_ID → Dilithium security level (65 = Level 3, 87 = Level 5)
# MUST include ALL ALG_IDs that use ML-DSA/Dilithium signatures
# CONSENSUS-CRITICAL: Wrapped in MappingProxyType to prevent runtime mutation
ML_DSA_LEVEL: MappingProxyType = MappingProxyType({
    AlgorithmID.ML_DSA_65: 65,
    AlgorithmID.ML_DSA_87: 87,
    AlgorithmID.HYBRID_ED25519_DILITHIUM3: 65,
    AlgorithmID.HYBRID_ED25519_DILITHIUM5: 87,
})

# Algorithms that are quantum-proof (post-quantum safe)
# Used for REQUIRE_PQ_SAFE_MODE enforcement at protocol layer
PQ_SAFE_ALGORITHMS: frozenset = frozenset({
    AlgorithmID.ML_DSA_65,
    AlgorithmID.ML_DSA_87,
    AlgorithmID.HYBRID_ED25519_DILITHIUM3,
    AlgorithmID.HYBRID_ED25519_DILITHIUM5,
})

# Algorithms safe for CONSENSUS (ML-DSA-only, NO Ed25519)
# HYBRID is excluded because Ed25519 verification determinism across
# libsodium versions/builds cannot be guaranteed for 2000-year consensus.
# Ed25519 strictness (encoding acceptance, malleability) varies by implementation.
# Use PQ_SAFE_ALGORITHMS for non-consensus PQ validation.
CONSENSUS_SAFE_ALGORITHMS: frozenset = frozenset({
    AlgorithmID.ML_DSA_65,
    AlgorithmID.ML_DSA_87,
})

# Algorithms that use ML-DSA signatures (for invariant checking)
ML_DSA_ALGORITHMS: frozenset = frozenset(ML_DSA_LEVEL.keys())

# Domain separators (spec §4.3)
# Format: LENGTH_BYTE || ASCII_STRING where LENGTH_BYTE = len(ASCII_STRING)
# This is a self-describing format for unambiguous parsing.
# CONSENSUS-CRITICAL: Wrapped in MappingProxyType to prevent runtime mutation
DOMAIN_SEPARATORS: MappingProxyType = MappingProxyType({
    ObjectType.TRANSACTION: b'\x12' + b'HONEST-CHAIN-v1-TX',         # 0x12 = 18
    ObjectType.BLOCK: b'\x15' + b'HONEST-CHAIN-v1-BLOCK',            # 0x15 = 21
    ObjectType.IDENTITY: b'\x18' + b'HONEST-CHAIN-v1-IDENTITY',      # 0x18 = 24
})


# Validation functions (called from crypto_selftest_or_die(), NOT at import time)
def validate_domain_separators() -> bool:
    """
    Validate domain separators for consensus safety.

    Checks:
    1. Length byte matches string length (self-describing format)
    2. Length byte is in valid range [1, 255]
    3. String part is pure ASCII (printable)
    4. All separators are unique (no collision)
    5. No separator is a prefix of another (unambiguous parsing)

    Returns:
        True if all separators are valid

    Raises:
        ConstantsValidationError: If any validation fails
    """
    seen_separators = set()

    for obj_type, separator in DOMAIN_SEPARATORS.items():
        # Check 1: non-empty
        if len(separator) < 2:
            raise ConstantsValidationError(
                f"DOMAIN_SEPARATORS[{obj_type.name}] too short (need length byte + content)"
            )

        length_byte = separator[0]
        string_part = separator[1:]

        # Check 2: length byte matches
        if length_byte != len(string_part):
            raise ConstantsValidationError(
                f"DOMAIN_SEPARATORS[{obj_type.name}] length byte mismatch: "
                f"prefix {length_byte} != actual {len(string_part)}"
            )

        # Check 3: length byte in valid range (1-255, since 0 would mean empty string)
        if length_byte < 1 or length_byte > 255:
            raise ConstantsValidationError(
                f"DOMAIN_SEPARATORS[{obj_type.name}] length byte {length_byte} out of range [1, 255]"
            )

        # Check 4: string part is ASCII printable (0x20-0x7E)
        for i, b in enumerate(string_part):
            if b < 0x20 or b > 0x7E:
                raise ConstantsValidationError(
                    f"DOMAIN_SEPARATORS[{obj_type.name}] contains non-printable ASCII "
                    f"at position {i}: 0x{b:02x}"
                )

        # Check 5: uniqueness
        if separator in seen_separators:
            raise ConstantsValidationError(
                f"DOMAIN_SEPARATORS[{obj_type.name}] is not unique"
            )
        seen_separators.add(separator)

    # Check 6: no prefix ambiguity (no separator is prefix of another)
    separator_list = list(DOMAIN_SEPARATORS.values())
    for i, sep_i in enumerate(separator_list):
        for j, sep_j in enumerate(separator_list):
            if i != j and sep_j.startswith(sep_i):
                raise ConstantsValidationError(
                    f"Domain separator prefix ambiguity: one separator is prefix of another"
                )

    return True


class ConstantsValidationError(Exception):
    """Constants validation failed - code or constants are inconsistent."""
    pass

# Ed25519 sizes (fixed)
ED25519_PK_SIZE = 32
ED25519_SIG_SIZE = 64

# Header size before Dilithium fields
HEADER_SIZE = 116


def validate_container_sizes() -> bool:
    """
    Validate that container size constants are consistent.

    Checks that CONTAINER_SIZES matches HEADER_SIZE + DILITHIUM_SIZES
    for all algorithm IDs.

    Returns:
        True if all sizes are consistent

    Raises:
        ConstantsValidationError: If any size is inconsistent
    """
    for alg_id in AlgorithmID:
        expected_pk_len, expected_sig_len = DILITHIUM_SIZES[alg_id]
        expected_size = HEADER_SIZE + expected_pk_len + expected_sig_len
        actual_size = CONTAINER_SIZES[alg_id]
        if expected_size != actual_size:
            raise ConstantsValidationError(
                f"CONTAINER_SIZES inconsistency for {alg_id.name}: "
                f"expected {expected_size} (HEADER_SIZE + {expected_pk_len} + "
                f"{expected_sig_len}), got {actual_size}"
            )
    return True


def validate_constants() -> bool:
    """
    Validate all constants for consistency.

    This function is called from crypto_selftest_or_die() at application
    startup, NOT at import time.

    Returns:
        True if all constants are valid

    Raises:
        ConstantsValidationError: If any validation fails
    """
    validate_domain_separators()
    validate_container_sizes()
    return True
