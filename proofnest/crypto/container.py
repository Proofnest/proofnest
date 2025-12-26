"""
HONEST Chain Signature Container

Per DILITHIUM_SPEC_v1.5 §3 (GPT-5.2 APPROVED)
Implements the universal signature container format.

DEPENDENCY REQUIREMENTS (CONSENSUS-CRITICAL):
================================================================================
ALL APIs in this module require the COMPLETE crypto selftest to pass, which
validates ALL cryptographic backends. This is a DELIBERATE DESIGN CHOICE for
consensus safety, not a limitation.

Required dependencies for ANY API call (including ED25519_ONLY):
- PyNaCl >= 1.5.0 (libsodium for Ed25519)
- pycryptodome (cSHAKE256 for KDF)
- dilithium-py >= 1.4.0 (CRYSTALS-Dilithium)

WHY: Consensus nodes MUST run identical code paths to ensure deterministic
behavior. Allowing "partial" initialization based on algorithm type would
create configuration-dependent behavior divergence across nodes. By requiring
all backends validated, we guarantee:
1. Every node runs identical selftest validation
2. Attestation fingerprints match across nodes
3. No "works on my machine" deployment failures

ED25519_ONLY mode is for TESTING AND NON-CONSENSUS TOOLING only. Production
consensus operations MUST use ML-DSA-only algorithms via the _consensus() APIs.
================================================================================

QUANTUM-PROOF CONSIDERATIONS:
This module supports multiple algorithm types including non-quantum-safe modes
(ED25519_ONLY). To achieve quantum-proof security guarantees, the PROTOCOL LAYER
must enforce that only PQ-safe modes are accepted for consensus:

- For quantum-proof: Use ML_DSA_65, ML_DSA_87, or HYBRID modes
- ED25519_ONLY is provided for testing and non-consensus tooling

The "2000-year quantum-proof" claim requires:
1. Protocol-level rejection of ED25519_ONLY for consensus transactions
2. Cryptographic agility plan for future algorithm migration
3. Governance framework for deprecating weak algorithms

This module provides the cryptographic primitives; enforcement is at the protocol layer.

DOMAIN SEPARATION NOTE:
The current spec (v1.5) includes ALG_ID in the SIGNING_INPUT hash, providing basic
algorithm domain separation. For maximum long-term security, future spec versions
could add algorithm-specific prefixes directly to the signature input:
- Ed25519: b"HONEST-ED25519-SIG-v1" || signing_input
- Dilithium: b"HONEST-DILITHIUM-SIG-v1" || signing_input

This is tracked as a potential spec v2.0 enhancement.
"""

from dataclasses import dataclass
from typing import Optional
import hashlib

import nacl.signing
import nacl.exceptions

# Runtime version enforcement for consensus-critical determinism
REQUIRED_PYNACL_VERSION = "1.5.0"  # Required for crypto_core_ed25519_is_valid_point

# Module-level validation state (using Event for portable thread-safety)
import threading
_LIBSODIUM_VALIDATION_EVENT = threading.Event()
_LIBSODIUM_VALIDATION_LOCK = threading.Lock()

# CONSENSUS-CRITICAL: Crypto selftest latch
# This latch is set ONLY by crypto_selftest_or_die() and is checked by all
# consensus APIs (deserialize_consensus, verify_consensus) to ensure the
# hash backends, constants, KAT, and signing-input vectors have been validated.
_CRYPTO_SELFTEST_EVENT = threading.Event()
_CRYPTO_SELFTEST_LOCK = threading.Lock()

# CONSENSUS-CRITICAL: Attestation and failed latch globals
# MUST be defined at module top to prevent NameError during circular imports.
# These are referenced by require_crypto_selftest() and crypto_selftest_or_die().
import types as _types
_CRYPTO_SELFTEST_ATTESTATION: _types.MappingProxyType = None  # type: ignore
_CRYPTO_SELFTEST_FAILED_EVENT = threading.Event()
_CRYPTO_SELFTEST_FAILED_EXCEPTION: Exception = None  # type: ignore


class CryptoSelftestNotRunError(Exception):
    """Consensus API called before crypto_selftest_or_die() completed.

    CONSENSUS-CRITICAL: All consensus nodes MUST call crypto_selftest_or_die()
    at startup BEFORE using any consensus APIs. This error indicates the node
    is not properly initialized and MUST NOT participate in consensus.
    """
    pass


class LibsodiumValidationError(Exception):
    """Libsodium validation failed - consensus-critical failure."""
    pass


class CryptoSelftestError(Exception):
    """Cryptographic self-test failed - node must not participate in consensus."""
    pass


def _parse_version_tuple(v: str) -> tuple:
    """
    Parse version string to tuple for comparison.

    Handles X.Y.Z format (e.g., "1.5.0" -> (1, 5, 0)).
    Strips PEP 440 suffixes: dev, a, b, rc, post, and local version (+).
    This avoids dependency on 'packaging' module.

    Examples:
        "1.5.0" -> (1, 5, 0)
        "1.5" -> (1, 5, 0)
        "1.5.0.dev1" -> (1, 5, 0)
        "1.5.0.post1" -> (1, 5, 0)
        "1.5.0+local" -> (1, 5, 0)
        "1.5.0a1" -> (1, 5, 0)
    """
    import re

    # Strip local version (+...) first
    base = v.split('+')[0]

    # Strip .devN, .postN, .aN, .bN, .rcN suffixes
    # Pattern: anything starting with .dev, .post, .a, .b, .rc followed by digits
    base = re.split(r'\.(dev|post|a|b|rc)\d*', base)[0]

    # Also handle aN, bN, rcN without dots (e.g., "1.5.0a1")
    base = re.split(r'(a|b|rc)\d+$', base)[0]

    # Split remaining version and convert to integers
    parts = base.split('.')
    result = []
    for p in parts[:3]:
        # Only take numeric parts
        try:
            result.append(int(p))
        except ValueError:
            # Non-numeric part, stop parsing
            break

    # Pad to 3 parts with zeros
    while len(result) < 3:
        result.append(0)

    return tuple(result)


def _check_pynacl_version() -> None:
    """
    Verify PyNaCl version meets minimum requirements.

    CONSENSUS-CRITICAL: Fails closed if version cannot be verified.
    Uses simple tuple comparison to avoid 'packaging' dependency.

    Raises:
        CryptoSelftestError: If version too old or cannot be determined
    """
    try:
        from importlib.metadata import version as get_version

        installed = get_version("pynacl")
        installed_tuple = _parse_version_tuple(installed)
        required_tuple = _parse_version_tuple(REQUIRED_PYNACL_VERSION)

        if installed_tuple < required_tuple:
            raise CryptoSelftestError(
                f"PyNaCl version {installed} < required {REQUIRED_PYNACL_VERSION}. "
                f"Upgrade: pip install 'pynacl>={REQUIRED_PYNACL_VERSION}'"
            )
    except CryptoSelftestError:
        raise
    except Exception as e:
        # Fail closed: cannot verify version = not safe for consensus
        raise CryptoSelftestError(
            f"Cannot verify PyNaCl version: {type(e).__name__}: {e}. "
            f"Consensus requires verified dependencies."
        ) from e


def _check_libsodium_features() -> None:
    """
    Verify libsodium has required features (Ed25519 core operations).

    CONSENSUS-CRITICAL: Fails closed if features are not available.
    We check feature flags rather than version numbers because:
    1. PyNaCl doesn't expose sodium_version_string
    2. Feature availability is what actually matters for consensus
    3. Runtime self-test (in _run_libsodium_torsion_selftest) validates behavior
    """
    try:
        from nacl.bindings import has_crypto_core_ed25519

        if not has_crypto_core_ed25519:
            raise LibsodiumValidationError(
                "libsodium crypto_core_ed25519 operations not available. "
                "Ensure PyNaCl is built with libsodium >= 1.0.18."
            )
    except ImportError:
        raise LibsodiumValidationError(
            "Cannot verify libsodium features - nacl.bindings unavailable. "
            "Ensure PyNaCl is properly installed."
        )


# All 8 canonical encodings of small-order Ed25519 points
# Used for runtime self-test only (actual rejection is done by libsodium)
_ED25519_TORSION_POINTS = [
    bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000"),  # Identity
    bytes.fromhex("0100000000000000000000000000000000000000000000000000000000000000"),  # Order 2
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),  # Order 4
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),  # Order 4
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),  # Order 8
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),  # Order 8
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),  # Order 8
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),  # Order 8
]

# Generator point G (must be accepted)
_ED25519_GENERATOR = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)


def _run_libsodium_torsion_selftest() -> None:
    """
    Run runtime self-test to verify libsodium rejects all 8 torsion points.

    CONSENSUS-CRITICAL: This MUST pass for consensus safety. If any torsion
    point is accepted, the libsodium build is incompatible.

    Raises:
        LibsodiumValidationError: If any torsion point is accepted or generator rejected
    """
    try:
        from nacl.bindings import crypto_core_ed25519_is_valid_point
    except ImportError:
        raise LibsodiumValidationError(
            "crypto_core_ed25519_is_valid_point not available. "
            "Ensure PyNaCl >= 1.5.0 with libsodium >= 1.0.18."
        )

    # Verify all 8 torsion points are rejected
    for i, point in enumerate(_ED25519_TORSION_POINTS):
        if crypto_core_ed25519_is_valid_point(point):
            raise LibsodiumValidationError(
                f"CONSENSUS-CRITICAL: libsodium accepted torsion point #{i} "
                f"({point.hex()[:16]}...). This libsodium build is incompatible."
            )

    # Verify generator is accepted (sanity check)
    if not crypto_core_ed25519_is_valid_point(_ED25519_GENERATOR):
        raise LibsodiumValidationError(
            "CONSENSUS-CRITICAL: libsodium rejected generator point G. "
            "This libsodium build is incompatible."
        )


def require_libsodium_validation() -> None:
    """
    Ensure libsodium has been validated for consensus safety.

    CONSENSUS-CRITICAL: Call this at node startup. Thread-safe.
    Uses threading.Event for portable correctness across Python interpreters.

    Raises:
        LibsodiumValidationError: If validation fails
    """
    # Fast path: already validated (Event.is_set() is thread-safe)
    if _LIBSODIUM_VALIDATION_EVENT.is_set():
        return

    # Slow path: acquire lock and validate
    with _LIBSODIUM_VALIDATION_LOCK:
        # Check again after acquiring lock (another thread may have completed)
        if _LIBSODIUM_VALIDATION_EVENT.is_set():
            return

        _check_libsodium_features()
        _run_libsodium_torsion_selftest()
        _LIBSODIUM_VALIDATION_EVENT.set()


def is_libsodium_validated() -> bool:
    """Return True if libsodium validation has passed."""
    return _LIBSODIUM_VALIDATION_EVENT.is_set()


def require_crypto_selftest() -> None:
    """
    Ensure crypto_selftest_or_die() has been called and passed.

    CONSENSUS-CRITICAL: This function MUST be called at the top of all
    consensus APIs (deserialize_consensus, verify_consensus, compute_signing_input)
    to ensure the node is properly initialized before processing consensus data.

    ATTESTATION CHECK: Also verifies that:
    1. The selftest has not failed (re-raises stored exception)
    2. The attestation object exists and is non-empty (mandatory)
    3. The constants fingerprint has not changed (detects runtime mutation)

    Raises:
        CryptoSelftestNotRunError: If crypto_selftest_or_die() has not been called
            or if the runtime environment has been mutated since selftest
        CryptoSelftestError: If selftest previously failed (re-raises the original)
    """
    # Check failed latch first - re-raise the original exception if selftest failed
    if _CRYPTO_SELFTEST_FAILED_EVENT.is_set():
        if _CRYPTO_SELFTEST_FAILED_EXCEPTION is not None:
            raise _CRYPTO_SELFTEST_FAILED_EXCEPTION
        else:
            raise CryptoSelftestNotRunError(
                "Crypto selftest previously failed but no exception was stored"
            )

    if not _CRYPTO_SELFTEST_EVENT.is_set():
        raise CryptoSelftestNotRunError(
            "Consensus API called before crypto_selftest_or_die(). "
            "All consensus nodes MUST call crypto_selftest_or_die() at startup "
            "BEFORE using any consensus APIs."
        )

    # Attestation MUST be present if latch is set (mandatory, not optional)
    if _CRYPTO_SELFTEST_ATTESTATION is None:
        raise CryptoSelftestNotRunError(
            "Attestation missing despite latch being set - internal state corruption"
        )

    # Attestation must have required fields
    if 'constants_fingerprint' not in _CRYPTO_SELFTEST_ATTESTATION:
        raise CryptoSelftestNotRunError(
            "Attestation missing 'constants_fingerprint' field - internal state corruption"
        )

    # Verify attestation fingerprint matches current runtime
    # This detects runtime mutation (hot-reload, monkeypatch, etc.)
    current_fingerprint = _compute_constants_fingerprint()
    stored_fingerprint = _CRYPTO_SELFTEST_ATTESTATION['constants_fingerprint']
    if current_fingerprint != stored_fingerprint:
        raise CryptoSelftestNotRunError(
            f"Constants fingerprint mismatch: runtime has been mutated since "
            f"crypto_selftest_or_die() was called. "
            f"Expected {stored_fingerprint[:16]}..., got {current_fingerprint[:16]}..."
        )


def is_crypto_selftest_complete() -> bool:
    """Return True if crypto_selftest_or_die() has been called and passed."""
    return _CRYPTO_SELFTEST_EVENT.is_set()


# NOTE: Import-time validation REMOVED per GPT-5.2 review.
# Consensus nodes MUST call crypto_selftest_or_die() before processing.
# This avoids non-deterministic partial initialization states and ensures
# a single explicit initialization path for consensus-critical validation.
# All version checks, feature checks, and self-tests are now deferred to
# crypto_selftest_or_die().

from .constants import (
    AlgorithmID,
    ObjectType,
    MAGIC,
    VERSION,
    CONTAINER_SIZES,
    DILITHIUM_SIZES,
    DOMAIN_SEPARATORS,
    ED25519_PK_SIZE,
    ED25519_SIG_SIZE,
    HEADER_SIZE,
    ML_DSA_LEVEL,
    PQ_SAFE_ALGORITHMS,
    CONSENSUS_SAFE_ALGORITHMS,
)
from .dilithium import ml_dsa_verify, require_kat_validation

# NOTE: PQ-safe enforcement is now done via explicit parameters to
# deserialize() and verify() methods, not via global mutable state.
# This ensures thread-safe, deterministic behavior in consensus nodes.


class ContainerError(Exception):
    """Error in signature container operations."""
    pass


class InvalidContainer(ContainerError):
    """Container format is invalid."""
    pass


class InvalidSignature(ContainerError):
    """Signature verification failed."""
    pass


@dataclass
class SignatureContainer:
    """
    Signature container per DILITHIUM_SPEC_v1.5 §3.1.

    Universal layout:
    - Offset 0-3: MAGIC
    - Offset 4: VERSION
    - Offset 5: ALG_ID
    - Offset 6-13: CHAIN_ID (uint64 LE)
    - Offset 14: OBJECT_TYPE
    - Offset 15: TX_VERSION
    - Offset 16-47: ED25519_PK (32 bytes, zeros if unused)
    - Offset 48-111: ED25519_SIG (64 bytes, zeros if unused)
    - Offset 112-113: DILITHIUM_PK_LEN (uint16 LE)
    - Offset 114-115: DILITHIUM_SIG_LEN (uint16 LE)
    - Offset 116+: DILITHIUM_PK (variable)
    - After PK: DILITHIUM_SIG (variable)
    """

    alg_id: AlgorithmID
    chain_id: int
    object_type: ObjectType
    tx_version: int
    ed25519_pk: bytes
    ed25519_sig: bytes
    dilithium_pk: bytes
    dilithium_sig: bytes

    def __post_init__(self):
        """Validate field sizes and ALG-specific invariants."""
        # Validate enum types (consensus-critical: must serialize correctly)
        if not isinstance(self.alg_id, AlgorithmID):
            raise InvalidContainer(
                f"alg_id must be AlgorithmID enum, got {type(self.alg_id).__name__}"
            )
        if not isinstance(self.object_type, ObjectType):
            raise InvalidContainer(
                f"object_type must be ObjectType enum, got {type(self.object_type).__name__}"
            )

        # Validate alg_id value (avoid KeyError)
        if self.alg_id not in DILITHIUM_SIZES:
            raise InvalidContainer(f"Unknown ALG_ID: {self.alg_id}")

        # Validate chain_id (uint64)
        if not isinstance(self.chain_id, int) or self.chain_id < 0 or self.chain_id > 0xFFFFFFFFFFFFFFFF:
            raise InvalidContainer(
                f"chain_id must be uint64 (0 to 2^64-1), got {self.chain_id}"
            )

        # Validate tx_version (uint8)
        if not isinstance(self.tx_version, int) or self.tx_version < 0 or self.tx_version > 255:
            raise InvalidContainer(
                f"tx_version must be uint8 (0-255), got {self.tx_version}"
            )

        if len(self.ed25519_pk) != ED25519_PK_SIZE:
            raise InvalidContainer(f"ED25519_PK must be {ED25519_PK_SIZE} bytes")
        if len(self.ed25519_sig) != ED25519_SIG_SIZE:
            raise InvalidContainer(f"ED25519_SIG must be {ED25519_SIG_SIZE} bytes")

        expected_pk_len, expected_sig_len = DILITHIUM_SIZES[self.alg_id]
        if len(self.dilithium_pk) != expected_pk_len:
            raise InvalidContainer(
                f"DILITHIUM_PK must be {expected_pk_len} bytes for {self.alg_id.name}"
            )
        if len(self.dilithium_sig) != expected_sig_len:
            raise InvalidContainer(
                f"DILITHIUM_SIG must be {expected_sig_len} bytes for {self.alg_id.name}"
            )

        # ALG-specific STRUCTURAL invariants only (no libsodium/crypto calls)
        # Crypto validation is deferred to verify() time
        self._validate_alg_invariants_structural()

    def _validate_alg_invariants_structural(self):
        """
        Validate ALG-specific STRUCTURAL invariants only (NO libsodium calls).

        PURE DATA VALIDATION: This method validates only structural requirements
        that can be checked without calling external cryptographic backends.
        This ensures SignatureContainer can be instantiated without triggering
        libsodium or Dilithium backend dependencies.

        Crypto validation (Ed25519 point validity, signature canonicality) is
        deferred to verify() time. This separation ensures:
        1. Container construction is deterministic and backend-independent
        2. Consensus code using deserialize_consensus() never triggers Ed25519 code
        3. Clear separation: "InvalidContainer" = structural, "InvalidSignature" = crypto

        Per spec format requirements:
        - ED25519_ONLY: Dilithium fields must be empty (size=0)
        - ML-DSA-only: Ed25519 fields must be all-zero (format encoding)
        - HYBRID: Ed25519 PK must be non-zero (structural, not point validity)
        """
        zero_ed_pk = bytes(ED25519_PK_SIZE)
        zero_ed_sig = bytes(ED25519_SIG_SIZE)

        if self.alg_id == AlgorithmID.ED25519_ONLY:
            # Dilithium fields must be empty (format requirement: size=0)
            if self.dilithium_pk != b'' or self.dilithium_sig != b'':
                raise InvalidContainer(
                    "ED25519_ONLY: Dilithium fields must be empty"
                )
            # NOTE: Ed25519 point validation DEFERRED to verify() time
            # This keeps __post_init__ libsodium-free

        elif self.alg_id in (AlgorithmID.ML_DSA_65, AlgorithmID.ML_DSA_87):
            # Ed25519 fields must be all-zero (format requirement)
            if self.ed25519_pk != zero_ed_pk:
                raise InvalidContainer(
                    "ML-DSA-only: Ed25519 PK must be all zeros"
                )
            if self.ed25519_sig != zero_ed_sig:
                raise InvalidContainer(
                    "ML-DSA-only: Ed25519 SIG must be all zeros"
                )
            # NOTE: Dilithium non-zero checks are in verify_consensus()

        elif self.alg_id in (
            AlgorithmID.HYBRID_ED25519_DILITHIUM3,
            AlgorithmID.HYBRID_ED25519_DILITHIUM5
        ):
            # HYBRID format: Ed25519 PK must be non-zero (structural check)
            if self.ed25519_pk == zero_ed_pk:
                raise InvalidContainer(
                    "HYBRID: Ed25519 PK must be non-zero"
                )
            # NOTE: Ed25519 point validation DEFERRED to verify() time
            # This keeps __post_init__ libsodium-free

    def _validate_ed25519_point(self) -> None:
        """
        Validate Ed25519 public key is a valid curve point (NOT small-order).

        CONSENSUS-CRITICAL: This validation MUST be consistent across all modes
        that use Ed25519 (ED25519_ONLY and HYBRID).

        Ed25519 VALIDATION POLICY (HONEST Chain v1.0):
        - Uses libsodium >=1.0.18 crypto_core_ed25519_is_valid_point
        - libsodium's is_valid_point ALREADY REJECTS all 8 small-order (torsion) points:
          * Identity (0x00...)
          * Order 4 points (0x01..., 0xed...)
          * Order 8 points (0xec..., 0xee..., 0xc7..., 0x26...)
        - Verified at RUNTIME via require_libsodium_validation() self-test
        - All nodes MUST use compatible libsodium builds (>=1.0.18)

        LIBSODIUM TORSION HANDLING:
        crypto_core_ed25519_is_valid_point returns false for:
        1. Non-canonical encodings (y >= p)
        2. Points not on the curve
        3. All 8 small-order points (torsion subgroup)
        This is the complete rejection - no additional hardcoded list needed.

        Raises:
            InvalidContainer: If point validation unavailable or key invalid
            LibsodiumValidationError: If libsodium self-test fails
        """
        # CONSENSUS-CRITICAL: Ensure libsodium has been validated (runs once per process)
        require_libsodium_validation()

        try:
            from nacl.bindings import crypto_core_ed25519_is_valid_point
        except ImportError:
            raise InvalidContainer(
                "Ed25519 point validation requires nacl.bindings.crypto_core_ed25519_is_valid_point. "
                "Upgrade PyNaCl to >=1.5.0 with libsodium >=1.0.18 support."
            )

        if not crypto_core_ed25519_is_valid_point(self.ed25519_pk):
            raise InvalidContainer(
                f"{self.alg_id.name}: Ed25519 PK is not a valid curve point "
                f"(includes small-order/torsion rejection)"
            )

    def serialize(self) -> bytes:
        """
        Serialize container to bytes.

        Returns:
            Serialized container bytes
        """
        dil_pk_len = len(self.dilithium_pk)
        dil_sig_len = len(self.dilithium_sig)

        header = bytearray()
        header.extend(MAGIC)  # 4 bytes
        header.append(VERSION)  # 1 byte
        header.append(int(self.alg_id))  # 1 byte - explicit int for consensus safety
        header.extend(self.chain_id.to_bytes(8, 'little'))  # 8 bytes
        header.append(int(self.object_type))  # 1 byte - explicit int for consensus safety
        header.append(self.tx_version)  # 1 byte
        header.extend(self.ed25519_pk)  # 32 bytes
        header.extend(self.ed25519_sig)  # 64 bytes
        header.extend(dil_pk_len.to_bytes(2, 'little'))  # 2 bytes
        header.extend(dil_sig_len.to_bytes(2, 'little'))  # 2 bytes

        # Validate header size (CRITICAL - do not use assert)
        if len(header) != HEADER_SIZE:
            raise InvalidContainer(
                f"Header size {len(header)} != expected {HEADER_SIZE}"
            )

        # Add Dilithium data
        data = bytes(header) + self.dilithium_pk + self.dilithium_sig

        # Validate total size (CRITICAL - do not use assert)
        expected_size = CONTAINER_SIZES[self.alg_id]
        if len(data) != expected_size:
            raise InvalidContainer(
                f"Container size {len(data)} != expected {expected_size}"
            )

        return data

    @classmethod
    def deserialize(
        cls,
        data: bytes,
        require_pq_safe: bool = True
    ) -> 'SignatureContainer':
        """
        Deserialize container from bytes.

        Per spec §3.4 validation pseudocode.

        QUANTUM-PROOF ENFORCEMENT: Default require_pq_safe=True enforces
        post-quantum algorithms (ML-DSA-only or HYBRID) for 2000-year security.
        Explicitly pass require_pq_safe=False only for non-consensus operations.

        NOTE: For CONSENSUS operations, use deserialize_consensus() which
        enforces ML-DSA-only (no HYBRID) for Ed25519 determinism safety.

        Args:
            data: Serialized container bytes
            require_pq_safe: If True (default), reject algorithms without ML-DSA
                            component (ED25519_ONLY rejected). Allows ML-DSA-only
                            and HYBRID. Set to False ONLY for non-consensus.

        Returns:
            SignatureContainer instance

        Raises:
            InvalidContainer: If container format is invalid or PQ requirement violated
        """
        # CONSENSUS-CRITICAL: Require crypto selftest before any deserialization
        # This ensures libsodium, Dilithium KAT, and constants are validated
        require_crypto_selftest()

        # BOUNDS CHECK 1: Minimum header size
        if len(data) < HEADER_SIZE:
            raise InvalidContainer(f"Too short: {len(data)} < {HEADER_SIZE}")

        # Parse header
        if data[0:4] != MAGIC:
            raise InvalidContainer(f"Invalid MAGIC: {data[0:4].hex()}")

        version = data[4]
        if version != VERSION:
            raise InvalidContainer(f"Unknown VERSION: {version}")

        alg_id_val = data[5]
        try:
            alg_id = AlgorithmID(alg_id_val)
        except ValueError:
            raise InvalidContainer(f"Unknown ALG_ID: {alg_id_val:#x}")

        # PQ enforcement: reject non-PQ-safe algorithms if required
        if require_pq_safe and alg_id not in PQ_SAFE_ALGORITHMS:
            raise InvalidContainer(
                f"require_pq_safe=True: {alg_id.name} is not post-quantum safe. "
                f"Use ML_DSA_* or HYBRID_* for quantum-proof security."
            )

        # BOUNDS CHECK 2: Exact expected size
        expected_size = CONTAINER_SIZES[alg_id]
        if len(data) != expected_size:
            raise InvalidContainer(f"Size {len(data)} != expected {expected_size}")

        chain_id = int.from_bytes(data[6:14], 'little')

        object_type_val = data[14]
        try:
            object_type = ObjectType(object_type_val)
        except ValueError:
            raise InvalidContainer(f"Unknown OBJECT_TYPE: {object_type_val}")

        tx_version = data[15]
        ed25519_pk = data[16:48]
        ed25519_sig = data[48:112]

        pk_len = int.from_bytes(data[112:114], 'little')
        sig_len = int.from_bytes(data[114:116], 'little')

        # BOUNDS CHECK 3: Length fields match expected
        expected_pk_len, expected_sig_len = DILITHIUM_SIZES[alg_id]
        if pk_len != expected_pk_len:
            raise InvalidContainer(f"DIL_PK_LEN {pk_len} != expected {expected_pk_len}")
        if sig_len != expected_sig_len:
            raise InvalidContainer(f"DIL_SIG_LEN {sig_len} != expected {expected_sig_len}")

        # BOUNDS CHECK 4: Explicit trailing bytes check (prevents parsing bugs)
        computed_size = HEADER_SIZE + pk_len + sig_len
        if computed_size != expected_size:
            raise InvalidContainer(
                f"Computed size {computed_size} != expected {expected_size}"
            )

        dilithium_pk = data[116:116+pk_len] if pk_len > 0 else b''
        dilithium_sig = data[116+pk_len:116+pk_len+sig_len] if sig_len > 0 else b''

        return cls(
            alg_id=alg_id,
            chain_id=chain_id,
            object_type=object_type,
            tx_version=tx_version,
            ed25519_pk=ed25519_pk,
            ed25519_sig=ed25519_sig,
            dilithium_pk=dilithium_pk,
            dilithium_sig=dilithium_sig,
        )

    def verify(
        self,
        signing_input: bytes,
        require_pq_safe: bool = True
    ) -> bool:
        """
        Verify container signatures.

        Per spec §3.3/§3.4:
        - ED25519_ONLY: Ed25519 must verify
        - ML-DSA-*: ML-DSA must verify, Ed25519 must be zeros
        - HYBRID: BOTH must verify

        QUANTUM-PROOF ENFORCEMENT: Default require_pq_safe=True enforces
        post-quantum algorithms (ML-DSA-only or HYBRID) for 2000-year security.
        Explicitly pass require_pq_safe=False only for non-consensus operations.

        NOTE: For CONSENSUS operations, use verify_consensus() which enforces
        ML-DSA-only (no HYBRID) for Ed25519 determinism safety.

        Args:
            signing_input: 64-byte SHAKE256 output (SIGNING_INPUT per §4.3)
            require_pq_safe: If True (default), reject non-PQ-safe algorithms.
                            Allows ML-DSA-only and HYBRID algorithms.
                            Set to False ONLY for non-consensus operations.

        Returns:
            True if valid

        Raises:
            InvalidContainer: If container violates format rules, signing_input wrong size,
                             or PQ requirement violated
            InvalidSignature: If signature verification fails
        """
        # CONSENSUS-CRITICAL: Require crypto selftest before any verification
        # This ensures libsodium, Dilithium KAT, and constants are validated
        require_crypto_selftest()

        # PQ enforcement: reject non-PQ-safe algorithms if required
        if require_pq_safe and self.alg_id not in PQ_SAFE_ALGORITHMS:
            raise InvalidContainer(
                f"require_pq_safe=True: {self.alg_id.name} is not post-quantum safe. "
                f"Use ML_DSA_* or HYBRID_* for quantum-proof security."
            )

        # Enforce exact signing_input length for cross-implementation consistency
        if len(signing_input) != 64:
            raise InvalidContainer(
                f"signing_input must be exactly 64 bytes, got {len(signing_input)}"
            )

        if self.alg_id == AlgorithmID.ED25519_ONLY:
            return self._verify_ed25519(signing_input)

        elif self.alg_id in (AlgorithmID.ML_DSA_65, AlgorithmID.ML_DSA_87):
            # Ed25519 fields must be zeros
            if self.ed25519_pk != bytes(ED25519_PK_SIZE):
                raise InvalidContainer("Ed25519 PK must be zeros for ML-DSA-only")
            if self.ed25519_sig != bytes(ED25519_SIG_SIZE):
                raise InvalidContainer("Ed25519 SIG must be zeros for ML-DSA-only")
            return self._verify_ml_dsa(signing_input)

        elif self.alg_id in (
            AlgorithmID.HYBRID_ED25519_DILITHIUM3,
            AlgorithmID.HYBRID_ED25519_DILITHIUM5
        ):
            # BOTH must verify (spec §3.3 normative rule)
            ed_ok = self._verify_ed25519(signing_input)
            dil_ok = self._verify_ml_dsa(signing_input)
            return ed_ok and dil_ok

        raise InvalidContainer(f"Unknown ALG_ID: {self.alg_id}")

    # Ed25519 curve order L (2^252 + 27742317777372353535851937790883648493)
    # Used for signature malleability check (S must be < L)
    _ED25519_L = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED

    def _check_ed25519_signature_canonical(self, sig: bytes) -> None:
        """
        Verify Ed25519 signature is fully canonical (R valid + not torsion, S < L).

        CONSENSUS-CRITICAL: This check ensures deterministic acceptance across
        all nodes, regardless of libsodium version. We check:
        1. R (first 32 bytes) is a valid curve point AND not small-order
        2. S (second 32 bytes) is < L (curve order)

        R TORSION REJECTION:
        libsodium's crypto_core_ed25519_is_valid_point already rejects all 8
        small-order points. This provides complete torsion rejection for R,
        matching our public key validation policy.

        Args:
            sig: 64-byte Ed25519 signature (R || S, each 32 bytes)

        Raises:
            InvalidSignature: If R not valid point, R is torsion, or S >= L
            LibsodiumValidationError: If libsodium self-test fails
        """
        # CONSENSUS-CRITICAL: Ensure libsodium has been validated (runs once per process)
        # This is NOT an ordering dependency - each method that uses libsodium
        # independently ensures validation has occurred.
        require_libsodium_validation()

        if len(sig) != 64:
            raise InvalidSignature(f"Ed25519 sig must be 64 bytes, got {len(sig)}")

        # Extract R (first 32 bytes) - must be valid curve point (rejects torsion)
        r_bytes = sig[0:32]
        try:
            from nacl.bindings import crypto_core_ed25519_is_valid_point
        except ImportError:
            raise InvalidSignature(
                "Ed25519 signature R validation requires nacl.bindings.crypto_core_ed25519_is_valid_point"
            )

        # is_valid_point returns false for:
        # 1. Non-canonical encodings (y >= p)
        # 2. Points not on the curve
        # 3. All 8 small-order points (torsion subgroup)
        if not crypto_core_ed25519_is_valid_point(r_bytes):
            raise InvalidSignature(
                "Ed25519 signature non-canonical: R is not a valid curve point "
                "(includes small-order/torsion rejection)"
            )

        # Extract S (second 32 bytes, little-endian) - must be < L
        s_bytes = sig[32:64]
        s = int.from_bytes(s_bytes, 'little')

        if s >= self._ED25519_L:
            raise InvalidSignature(
                "Ed25519 signature non-canonical: S >= L (malleable)"
            )

    def _verify_ed25519(self, signing_input: bytes) -> bool:
        """Verify Ed25519 signature with malleability and point validity checks."""
        # CONSENSUS-CRITICAL: Re-validate Ed25519 public key point at verification time
        # This protects against bypass of __post_init__ invariants
        self._validate_ed25519_point()

        # Check signature canonicality BEFORE calling libsodium
        self._check_ed25519_signature_canonical(self.ed25519_sig)

        try:
            verify_key = nacl.signing.VerifyKey(self.ed25519_pk)
            verify_key.verify(signing_input, self.ed25519_sig)
            return True
        except nacl.exceptions.BadSignature:
            raise InvalidSignature("Ed25519 verification failed")
        except Exception as e:
            raise InvalidSignature(f"Ed25519 error: {e}")

    def _verify_ml_dsa(self, signing_input: bytes) -> bool:
        """
        Verify ML-DSA signature.

        CONSENSUS-CRITICAL: Ensures KAT validation has been run before
        accepting any ML-DSA signature. This guarantees the backend
        produces expected outputs for consensus determinism.
        """
        # Ensure KAT has been validated (idempotent, runs once per process)
        # This is CONSENSUS-CRITICAL: nodes MUST verify backend correctness
        require_kat_validation()

        level = ML_DSA_LEVEL.get(self.alg_id)
        if level is None:
            raise InvalidContainer(f"No ML-DSA level for {self.alg_id}")

        if not ml_dsa_verify(
            self.dilithium_pk,
            signing_input,
            self.dilithium_sig,
            level
        ):
            raise InvalidSignature("ML-DSA verification failed")
        return True

    # =========================================================================
    # CONSENSUS-SAFE APIs
    # =========================================================================
    # These methods HARD-ENFORCE quantum-proof algorithms with NO override option.
    # Use these for all consensus-critical operations to prevent accidental
    # acceptance of non-PQ-safe containers.

    @classmethod
    def deserialize_consensus(cls, data: bytes) -> 'SignatureContainer':
        """
        Deserialize container for consensus operations (ML-DSA-only enforced).

        CONSENSUS-CRITICAL: This method HARD-ENFORCES ML-DSA-only algorithms.
        HYBRID containers are REJECTED because Ed25519 verification determinism
        cannot be guaranteed across libsodium versions/builds.

        EARLY REJECTION: ALG_ID is checked BEFORE full parsing to avoid
        executing Ed25519 validation code for non-consensus containers.

        CONSENSUS RULE (NORMATIVE - all implementations MUST enforce):
        1. Only ML_DSA_65 and ML_DSA_87 algorithm IDs are allowed
        2. Dilithium public key MUST NOT be all zeros
        3. Dilithium signature MUST NOT be all zeros

        Rule #2 and #3 prevent DoS attacks via trivial-to-construct containers
        that are expensive to verify. All HONEST Chain implementations MUST
        reject all-zero pk/sig at deserialization time, NOT just at verify time.
        This is a CONSENSUS VALIDITY RULE, not an optimization.

        For non-consensus operations (testing, migration, legacy tools), use
        deserialize() with require_pq_safe=False.

        Args:
            data: Serialized container bytes

        Returns:
            SignatureContainer instance (guaranteed ML-DSA-only algorithm)

        Raises:
            CryptoSelftestNotRunError: If crypto_selftest_or_die() has not been called
            InvalidContainer: If format invalid, algorithm is not ML-DSA-only,
                             or Dilithium pk/sig is all zeros
        """
        # CONSENSUS-CRITICAL: Ensure crypto_selftest_or_die() has been called
        require_crypto_selftest()

        # EARLY REJECTION: Check header fields BEFORE full parsing
        # This avoids running Ed25519 validation for attacker-provided containers
        if len(data) < HEADER_SIZE:
            raise InvalidContainer(f"Too short: {len(data)} < {HEADER_SIZE}")

        if data[0:4] != MAGIC:
            raise InvalidContainer(f"Invalid MAGIC: {data[0:4].hex()}")

        version = data[4]
        if version != VERSION:
            raise InvalidContainer(f"Unknown VERSION: {version}")

        alg_id_val = data[5]
        try:
            alg_id = AlgorithmID(alg_id_val)
        except ValueError:
            raise InvalidContainer(f"Unknown ALG_ID: {alg_id_val:#x}")

        # EARLY CHECK: Reject non-consensus algorithms before Ed25519 validation
        if alg_id not in CONSENSUS_SAFE_ALGORITHMS:
            raise InvalidContainer(
                f"Consensus requires ML-DSA-only: {alg_id.name} is not allowed. "
                f"HYBRID containers are excluded from consensus due to Ed25519 "
                f"verification determinism concerns. Use ML_DSA_65 or ML_DSA_87."
            )

        # EARLY CHECK: Verify container has correct total length for this alg_id
        expected_size = CONTAINER_SIZES[alg_id]
        if len(data) != expected_size:
            raise InvalidContainer(
                f"Wrong size for {alg_id.name}: got {len(data)}, expected {expected_size}"
            )

        # Parse remaining header fields
        chain_id = int.from_bytes(data[6:14], 'little')

        object_type_val = data[14]
        try:
            object_type = ObjectType(object_type_val)
        except ValueError:
            raise InvalidContainer(f"Unknown OBJECT_TYPE: {object_type_val}")

        tx_version = data[15]
        ed25519_pk = data[16:48]
        ed25519_sig = data[48:112]

        # CONSENSUS RULE: For ML-DSA-only, Ed25519 fields MUST be all-zero
        # This is enforced early to fail fast and reduce attack surface
        if ed25519_pk != bytes(ED25519_PK_SIZE):
            raise InvalidContainer(
                "Consensus: Ed25519 public key must be all-zero for ML-DSA-only algorithms"
            )
        if ed25519_sig != bytes(ED25519_SIG_SIZE):
            raise InvalidContainer(
                "Consensus: Ed25519 signature must be all-zero for ML-DSA-only algorithms"
            )

        # Validate length fields match expected
        pk_len_field = int.from_bytes(data[112:114], 'little')
        sig_len_field = int.from_bytes(data[114:116], 'little')
        expected_pk_len, expected_sig_len = DILITHIUM_SIZES[alg_id]

        if pk_len_field != expected_pk_len:
            raise InvalidContainer(f"DIL_PK_LEN {pk_len_field} != expected {expected_pk_len}")
        if sig_len_field != expected_sig_len:
            raise InvalidContainer(f"DIL_SIG_LEN {sig_len_field} != expected {expected_sig_len}")

        # Extract Dilithium pk/sig
        dilithium_pk = data[HEADER_SIZE:HEADER_SIZE + expected_pk_len]
        dilithium_sig = data[HEADER_SIZE + expected_pk_len:HEADER_SIZE + expected_pk_len + expected_sig_len]

        # CONSENSUS RULE: Verify Dilithium pk/sig are non-zero (DoS protection)
        # All-zero pk/sig would be cheap to construct but expensive to verify
        if dilithium_pk == bytes(expected_pk_len):
            raise InvalidContainer(
                "Consensus: Dilithium public key is all zeros (DoS protection)"
            )

        if dilithium_sig == bytes(expected_sig_len):
            raise InvalidContainer(
                "Consensus: Dilithium signature is all zeros (DoS protection)"
            )

        # SELF-CONTAINED: Create container directly without calling general deserialize()
        # This avoids any footgun risk from the general API
        return cls(
            alg_id=alg_id,
            chain_id=chain_id,
            object_type=object_type,
            tx_version=tx_version,
            ed25519_pk=ed25519_pk,
            ed25519_sig=ed25519_sig,
            dilithium_pk=dilithium_pk,
            dilithium_sig=dilithium_sig,
        )

    def verify_consensus(self, signing_input: bytes) -> bool:
        """
        Verify container for consensus operations (ML-DSA-only enforced).

        CONSENSUS-CRITICAL: This method HARD-ENFORCES ML-DSA-only algorithms.
        HYBRID containers are REJECTED because Ed25519 verification determinism
        cannot be guaranteed across libsodium versions/builds.

        CONSENSUS RULE (NORMATIVE - all implementations MUST enforce):
        1. Only ML_DSA_65 and ML_DSA_87 algorithm IDs are allowed
        2. Dilithium public key MUST NOT be all zeros
        3. Dilithium signature MUST NOT be all zeros

        Rule #2 and #3 prevent DoS attacks via trivial-to-construct containers
        that are expensive to verify. This check is duplicated from
        deserialize_consensus() because verify_consensus() may be called on
        containers created via other code paths. Both checks are REQUIRED.

        For non-consensus operations (testing, migration, legacy tools), use
        verify() with require_pq_safe=False.

        Args:
            signing_input: 64-byte SHAKE256 output (SIGNING_INPUT per §4.3)

        Returns:
            True if valid

        Raises:
            CryptoSelftestNotRunError: If crypto_selftest_or_die() has not been called
            InvalidContainer: If algorithm is not ML-DSA-only or pk/sig is zero
            InvalidSignature: If signature verification fails
        """
        # CONSENSUS-CRITICAL: Ensure crypto_selftest_or_die() has been called
        require_crypto_selftest()

        # Check: consensus requires ML-DSA-only, not HYBRID
        if self.alg_id not in CONSENSUS_SAFE_ALGORITHMS:
            raise InvalidContainer(
                f"Consensus requires ML-DSA-only: {self.alg_id.name} is not allowed. "
                f"HYBRID containers are excluded from consensus due to Ed25519 "
                f"verification determinism concerns. Use ML_DSA_65 or ML_DSA_87."
            )

        # DoS protection: reject all-zero Dilithium pk/sig
        # This check is independent of deserialize_consensus() because
        # verify_consensus() may be called on containers created other ways
        pk_len, sig_len = DILITHIUM_SIZES[self.alg_id]
        if self.dilithium_pk == bytes(pk_len):
            raise InvalidContainer(
                "Consensus: Dilithium public key is all zeros (DoS protection)"
            )
        if self.dilithium_sig == bytes(sig_len):
            raise InvalidContainer(
                "Consensus: Dilithium signature is all zeros (DoS protection)"
            )

        return self.verify(signing_input, require_pq_safe=False)


# Signing input constants (spec §4.3)
# MESSAGE_HASH uses SHA3-256 (FIPS 202), producing 32 bytes
MESSAGE_HASH_ALG = "SHA3-256"
MESSAGE_HASH_SIZE = 32

# SIGNING_INPUT uses SHAKE256 (FIPS 202 XOF), producing 64 bytes
SIGNING_INPUT_XOF = "SHAKE256"
SIGNING_INPUT_SIZE = 64


def _compute_signing_input_unchecked(
    object_bytes: bytes,
    chain_id: int,
    object_type: ObjectType,
    tx_version: int,
    alg_id: AlgorithmID,
    max_object_size: int = 10 * 1024 * 1024  # 10 MB default limit
) -> bytes:
    """
    Internal: Compute SIGNING_INPUT without latch check.

    INTERNAL USE ONLY: This function is called by validate_signing_input_vectors()
    during crypto_selftest_or_die(). The public compute_signing_input() wraps
    this with a latch check.

    See compute_signing_input() for full documentation.
    """
    # Accept any bytes-like object and normalize to bytes for deterministic hashing
    # This allows bytearray, memoryview, and other buffer protocol objects
    if isinstance(object_bytes, (bytes, bytearray, memoryview)):
        object_bytes = bytes(object_bytes)
    else:
        raise ContainerError(
            f"object_bytes must be bytes-like, got {type(object_bytes).__name__}"
        )

    # DoS protection: limit object size
    if max_object_size > 0 and len(object_bytes) > max_object_size:
        raise ContainerError(
            f"object_bytes size {len(object_bytes)} exceeds max {max_object_size}"
        )

    # Validate chain_id (uint64)
    if not isinstance(chain_id, int) or chain_id < 0 or chain_id > 0xFFFFFFFFFFFFFFFF:
        raise ContainerError(
            f"chain_id must be uint64 (0 to 2^64-1), got {chain_id}"
        )

    # Validate tx_version (uint8)
    if not isinstance(tx_version, int) or tx_version < 0 or tx_version > 255:
        raise ContainerError(
            f"tx_version must be uint8 (0-255), got {tx_version}"
        )

    # Validate object_type is valid enum
    if not isinstance(object_type, ObjectType):
        raise ContainerError(
            f"object_type must be ObjectType enum, got {type(object_type)}"
        )
    if object_type not in DOMAIN_SEPARATORS:
        raise ContainerError(f"Unknown object_type: {object_type}")

    # Validate alg_id is valid enum and in uint8 range
    if not isinstance(alg_id, AlgorithmID):
        raise ContainerError(
            f"alg_id must be AlgorithmID enum, got {type(alg_id)}"
        )
    # Explicit range check for future-proofing (even though IntEnum values are small)
    alg_id_int = int(alg_id)
    if alg_id_int < 0 or alg_id_int > 255:
        raise ContainerError(
            f"alg_id must be uint8 (0-255), got {alg_id_int}"
        )

    # MESSAGE_HASH = SHA3-256(OBJECT_BYTES)
    message_hash = hashlib.sha3_256(object_bytes).digest()

    # DOMAIN_SEPARATOR
    domain_sep = DOMAIN_SEPARATORS[object_type]

    # INPUT_BYTES - use explicit int().to_bytes() for deterministic encoding
    # (bytes([x]) can behave unexpectedly with non-int types)
    input_bytes = (
        domain_sep +
        chain_id.to_bytes(8, 'little') +
        int(object_type).to_bytes(1, 'little') +
        tx_version.to_bytes(1, 'little') +
        alg_id_int.to_bytes(1, 'little') +
        message_hash
    )

    # SHAKE256(INPUT_BYTES, 64)
    shake = hashlib.shake_256()
    shake.update(input_bytes)
    return shake.digest(64)


def compute_signing_input(
    object_bytes: bytes,
    chain_id: int,
    object_type: ObjectType,
    tx_version: int,
    alg_id: AlgorithmID,
    max_object_size: int = 10 * 1024 * 1024  # 10 MB default limit
) -> bytes:
    """
    Compute SIGNING_INPUT per spec §4.3.

    CRYPTOGRAPHIC HASH ALGORITHMS:
    - MESSAGE_HASH = SHA3-256(object_bytes) → 32 bytes
    - SIGNING_INPUT = SHAKE256(input_bytes, 64) → 64 bytes

    SIGNING_INPUT = SHAKE256(
        DOMAIN_SEPARATOR || CHAIN_ID(8 LE) || OBJECT_TYPE(1) ||
        TX_VERSION(1) || ALG_ID(1) || MESSAGE_HASH(32),
        64
    )

    Args:
        object_bytes: Canonical serialization of object (TX/BLOCK/IDENTITY).
                      Accepts bytes, bytearray, or memoryview (normalized to bytes).
        chain_id: Chain ID (uint64, 0 to 2^64-1, little-endian encoding)
        object_type: Object type enum
        tx_version: Transaction version (uint8, 0-255)
        alg_id: Algorithm ID enum
        max_object_size: Maximum allowed size of object_bytes in bytes.
                         Default 10 MB. Set to 0 to disable check.

    Returns:
        64-byte signing input (SHAKE256 output)

    Raises:
        CryptoSelftestNotRunError: If crypto_selftest_or_die() has not been called
        ContainerError: If inputs are out of valid ranges or wrong types
    """
    # CONSENSUS-CRITICAL: Ensure crypto_selftest_or_die() has been called
    # This validates hash backends and constants before we use them
    require_crypto_selftest()

    return _compute_signing_input_unchecked(
        object_bytes=object_bytes,
        chain_id=chain_id,
        object_type=object_type,
        tx_version=tx_version,
        alg_id=alg_id,
        max_object_size=max_object_size,
    )


# Test vectors for compute_signing_input (spec §4.3)
# NORMATIVE: Implementation MUST reproduce these exactly
# Vectors cover: all ObjectTypes, multiple AlgorithmIDs, edge cases
SIGNING_INPUT_TEST_VECTORS = {
    # Basic vector: TRANSACTION + ED25519_ONLY
    'vector_1_tx_ed25519': {
        'object_bytes': b'test_object',
        'chain_id': 1,
        'object_type': 0x01,  # TRANSACTION
        'tx_version': 1,
        'alg_id': 0x01,  # ED25519_ONLY
        'expected': '240b0cebedd183b32fbdbcfd670fcf47dcc284f04dc410b77090d7c4f3eb76388ef06204f219b97ac04d4aefc92063eae0b1e4908e21f3fd40aef7d033ceff2c',
    },
    # BLOCK object type
    'vector_2_block': {
        'object_bytes': b'block_data',
        'chain_id': 1,
        'object_type': 0x02,  # BLOCK
        'tx_version': 1,
        'alg_id': 0x01,  # ED25519_ONLY
        'expected': 'd289427a2e8d6aaed7b99f1d93caac6a12a0fccc051bfb4090c1050b0b8532447565ec0cd43f350a46c658f5a157b0b78e7e54f8494cded4cf513d26bfcf95fb',
    },
    # IDENTITY object type
    'vector_3_identity': {
        'object_bytes': b'identity_data',
        'chain_id': 1,
        'object_type': 0x03,  # IDENTITY
        'tx_version': 1,
        'alg_id': 0x01,  # ED25519_ONLY
        'expected': 'a954c100ea18c368dd7779ca86f682ad93cf9f116036c214e8a0122f4f7e409705ccae861f6203bfb3294a05d65d8ab0fc7d852facee00d4e6c91a7d387bfa1d',
    },
    # ML_DSA_65 algorithm
    'vector_4_ml_dsa_65': {
        'object_bytes': b'test_object',
        'chain_id': 1,
        'object_type': 0x01,  # TRANSACTION
        'tx_version': 1,
        'alg_id': 0x02,  # ML_DSA_65
        'expected': 'fc8bb966eecc37d6eec2ddbf040364689ba997e18f8e44159c801c749c04b5a5392cb627aae1f0e813486646fd4be19c4827767cf641ce20ec90ff62135aef45',
    },
    # HYBRID_ED25519_DILITHIUM3
    'vector_5_hybrid': {
        'object_bytes': b'test_object',
        'chain_id': 1,
        'object_type': 0x01,  # TRANSACTION
        'tx_version': 1,
        'alg_id': 0x10,  # HYBRID_ED25519_DILITHIUM3
        'expected': '58cf62714758cf462fb89d10ddb96ce27613e82cddab939839bcfa52172b6d5431f0b6f98d2de4bae46147304e3f9e5b98b9c8086534bcc76a847f5a3086d53f',
    },
    # Edge case: empty object_bytes
    'vector_6_empty_object': {
        'object_bytes': b'',
        'chain_id': 1,
        'object_type': 0x01,  # TRANSACTION
        'tx_version': 1,
        'alg_id': 0x01,  # ED25519_ONLY
        'expected': 'cbb0776980b6a95c870f446c6d7efe2360d9ab8296a2ba0789eb11bac84aea9df1f9eafa1feae307a4e5e8dc24325f4e8b21f82d281f63d650d09761558df6ec',
    },
    # Edge case: large chain_id (uint64_max - 1)
    'vector_7_large_chain_id': {
        'object_bytes': b'test',
        'chain_id': 0xFFFFFFFFFFFFFFFE,
        'object_type': 0x01,  # TRANSACTION
        'tx_version': 1,
        'alg_id': 0x01,  # ED25519_ONLY
        'expected': '9426d1729d49b3f71d41b5808bdd75b23cd4587a2c0e6d94509e6690dc97b1e93b6c9f5ba40c4eb99785ffcf7f4a3b1e30b0c0f2efbd154650b791737f8aa506',
    },
    # Edge case: tx_version = 255
    'vector_8_tx_version_max': {
        'object_bytes': b'test',
        'chain_id': 1,
        'object_type': 0x01,  # TRANSACTION
        'tx_version': 255,
        'alg_id': 0x01,  # ED25519_ONLY
        'expected': 'eaab9fe9b72e4e2a840e03eb3d828b8ea9ad69a0e2eb23e06bc10712fdd6be6e75165d7ffe0d9403c96db7fd129f65a8f105c77a095f33e6d503657ea461e838',
    },
}


class SigningInputVectorError(ContainerError):
    """compute_signing_input test vector mismatch."""
    pass


def validate_signing_input_vectors() -> bool:
    """
    Validate signing input computation against test vectors.

    INTERNAL: Uses _compute_signing_input_unchecked() because this function
    is called during crypto_selftest_or_die() before the latch is set.

    Returns:
        True if all vectors match

    Raises:
        SigningInputVectorError: If any vector does not match
    """
    for name, vec in SIGNING_INPUT_TEST_VECTORS.items():
        result = _compute_signing_input_unchecked(
            object_bytes=vec['object_bytes'],
            chain_id=vec['chain_id'],
            object_type=ObjectType(vec['object_type']),
            tx_version=vec['tx_version'],
            alg_id=AlgorithmID(vec['alg_id'])
        )
        expected = vec['expected']
        actual = result.hex()
        if actual != expected:
            raise SigningInputVectorError(
                f"Vector {name} mismatch: got {actual}, expected {expected}"
            )
    return True


class HashBackendError(CryptoSelftestError):
    """Hash backend (SHA3/SHAKE) validation failed."""
    pass


# NIST test vectors for SHA3-256 and SHAKE256
# Source: NIST FIPS 202 test vectors
HASH_TEST_VECTORS = {
    # SHA3-256 (NIST FIPS 202)
    'sha3_256_empty': {
        'input': b'',
        'expected': 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a',
    },
    'sha3_256_abc': {
        'input': b'abc',
        'expected': '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
    },
    # SHAKE256 with 64-byte output (matches SIGNING_INPUT_SIZE)
    'shake256_empty_64': {
        'input': b'',
        'output_len': 64,
        'expected': '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
                    'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be',
    },
    'shake256_abc_64': {
        'input': b'abc',
        'output_len': 64,
        'expected': '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739'
                    'd5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4',
    },
}


def validate_hash_backends() -> bool:
    """
    Validate SHA3-256 and SHAKE256 backends against NIST test vectors.

    CONSENSUS-CRITICAL: These hash functions are used in SIGNING_INPUT
    computation. Any deviation from NIST FIPS 202 would cause consensus splits.

    Returns:
        True if all vectors match

    Raises:
        HashBackendError: If any vector does not match or hash unavailable
    """
    import hashlib

    # Test SHA3-256
    for name in ['sha3_256_empty', 'sha3_256_abc']:
        vec = HASH_TEST_VECTORS[name]
        try:
            result = hashlib.sha3_256(vec['input']).hexdigest()
        except Exception as e:
            raise HashBackendError(
                f"SHA3-256 unavailable: {type(e).__name__}: {e}"
            ) from e

        if result != vec['expected']:
            raise HashBackendError(
                f"SHA3-256 vector {name} mismatch: got {result}, "
                f"expected {vec['expected']}"
            )

    # Test SHAKE256
    for name in ['shake256_empty_64', 'shake256_abc_64']:
        vec = HASH_TEST_VECTORS[name]
        try:
            shake = hashlib.shake_256()
            shake.update(vec['input'])
            result = shake.digest(vec['output_len']).hex()
        except Exception as e:
            raise HashBackendError(
                f"SHAKE256 unavailable: {type(e).__name__}: {e}"
            ) from e

        if result != vec['expected']:
            raise HashBackendError(
                f"SHAKE256 vector {name} mismatch: got {result}, "
                f"expected {vec['expected']}"
            )

    return True


def _compute_constants_fingerprint() -> str:
    """
    Compute a fingerprint of ALL consensus-critical constants and test vectors.

    This fingerprint is stored in the attestation and checked by
    require_crypto_selftest() to detect runtime mutation.

    Covers:
    - Wire format constants (MAGIC, VERSION, sizes)
    - Algorithm policy sets
    - Domain separators
    - Hash algorithm constants
    - Normative test vectors (HASH_TEST_VECTORS, SIGNING_INPUT_TEST_VECTORS)

    Returns:
        Hex string of SHA3-256 hash of canonical representation
    """
    import hashlib
    import json
    from .constants import (
        MAGIC, VERSION, CONTAINER_SIZES, DILITHIUM_SIZES,
        DOMAIN_SEPARATORS, CONSENSUS_SAFE_ALGORITHMS,
        PQ_SAFE_ALGORITHMS, ML_DSA_LEVEL, ML_DSA_ALGORITHMS,
        ED25519_PK_SIZE, ED25519_SIG_SIZE, HEADER_SIZE,
    )

    # Serialize ALL consensus-critical constants in canonical order
    data = {
        # Wire format constants
        'MAGIC': MAGIC.hex(),
        'VERSION': VERSION,
        'CONTAINER_SIZES': {str(k.value): v for k, v in sorted(CONTAINER_SIZES.items())},
        'DILITHIUM_SIZES': {str(k.value): list(v) for k, v in sorted(DILITHIUM_SIZES.items())},
        'DOMAIN_SEPARATORS': {str(k.value): v.hex() for k, v in sorted(DOMAIN_SEPARATORS.items())},
        'ED25519_PK_SIZE': ED25519_PK_SIZE,
        'ED25519_SIG_SIZE': ED25519_SIG_SIZE,
        'HEADER_SIZE': HEADER_SIZE,

        # Algorithm policy sets
        'CONSENSUS_SAFE_ALGORITHMS': sorted([a.value for a in CONSENSUS_SAFE_ALGORITHMS]),
        'PQ_SAFE_ALGORITHMS': sorted([a.value for a in PQ_SAFE_ALGORITHMS]),
        'ML_DSA_LEVEL': {str(k.value): v for k, v in sorted(ML_DSA_LEVEL.items())},
        'ML_DSA_ALGORITHMS': sorted([a.value for a in ML_DSA_ALGORITHMS]),

        # Hash algorithm constants
        'MESSAGE_HASH_ALG': MESSAGE_HASH_ALG,
        'MESSAGE_HASH_SIZE': MESSAGE_HASH_SIZE,
        'SIGNING_INPUT_XOF': SIGNING_INPUT_XOF,
        'SIGNING_INPUT_SIZE': SIGNING_INPUT_SIZE,

        # Normative test vectors (canonicalized to avoid bytes serialization issues)
        'HASH_TEST_VECTORS': {
            k: {
                'input': v['input'].hex(),  # Canonicalize bytes to hex
                'expected': v['expected'],
                **({'output_len': v['output_len']} if 'output_len' in v else {}),
            } for k, v in sorted(HASH_TEST_VECTORS.items())
        },
        'SIGNING_INPUT_TEST_VECTORS': {
            k: {
                'object_bytes': v['object_bytes'].hex(),
                'chain_id': v['chain_id'],
                'object_type': v['object_type'],
                'tx_version': v['tx_version'],
                'alg_id': v['alg_id'],
                'expected': v['expected'],
            } for k, v in sorted(SIGNING_INPUT_TEST_VECTORS.items())
        },
    }
    # NOTE: No default=str - all values must be JSON-serializable primitives
    # This ensures fail-closed behavior if any unexpected type sneaks in
    canonical = json.dumps(data, sort_keys=True).encode('utf-8')
    return hashlib.sha3_256(canonical).hexdigest()


def crypto_selftest_or_die() -> None:
    """
    Run all cryptographic self-tests and FAIL HARD on any error.

    CONSENSUS-CRITICAL: This function must be called by consensus nodes at
    startup BEFORE processing any blocks, transactions, or signatures.
    It validates:

    1. Hash backends (SHA3-256, SHAKE256) against NIST vectors
    2. Constants consistency (domain separators, container sizes)
    3. PyNaCl version requirements
    4. libsodium features and torsion rejection
    5. Dilithium KAT (verify-only)
    6. KDF test vectors
    7. Signing input test vectors

    THREAD-SAFETY: Uses double-checked locking to ensure selftest runs exactly
    once per process, even under concurrent calls.

    FAILED LATCH: If selftest fails, subsequent calls immediately raise the
    stored exception without re-running tests. This prevents non-deterministic
    retry behavior under failure conditions.

    ATTESTATION: Stores an immutable fingerprint of validated constants/runtime
    so that require_crypto_selftest() can detect runtime mutation.

    EXCEPTION HANDLING:
    This function catches all exceptions and converts them to CryptoSelftestError.
    Consensus code should branch on exception TYPE, not message strings.

    Raises:
        CryptoSelftestError: If any self-test fails (node must exit)
    """
    global _CRYPTO_SELFTEST_ATTESTATION, _CRYPTO_SELFTEST_FAILED_EXCEPTION

    # Fast path: already validated successfully
    if _CRYPTO_SELFTEST_EVENT.is_set():
        return

    # Fast path: already failed - raise stored exception
    if _CRYPTO_SELFTEST_FAILED_EVENT.is_set():
        raise _CRYPTO_SELFTEST_FAILED_EXCEPTION

    # Double-checked locking pattern
    with _CRYPTO_SELFTEST_LOCK:
        # Re-check after acquiring lock
        if _CRYPTO_SELFTEST_EVENT.is_set():
            return
        if _CRYPTO_SELFTEST_FAILED_EVENT.is_set():
            raise _CRYPTO_SELFTEST_FAILED_EXCEPTION

        from .kdf import validate_test_vectors as validate_kdf_vectors
        from .constants import validate_constants
        import sys

        try:
            # 1. Hash backends (SHA3-256, SHAKE256) - fundamental for all crypto
            validate_hash_backends()

            # 2. Constants validation (domain separators, container sizes)
            validate_constants()

            # 3. PyNaCl version check (diagnostic, features are primary)
            _check_pynacl_version()

            # 4. libsodium validation (explicit, not import-time)
            require_libsodium_validation()

            # 5. Dilithium KAT
            require_kat_validation()

            # 6. KDF test vectors
            validate_kdf_vectors()

            # 7. Signing input test vectors
            validate_signing_input_vectors()

            # 8. Compute attestation fingerprint as IMMUTABLE MappingProxyType
            # This prevents accidental/malicious mutation of attestation
            _CRYPTO_SELFTEST_ATTESTATION = _types.MappingProxyType({
                'constants_fingerprint': _compute_constants_fingerprint(),
                'python_version': sys.version,
            })

            # 9. All tests passed - set the latch for consensus API access
            _CRYPTO_SELFTEST_EVENT.set()

        except CryptoSelftestError as e:
            # Set failed latch to prevent retries
            _CRYPTO_SELFTEST_FAILED_EXCEPTION = e
            _CRYPTO_SELFTEST_FAILED_EVENT.set()
            raise
        except Exception as e:
            # Convert any exception to CryptoSelftestError for uniform handling
            exc = CryptoSelftestError(
                f"Cryptographic self-test failed: {type(e).__name__}: {e}"
            )
            exc.__cause__ = e
            # Set failed latch to prevent retries
            _CRYPTO_SELFTEST_FAILED_EXCEPTION = exc
            _CRYPTO_SELFTEST_FAILED_EVENT.set()
            raise exc from e
