"""
HONEST Chain - Cryptographic Algorithm Registry

Implements algorithm agility for 2000-year durability.
Allows protocol-level algorithm migration without hard forks.

Per GPT-5.2 recommendation:
    "Cryptographic agility is non-optional for 2000 years.
     Build a Crypto Registry into consensus rules."

GPT-5.2 REVIEWED: 2025-12-23
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Callable, Tuple
import hashlib
import time


class AlgorithmType(Enum):
    """Types of cryptographic algorithms."""
    SIGNATURE = auto()      # Digital signatures
    HASH = auto()           # Hash functions
    ENCRYPTION = auto()     # Symmetric encryption
    KDF = auto()            # Key derivation
    ZK = auto()             # Zero-knowledge proofs
    VRF = auto()            # Verifiable random functions


class SecurityLevel(Enum):
    """Security levels (bits of security)."""
    LEVEL_128 = 128         # Standard security
    LEVEL_192 = 192         # High security
    LEVEL_256 = 256         # Maximum security


@dataclass(frozen=True)
class Algorithm:
    """
    Immutable algorithm definition.

    Stored in the registry with validity windows
    for graceful migration.
    """
    # IDENTIFIER
    id: bytes                           # 4-byte unique ID
    name: str                           # Human-readable name
    algorithm_type: AlgorithmType       # Type of algorithm

    # SECURITY
    security_level: SecurityLevel       # Bits of security
    pq_safe: bool                       # Post-quantum safe?

    # VALIDITY
    valid_from_height: int = 0          # Block height start
    valid_until_height: int = 0         # Block height end (0 = no end)
    deprecated: bool = False            # Soft deprecation flag

    # PARAMETERS
    params: bytes = b""                 # Algorithm-specific parameters

    # METADATA
    specification_url: str = ""         # Link to specification
    notes: str = ""                     # Implementation notes

    def is_valid_at(self, height: int) -> bool:
        """Check if algorithm is valid at given block height."""
        if height < self.valid_from_height:
            return False
        if self.valid_until_height > 0 and height >= self.valid_until_height:
            return False
        return True

    def __hash__(self):
        return hash(self.id)


# ═══════════════════════════════════════════════════════════════════════════════
# PREDEFINED ALGORITHMS
# ═══════════════════════════════════════════════════════════════════════════════

# SIGNATURE ALGORITHMS
DILITHIUM3 = Algorithm(
    id=b"DL3\x00",
    name="ML-DSA-65 (Dilithium3)",
    algorithm_type=AlgorithmType.SIGNATURE,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=True,
    specification_url="https://pq-crystals.org/dilithium/",
    notes="NIST FIPS 204 standardized. Primary quantum-proof signature."
)

DILITHIUM5 = Algorithm(
    id=b"DL5\x00",
    name="ML-DSA-87 (Dilithium5)",
    algorithm_type=AlgorithmType.SIGNATURE,
    security_level=SecurityLevel.LEVEL_192,
    pq_safe=True,
    specification_url="https://pq-crystals.org/dilithium/",
    notes="NIST FIPS 204 standardized. Higher security variant."
)

SPHINCS_SHA3_256F = Algorithm(
    id=b"SPH\x00",
    name="SPHINCS+-SHA3-256f",
    algorithm_type=AlgorithmType.SIGNATURE,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=True,
    specification_url="https://sphincs.org/",
    notes="Hash-based signature. Emergency fallback if lattice crypto breaks."
)

ED25519 = Algorithm(
    id=b"E25\x00",
    name="Ed25519",
    algorithm_type=AlgorithmType.SIGNATURE,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=False,
    deprecated=True,  # Deprecated for new uses, valid for legacy
    notes="NOT quantum-safe. Only for legacy compatibility."
)

# HASH ALGORITHMS
SHA3_256 = Algorithm(
    id=b"S3H\x00",
    name="SHA3-256",
    algorithm_type=AlgorithmType.HASH,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=True,  # 128-bit security against Grover's algorithm
    specification_url="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf",
    notes="NIST FIPS 202. Primary hash function."
)

SHAKE256 = Algorithm(
    id=b"SHK\x00",
    name="SHAKE256",
    algorithm_type=AlgorithmType.HASH,
    security_level=SecurityLevel.LEVEL_256,
    pq_safe=True,
    specification_url="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf",
    notes="NIST FIPS 202. Extendable output function."
)

BLAKE3 = Algorithm(
    id=b"B3H\x00",
    name="BLAKE3",
    algorithm_type=AlgorithmType.HASH,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=True,
    specification_url="https://github.com/BLAKE3-team/BLAKE3-specs",
    notes="Fast, parallelizable. Alternative to SHA3."
)

# ENCRYPTION ALGORITHMS
CHACHA20_POLY1305 = Algorithm(
    id=b"CCP\x00",
    name="ChaCha20-Poly1305",
    algorithm_type=AlgorithmType.ENCRYPTION,
    security_level=SecurityLevel.LEVEL_256,
    pq_safe=True,  # 128-bit security against Grover
    specification_url="https://datatracker.ietf.org/doc/html/rfc8439",
    notes="IETF RFC 8439. Primary AEAD cipher."
)

AES_256_GCM = Algorithm(
    id=b"AES\x00",
    name="AES-256-GCM",
    algorithm_type=AlgorithmType.ENCRYPTION,
    security_level=SecurityLevel.LEVEL_256,
    pq_safe=True,  # 128-bit security against Grover
    specification_url="https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf",
    notes="NIST SP 800-38D. Alternative AEAD cipher."
)

# KDF ALGORITHMS
HKDF_SHA3_256 = Algorithm(
    id=b"HKS\x00",
    name="HKDF-SHA3-256",
    algorithm_type=AlgorithmType.KDF,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=True,
    specification_url="https://datatracker.ietf.org/doc/html/rfc5869",
    notes="HMAC-based KDF with SHA3-256."
)

ARGON2ID = Algorithm(
    id=b"AR2\x00",
    name="Argon2id",
    algorithm_type=AlgorithmType.KDF,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=True,
    specification_url="https://datatracker.ietf.org/doc/html/rfc9106",
    notes="Memory-hard KDF for password hashing."
)

# ZK PROOF SYSTEMS
STARK = Algorithm(
    id=b"STK\x00",
    name="STARK",
    algorithm_type=AlgorithmType.ZK,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=True,  # Hash-based, transparent setup
    specification_url="https://eprint.iacr.org/2018/046",
    notes="Transparent, post-quantum ZK proofs. Preferred for long-term."
)

GROTH16 = Algorithm(
    id=b"G16\x00",
    name="Groth16",
    algorithm_type=AlgorithmType.ZK,
    security_level=SecurityLevel.LEVEL_128,
    pq_safe=False,
    deprecated=True,
    notes="NOT quantum-safe. Requires trusted setup. Legacy only."
)


# ═══════════════════════════════════════════════════════════════════════════════
# REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

class CryptoRegistry:
    """
    Protocol-level algorithm registry.

    Enables:
    - Algorithm migration without hard forks
    - Multi-algorithm signatures during transitions
    - Deprecation with grace periods
    - Emergency algorithm replacement

    Per GPT-5.2:
        "Build a Crypto Registry into consensus rules:
         algorithm IDs, parameter sets, validity windows,
         deprecation heights, multi-sig support during migration."
    """

    def __init__(self):
        self._algorithms: Dict[bytes, Algorithm] = {}
        self._by_type: Dict[AlgorithmType, List[Algorithm]] = {t: [] for t in AlgorithmType}
        self._deprecated_warnings: set = set()

        # Register default algorithms
        self._register_defaults()

    def _register_defaults(self):
        """Register all predefined algorithms."""
        defaults = [
            # Signatures
            DILITHIUM3, DILITHIUM5, SPHINCS_SHA3_256F, ED25519,
            # Hashes
            SHA3_256, SHAKE256, BLAKE3,
            # Encryption
            CHACHA20_POLY1305, AES_256_GCM,
            # KDF
            HKDF_SHA3_256, ARGON2ID,
            # ZK
            STARK, GROTH16,
        ]
        for algo in defaults:
            self.register(algo)

    def register(self, algorithm: Algorithm) -> None:
        """Register an algorithm."""
        if algorithm.id in self._algorithms:
            raise ValueError(f"Algorithm {algorithm.id!r} already registered")
        self._algorithms[algorithm.id] = algorithm
        self._by_type[algorithm.algorithm_type].append(algorithm)

    def get(self, algo_id: bytes) -> Optional[Algorithm]:
        """Get algorithm by ID."""
        return self._algorithms.get(algo_id)

    def get_valid_at(self, algo_id: bytes, height: int) -> Optional[Algorithm]:
        """Get algorithm only if valid at given height."""
        algo = self.get(algo_id)
        if algo and algo.is_valid_at(height):
            return algo
        return None

    def get_by_type(self, algo_type: AlgorithmType,
                    height: int = 0,
                    pq_only: bool = False,
                    exclude_deprecated: bool = True) -> List[Algorithm]:
        """
        Get all algorithms of a type.

        Args:
            algo_type: Type to filter by
            height: Only return valid at this height (0 = ignore)
            pq_only: Only return post-quantum safe algorithms
            exclude_deprecated: Exclude deprecated algorithms
        """
        result = []
        for algo in self._by_type[algo_type]:
            if height > 0 and not algo.is_valid_at(height):
                continue
            if pq_only and not algo.pq_safe:
                continue
            if exclude_deprecated and algo.deprecated:
                continue
            result.append(algo)
        return result

    def get_preferred_signature(self, height: int = 0) -> Algorithm:
        """Get preferred signature algorithm for new signatures."""
        # Prefer Dilithium3 for quantum safety
        valid = self.get_valid_at(DILITHIUM3.id, height)
        if valid and not valid.deprecated:
            return valid
        # Fallback to any valid PQ signature
        pq_sigs = self.get_by_type(AlgorithmType.SIGNATURE, height, pq_only=True)
        if pq_sigs:
            return pq_sigs[0]
        # Last resort: any signature
        all_sigs = self.get_by_type(AlgorithmType.SIGNATURE, height, exclude_deprecated=False)
        if all_sigs:
            return all_sigs[0]
        raise RuntimeError("No valid signature algorithms available")

    def get_preferred_hash(self, height: int = 0) -> Algorithm:
        """Get preferred hash algorithm."""
        valid = self.get_valid_at(SHA3_256.id, height)
        if valid and not valid.deprecated:
            return valid
        pq_hashes = self.get_by_type(AlgorithmType.HASH, height, pq_only=True)
        if pq_hashes:
            return pq_hashes[0]
        raise RuntimeError("No valid hash algorithms available")

    def check_deprecated(self, algo_id: bytes) -> bool:
        """
        Check if algorithm is deprecated.
        Logs warning once per algorithm.
        """
        algo = self.get(algo_id)
        if algo and algo.deprecated:
            if algo_id not in self._deprecated_warnings:
                self._deprecated_warnings.add(algo_id)
                print(f"WARNING: Algorithm {algo.name} is deprecated. "
                      f"Reason: {algo.notes}")
            return True
        return False


@dataclass
class MultiAlgorithmSignature:
    """
    Multi-algorithm signature for migration periods.

    Per GPT-5.2:
        "Multi-sig / multi-alg support (e.g., valid if any 2-of-3
         algorithms verify) during migration."

    Use cases:
    - Transitioning from Ed25519 to Dilithium
    - Emergency fallback if one algorithm breaks
    - Extra assurance for high-value operations
    """

    # List of (algorithm_id, signature_bytes)
    signatures: List[Tuple[bytes, bytes]]

    # Verification threshold
    threshold: int = 1

    # Message that was signed (hash)
    message_hash: bytes = b""

    def add_signature(self, algo_id: bytes, signature: bytes) -> None:
        """Add a signature to the multi-sig."""
        self.signatures.append((algo_id, signature))

    def verify(self, message: bytes,
               pubkeys: Dict[bytes, bytes],
               registry: CryptoRegistry,
               height: int = 0) -> bool:
        """
        Verify multi-algorithm signature.

        Args:
            message: Original message that was signed
            pubkeys: Dict of algo_id -> public_key
            registry: Algorithm registry
            height: Current block height for validity check

        Returns:
            True if threshold signatures verify
        """
        valid_count = 0

        for algo_id, sig in self.signatures:
            algo = registry.get_valid_at(algo_id, height)
            if not algo:
                continue  # Algorithm not valid at this height

            pubkey = pubkeys.get(algo_id)
            if not pubkey:
                continue  # No public key for this algorithm

            # Check for deprecation
            registry.check_deprecated(algo_id)

            # Verify based on algorithm type
            try:
                if self._verify_single(algo, pubkey, message, sig):
                    valid_count += 1
            except Exception:
                continue  # Verification failed

        return valid_count >= self.threshold

    def _verify_single(self, algo: Algorithm, pubkey: bytes,
                       message: bytes, signature: bytes) -> bool:
        """Verify a single signature."""
        if algo.id == DILITHIUM3.id:
            from .dilithium import ml_dsa_verify
            return ml_dsa_verify(pubkey, message, signature, level=65)
        elif algo.id == DILITHIUM5.id:
            from .dilithium import ml_dsa_verify
            return ml_dsa_verify(pubkey, message, signature, level=87)
        elif algo.id == ED25519.id:
            try:
                from nacl.signing import VerifyKey
                verify_key = VerifyKey(pubkey)
                verify_key.verify(message, signature)
                return True
            except Exception:
                return False
        # Add more algorithms as needed
        raise NotImplementedError(f"Verification not implemented for {algo.name}")


class MigrationPlan:
    """
    Plan for algorithm migration.

    Defines:
    - Old algorithm(s) to phase out
    - New algorithm(s) to phase in
    - Timeline (block heights)
    - Transition rules
    """

    def __init__(self,
                 old_algos: List[bytes],
                 new_algos: List[bytes],
                 dual_signing_start: int,
                 old_deprecated_height: int,
                 old_invalid_height: int):
        """
        Args:
            old_algos: Algorithm IDs being phased out
            new_algos: Algorithm IDs being phased in
            dual_signing_start: Height when dual-signing begins
            old_deprecated_height: Height when old algos become deprecated
            old_invalid_height: Height when old algos become invalid
        """
        self.old_algos = old_algos
        self.new_algos = new_algos
        self.dual_signing_start = dual_signing_start
        self.old_deprecated_height = old_deprecated_height
        self.old_invalid_height = old_invalid_height

    def get_required_signatures(self, height: int) -> List[bytes]:
        """Get which algorithm IDs are required at given height."""
        if height < self.dual_signing_start:
            return self.old_algos
        elif height < self.old_invalid_height:
            # During transition: both required
            return self.old_algos + self.new_algos
        else:
            return self.new_algos

    def is_complete(self, height: int) -> bool:
        """Check if migration is complete at given height."""
        return height >= self.old_invalid_height


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL REGISTRY INSTANCE
# ═══════════════════════════════════════════════════════════════════════════════

# Global registry for the protocol
_global_registry: Optional[CryptoRegistry] = None


def get_registry() -> CryptoRegistry:
    """Get the global crypto registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = CryptoRegistry()
    return _global_registry


def get_preferred_signature_algorithm(height: int = 0) -> Algorithm:
    """Get preferred signature algorithm at given height."""
    return get_registry().get_preferred_signature(height)


def get_preferred_hash_algorithm(height: int = 0) -> Algorithm:
    """Get preferred hash algorithm at given height."""
    return get_registry().get_preferred_hash(height)


# ═══════════════════════════════════════════════════════════════════════════════
# HASH UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def hash_sha3_256(data: bytes) -> bytes:
    """Hash data with SHA3-256."""
    return hashlib.sha3_256(data).digest()


def hash_shake256(data: bytes, length: int = 32) -> bytes:
    """Hash data with SHAKE256."""
    return hashlib.shake_256(data).digest(length)


def domain_separate(domain: str, data: bytes) -> bytes:
    """
    Apply domain separation to data.

    Per GPT-5.2:
        "Explicit domain separation everywhere."

    Format: SHA3-256(len(domain) || domain || data)
    """
    domain_bytes = domain.encode('utf-8')
    length_prefix = len(domain_bytes).to_bytes(4, 'big')
    return hash_sha3_256(length_prefix + domain_bytes + data)


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("HONEST Chain - Crypto Registry Test")
    print("=" * 50)

    registry = get_registry()

    print("\nRegistered Algorithms:")
    for algo_type in AlgorithmType:
        algos = registry.get_by_type(algo_type, exclude_deprecated=False)
        print(f"\n{algo_type.name}:")
        for algo in algos:
            status = "DEPRECATED" if algo.deprecated else ("PQ-SAFE" if algo.pq_safe else "CLASSICAL")
            print(f"  - {algo.name} [{algo.id.hex()}] {status}")

    print(f"\nPreferred signature: {registry.get_preferred_signature().name}")
    print(f"Preferred hash: {registry.get_preferred_hash().name}")

    # Test domain separation
    test_data = b"hello world"
    separated = domain_separate("HONEST.test", test_data)
    print(f"\nDomain separated hash: {separated.hex()[:32]}...")

    print("\nRegistry test passed!")
