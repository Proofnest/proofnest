"""
HONEST Chain Key Derivation Function

Per DILITHIUM_SPEC_v1.5 §5 (GPT-5.2 APPROVED)
Uses proper cSHAKE256 from pycryptodome (NIST SP 800-185).

cSHAKE256 PARAMETERS (NIST SP 800-185 §3):
- N (function name): Empty string (b"") - we use only customization
- S (customization string): Domain-specific prefixes like "HONEST-KDF-v1-*"

The cSHAKE256(X, L, N, S) function with N="" reduces to:
  cSHAKE256(X, L, "", S) = SHAKE256(bytepad(encode_string("") || encode_string(S), 136) || X, L)

PyCryptodome's cSHAKE256.new(data=X, custom=S) uses N="" implicitly.

SPEC REFERENCE: §5.1 defines customization strings, §6 provides test vectors.
Test vectors are NORMATIVE - implementation MUST reproduce them exactly.
"""

from typing import Tuple

# Use cSHAKE256 from pycryptodome (REQUIRED for HONEST Chain)
# NOTE: No version checking - test vectors are the definitive correctness check.
# If cSHAKE256 passes the spec §6 test vectors, it is acceptable for consensus.
# Test vectors are validated via validate_test_vectors() in crypto_selftest_or_die().
try:
    from Crypto.Hash import cSHAKE256
    HAS_CSHAKE = True
except ImportError:
    HAS_CSHAKE = False
    # Note: We do NOT import fallback shake_256 because cSHAKE256 is required.
    # The _cshake256 method will raise KDFError if pycryptodome is not installed.


class KDFError(Exception):
    """Error in key derivation."""
    pass


class HonestKDF:
    """
    Key derivation per DILITHIUM_SPEC_v1.5 §5.

    Uses cSHAKE256 (NIST SP 800-185) with domain separation.
    """

    # KDF customization strings
    ED25519_MASTER_S = b"HONEST-KDF-v1-ED25519-MASTER"
    DILITHIUM_MASTER_S = b"HONEST-KDF-v1-DILITHIUM-MASTER"
    ED25519_CHILD_S = b"HONEST-KDF-v1-ED25519-CHILD"
    ML_DSA_65_CHILD_S = b"HONEST-KDF-v1-ML-DSA-65-CHILD"
    ML_DSA_87_CHILD_S = b"HONEST-KDF-v1-ML-DSA-87-CHILD"

    def __init__(self, master_seed: bytes):
        """
        Initialize KDF with 32-byte master seed.

        Args:
            master_seed: 32 bytes of high-entropy randomness

        Raises:
            KDFError: If pycryptodome cSHAKE256 not available
            ValueError: If seed is wrong size
        """
        if len(master_seed) != 32:
            raise ValueError(f"Master seed must be 32 bytes, got {len(master_seed)}")

        self._master_seed = master_seed
        self._ed25519_master = self._cshake256(master_seed, self.ED25519_MASTER_S)
        self._dilithium_master = self._cshake256(master_seed, self.DILITHIUM_MASTER_S)

    # Maximum output bytes to prevent accidental resource exhaustion
    MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB

    @staticmethod
    def _cshake256(x: bytes, s: bytes, output_bytes: int = 32) -> bytes:
        """
        cSHAKE256 per NIST SP 800-185.

        Uses pycryptodome's proper cSHAKE256 implementation.

        Args:
            x: Input bytes (must be bytes type)
            s: Customization string (S) (must be bytes type, non-empty)
            output_bytes: Output length in bytes (default 32, max 1MB)

        Returns:
            Derived bytes

        Raises:
            KDFError: If cSHAKE256 not available or inputs invalid
        """
        # Validate input types (consensus-critical)
        if not isinstance(x, bytes):
            raise KDFError(f"Input x must be bytes, got {type(x).__name__}")
        if not isinstance(s, bytes):
            raise KDFError(f"Customization string s must be bytes, got {type(s).__name__}")

        # Validate customization string is non-empty (per HONEST spec)
        if len(s) == 0:
            raise KDFError("Customization string s must be non-empty")

        # Validate output_bytes bounds
        if not isinstance(output_bytes, int) or output_bytes < 1:
            raise KDFError(f"output_bytes must be positive int, got {output_bytes}")
        if output_bytes > HonestKDF.MAX_OUTPUT_BYTES:
            raise KDFError(
                f"output_bytes {output_bytes} exceeds max {HonestKDF.MAX_OUTPUT_BYTES}"
            )

        if HAS_CSHAKE:
            # Proper cSHAKE256 with customization string
            h = cSHAKE256.new(data=x, custom=s)
            return h.read(output_bytes)
        else:
            # Fallback (NOT recommended for production)
            # This is NOT equivalent to cSHAKE256
            raise KDFError(
                "cSHAKE256 requires pycryptodome. Install with: pip install pycryptodome"
            )

    def derive_path(self, chain_id: int, account: int, index: int) -> bytes:
        """
        Create derivation path per spec §5.

        PATH = CHAIN_ID(8 LE) || ACCOUNT(4 LE) || INDEX(4 LE)

        Args:
            chain_id: Chain ID (uint64, 0 to 2^64-1)
            account: Account number (uint32, 0 to 2^32-1)
            index: Key index (uint32, 0 to 2^32-1)

        Returns:
            16-byte derivation path

        Raises:
            KDFError: If any input is out of valid range
        """
        # Validate ranges explicitly (avoid OverflowError from to_bytes)
        if not isinstance(chain_id, int) or chain_id < 0 or chain_id > 0xFFFFFFFFFFFFFFFF:
            raise KDFError(f"chain_id must be uint64 (0 to 2^64-1), got {chain_id}")
        if not isinstance(account, int) or account < 0 or account > 0xFFFFFFFF:
            raise KDFError(f"account must be uint32 (0 to 2^32-1), got {account}")
        if not isinstance(index, int) or index < 0 or index > 0xFFFFFFFF:
            raise KDFError(f"index must be uint32 (0 to 2^32-1), got {index}")

        return (
            chain_id.to_bytes(8, 'little') +
            account.to_bytes(4, 'little') +
            index.to_bytes(4, 'little')
        )

    def derive_ed25519_child(self, chain_id: int, account: int = 0, index: int = 0) -> bytes:
        """
        Derive Ed25519 child seed.

        Args:
            chain_id: Chain ID
            account: Account number
            index: Key index

        Returns:
            32-byte child seed for Ed25519 key generation
        """
        path = self.derive_path(chain_id, account, index)
        return self._cshake256(self._ed25519_master + path, self.ED25519_CHILD_S)

    def derive_dilithium_child(
        self,
        chain_id: int,
        account: int = 0,
        index: int = 0,
        level: int = 65
    ) -> bytes:
        """
        Derive Dilithium/ML-DSA child seed.

        Args:
            chain_id: Chain ID
            account: Account number
            index: Key index
            level: 65 for ML-DSA-65, 87 for ML-DSA-87

        Returns:
            32-byte child seed for ML-DSA key generation

        Raises:
            KDFError: If level is not 65 or 87
        """
        # Validate level explicitly (don't silently default)
        if level not in (65, 87):
            raise KDFError(f"level must be 65 or 87, got {level}")

        path = self.derive_path(chain_id, account, index)
        customization = self.ML_DSA_65_CHILD_S if level == 65 else self.ML_DSA_87_CHILD_S
        return self._cshake256(self._dilithium_master + path, customization)

    def derive_ed25519_keypair(
        self,
        chain_id: int,
        account: int = 0,
        index: int = 0
    ) -> Tuple[bytes, bytes]:
        """
        Derive Ed25519 keypair.

        Args:
            chain_id: Chain ID
            account: Account number
            index: Key index

        Returns:
            Tuple of (public_key, seed) as (32, 32) bytes.
            The seed is the 32-byte Ed25519 private key seed (NOT the
            64-byte expanded secret key). Use nacl.signing.SigningKey(seed)
            to reconstruct the signing key for signing operations.
        """
        # Import nacl.signing only when needed (minimize import-time dependencies)
        import nacl.signing

        child_seed = self.derive_ed25519_child(chain_id, account, index)
        signing_key = nacl.signing.SigningKey(child_seed)
        public_key = bytes(signing_key.verify_key)
        # Return 32-byte seed, not 64-byte expanded key
        # nacl.signing.SigningKey stores only the seed
        seed = bytes(signing_key)
        return public_key, seed

    @property
    def ed25519_master(self) -> bytes:
        """Get Ed25519 master key (32 bytes)."""
        return self._ed25519_master

    @property
    def dilithium_master(self) -> bytes:
        """Get Dilithium master key (32 bytes)."""
        return self._dilithium_master


class KDFVectorMismatch(KDFError):
    """Test vector mismatch - implementation non-conformant."""
    pass


# Spec §6 test vectors (NORMATIVE - using proper cSHAKE256)
# CONSENSUS-CRITICAL: Wrapped in MappingProxyType to prevent runtime mutation
from types import MappingProxyType as _MappingProxyType

SPEC_TEST_VECTORS: _MappingProxyType = _MappingProxyType({
    'MASTER_SEED': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'CHAIN_ID': 1,
    'ACCOUNT': 0,
    'INDEX': 0,
    'ED25519_MASTER': 'dd18bf1f64d6443bf98b806ebd9cdb205ae2eb0e83758d2b8dfa9b95068dec83',
    'DILITHIUM_MASTER': '8f4bb0a163dc16f9cc21d41d6f927181edccee57ebcad2e93ecbcba2f634399a',
    'ED25519_CHILD': '61cd37a85379befd8fe8a8e647cf7988226d0fc1228dbe245d1779581ba8ba74',
    'DIL65_CHILD': '54b62a651ebd892a62914b85d22c5bd5cb6263cd1ab5e176e8bd906677ef1c72',
    'ED25519_PK': 'f18b53899e811a6945898be53b7bae82ca1824e605c69888d211373d2de4c7ce',
})


def validate_test_vectors() -> bool:
    """
    Validate implementation against spec §6 test vectors.

    Per spec §7: "Implementation conforms if it reproduces §6 test vectors exactly."

    Returns:
        True if all tests pass

    Raises:
        KDFVectorMismatch: If any vector does not match exactly
    """
    master_seed = bytes.fromhex(SPEC_TEST_VECTORS['MASTER_SEED'])

    kdf = HonestKDF(master_seed)

    # Hard-assert ED25519_MASTER
    expected = SPEC_TEST_VECTORS['ED25519_MASTER']
    actual = kdf.ed25519_master.hex()
    if actual != expected:
        raise KDFVectorMismatch(
            f"ED25519_MASTER mismatch: got {actual}, expected {expected}"
        )

    # Hard-assert DILITHIUM_MASTER
    expected = SPEC_TEST_VECTORS['DILITHIUM_MASTER']
    actual = kdf.dilithium_master.hex()
    if actual != expected:
        raise KDFVectorMismatch(
            f"DILITHIUM_MASTER mismatch: got {actual}, expected {expected}"
        )

    # Hard-assert ED25519_CHILD
    ed25519_child = kdf.derive_ed25519_child(
        chain_id=SPEC_TEST_VECTORS['CHAIN_ID'],
        account=SPEC_TEST_VECTORS['ACCOUNT'],
        index=SPEC_TEST_VECTORS['INDEX']
    )
    expected = SPEC_TEST_VECTORS['ED25519_CHILD']
    actual = ed25519_child.hex()
    if actual != expected:
        raise KDFVectorMismatch(
            f"ED25519_CHILD mismatch: got {actual}, expected {expected}"
        )

    # Hard-assert DIL65_CHILD
    dil65_child = kdf.derive_dilithium_child(
        chain_id=SPEC_TEST_VECTORS['CHAIN_ID'],
        account=SPEC_TEST_VECTORS['ACCOUNT'],
        index=SPEC_TEST_VECTORS['INDEX'],
        level=65
    )
    expected = SPEC_TEST_VECTORS['DIL65_CHILD']
    actual = dil65_child.hex()
    if actual != expected:
        raise KDFVectorMismatch(
            f"DIL65_CHILD mismatch: got {actual}, expected {expected}"
        )

    # Hard-assert ED25519_PK
    ed25519_pk, _ = kdf.derive_ed25519_keypair(
        chain_id=SPEC_TEST_VECTORS['CHAIN_ID'],
        account=SPEC_TEST_VECTORS['ACCOUNT'],
        index=SPEC_TEST_VECTORS['INDEX']
    )
    expected = SPEC_TEST_VECTORS['ED25519_PK']
    actual = ed25519_pk.hex()
    if actual != expected:
        raise KDFVectorMismatch(
            f"ED25519_PK mismatch: got {actual}, expected {expected}"
        )

    return True


if __name__ == "__main__":
    print(f"cSHAKE256 available: {HAS_CSHAKE}")
    if validate_test_vectors():
        print("\n✅ KDF implementation ready!")
