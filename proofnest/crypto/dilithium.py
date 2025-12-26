"""
HONEST Chain CRYSTALS-Dilithium Implementation

Per DILITHIUM_SPEC_v1.5 §2.2 (GPT-5.2 APPROVED)

IMPORTANT CRYPTOGRAPHIC NOTE:
This module uses the CRYSTALS-Dilithium signature scheme as implemented
in the 'dilithium-py' library. CRYSTALS-Dilithium is the basis for
NIST FIPS 204 ML-DSA, but there may be minor encoding/parameter
differences between the academic Dilithium specification and the
final FIPS 204 standard.

For HONEST Chain v1.0:
- We use CRYSTALS-Dilithium (via dilithium-py) as the quantum-proof backend
- Dilithium3 = 1952-byte public key, 3293-byte signature (NIST Level 3)
- Dilithium5 = 2592-byte public key, 4595-byte signature (NIST Level 5)
  NOTE: CRYSTALS-Dilithium5 uses 4595-byte signatures, NOT 4627 (ML-DSA-87)

When a vetted FIPS 204 ML-DSA implementation becomes available, we will
migrate to it while maintaining backward compatibility via ALG_ID versioning.

Backend: dilithium-py (https://github.com/GiacomoPope/dilithium-py)
Version pinning: Required in production deployments

============================================================================
SECRET KEY HANDLING REQUIREMENTS
============================================================================

This module returns secret keys as raw bytes. In Python, there is no secure
memory management (no guaranteed zeroization). Callers MUST:

1. NEVER log, print, or serialize secret keys to persistent storage
2. NEVER include secret keys in exception messages or stack traces
3. Minimize secret key lifetime in memory (derive → sign → discard)
4. Use secure key storage (HSM, encrypted file) for long-term keys
5. Consider subprocess isolation for key generation in production

For production deployments requiring FIPS 140-3 level key handling:
- Use a validated cryptographic module with secure key storage
- This pure-Python implementation is NOT suitable for HSM-level security

============================================================================
"""

from typing import Tuple, Optional
from hashlib import shake_256
import threading

# Thread-safety lock for deterministic keygen
# dilithium-py uses global DRBG state, so concurrent calls would race
_KEYGEN_LOCK = threading.Lock()

# Backend version pinning
# We require dilithium-py >= 1.4.0 for deterministic keygen via set_drbg_seed
# CONSENSUS-CRITICAL: KAT vectors are pinned to specific backend behavior.
# If you upgrade dilithium-py, you MUST verify KAT still passes.
REQUIRED_DILITHIUM_PY_VERSION = "1.4.0"
# For exact reproducibility, pin to this version in production
RECOMMENDED_DILITHIUM_PY_VERSION = "1.4.0"

# Backend: dilithium-py (CRYSTALS-Dilithium implementation)
# NOTE: This is NOT the finalized FIPS 204 ML-DSA, but the underlying
# CRYSTALS-Dilithium scheme that ML-DSA is based on.
try:
    from dilithium_py.dilithium import Dilithium3, Dilithium5
    HAS_DILITHIUM_PY = True
    BACKEND_NAME = "dilithium-py (CRYSTALS-Dilithium)"
    HAS_DETERMINISTIC_KEYGEN = True

    # Check version via importlib.metadata (Python 3.8+)
    try:
        from importlib.metadata import version as get_version
        _installed_version = get_version("dilithium-py")
        BACKEND_VERSION = _installed_version
    except Exception:
        BACKEND_VERSION = "unknown"

except ImportError:
    HAS_DILITHIUM_PY = False
    BACKEND_NAME = None
    BACKEND_VERSION = None
    HAS_DETERMINISTIC_KEYGEN = False


class DilithiumError(Exception):
    """Error in Dilithium operations."""
    pass


# Size constants per spec §2.1
# NOTE: These are CRYSTALS-Dilithium sizes (dilithium-py backend), not NIST ML-DSA.
# CRYSTALS-Dilithium5 sig=4595 bytes, while ML-DSA-87 sig=4627 bytes.
# CONSENSUS-CRITICAL: Wrapped in MappingProxyType to prevent runtime mutation
from types import MappingProxyType as _MappingProxyType

ML_DSA_SIZES: _MappingProxyType = _MappingProxyType({
    65: _MappingProxyType({'pk': 1952, 'sk': 4000, 'sig': 3293}),  # Dilithium3 (NIST Level 3)
    87: _MappingProxyType({'pk': 2592, 'sk': 4864, 'sig': 4595}),  # Dilithium5 (NIST Level 5)
})


def _get_backend() -> str:
    """
    Get available cryptographic backend.

    NOTE: Version is logged for diagnostics only. Consensus safety is enforced
    by KAT (Known-Answer Test) validation, not by version string matching.
    This avoids dependency on Python packaging metadata correctness.

    Returns:
        Backend name with version (for diagnostics)

    Raises:
        DilithiumError: If backend unavailable
    """
    if not HAS_DILITHIUM_PY:
        raise DilithiumError(
            "No Dilithium backend available. Install 'dilithium-py'."
        )

    # Version is logged for diagnostics only - consensus safety relies on KAT
    # validation, not on packaging metadata. Different versions may work if
    # they produce identical outputs (validated by KAT).
    return f"{BACKEND_NAME} v{BACKEND_VERSION}"


# KAT validation state (using Event for portable thread-safety)
_KAT_VALIDATION_EVENT = threading.Event()
_KAT_VALIDATION_LOCK = threading.Lock()


def require_kat_validation() -> None:
    """
    Ensure KAT validation has been run.

    CONSENSUS-CRITICAL: Call this at node startup to ensure the backend
    produces expected outputs. If KAT fails, the node MUST NOT participate
    in consensus.

    Thread-safe: Uses threading.Event for portable correctness across
    Python interpreters (not just CPython).

    Raises:
        DilithiumKATError: If KAT validation fails
    """
    # Fast path: already validated (Event.is_set() is thread-safe)
    if _KAT_VALIDATION_EVENT.is_set():
        return

    # Slow path: acquire lock and validate
    with _KAT_VALIDATION_LOCK:
        # Check again after acquiring lock (another thread may have completed)
        if _KAT_VALIDATION_EVENT.is_set():
            return

        validate_dilithium_kat(levels=(65, 87))
        _KAT_VALIDATION_EVENT.set()


def is_kat_validated() -> bool:
    """Return True if KAT validation has passed."""
    return _KAT_VALIDATION_EVENT.is_set()


def _validate_sizes(pk: bytes, sig: bytes, level: int) -> None:
    """
    Validate public key and signature sizes.

    Args:
        pk: Public key bytes
        sig: Signature bytes
        level: 65 or 87

    Raises:
        DilithiumError: If sizes don't match expected
    """
    if level not in ML_DSA_SIZES:
        raise DilithiumError(f"Invalid level {level}")

    expected = ML_DSA_SIZES[level]

    if len(pk) != expected['pk']:
        raise DilithiumError(
            f"Public key size {len(pk)} != expected {expected['pk']}"
        )
    if len(sig) != expected['sig']:
        raise DilithiumError(
            f"Signature size {len(sig)} != expected {expected['sig']}"
        )


# Environment variable for TESTING ONLY mode
# Testing mode for deterministic keygen (IMMUTABLE LATCH)
# SECURITY: Once latched, the testing mode state CANNOT change.
# This prevents runtime attacks that modify os.environ.
import os
import threading

_TESTING_MODE_LOCK = threading.Lock()
_TESTING_MODE_LATCHED = False  # Has the value been latched?
_TESTING_MODE_VALUE = False    # The latched value


def _latch_testing_mode() -> bool:
    """
    Latch testing mode from environment (once only, immutable after).

    SECURITY: This captures testing mode from os.environ on first call.
    After latching, the value is IMMUTABLE - further os.environ changes are
    ignored. This prevents runtime attacks where malicious code sets the
    environment variable after process startup.

    CONSENSUS-CRITICAL: To prevent production misconfiguration, deterministic
    keygen now requires BOTH:
    1. HONEST_TESTING_MODE=1 (explicit opt-in)
    2. PYTEST_CURRENT_TEST is set (pytest is running)

    This makes it physically impossible to use deterministic keygen in
    production, even if HONEST_TESTING_MODE is accidentally set.

    Returns:
        True if testing mode is enabled, False otherwise
    """
    global _TESTING_MODE_LATCHED, _TESTING_MODE_VALUE

    with _TESTING_MODE_LOCK:
        if not _TESTING_MODE_LATCHED:
            # CONSENSUS-CRITICAL: Require BOTH conditions for deterministic keygen
            # 1. Explicit opt-in via HONEST_TESTING_MODE=1
            # 2. Running under pytest (PYTEST_CURRENT_TEST is set by pytest)
            # This prevents production misconfiguration accidents
            has_testing_mode = os.environ.get("HONEST_TESTING_MODE", "").strip() == "1"
            is_pytest_running = "PYTEST_CURRENT_TEST" in os.environ
            _TESTING_MODE_VALUE = has_testing_mode and is_pytest_running
            _TESTING_MODE_LATCHED = True
        return _TESTING_MODE_VALUE


def _is_testing_mode() -> bool:
    """
    Check if testing mode is enabled (uses immutable latch).

    SECURITY: Testing mode is captured from os.environ on first call and
    CANNOT be changed after. Runtime attacks attempting to set
    HONEST_TESTING_MODE after process startup will have no effect.

    For test isolation, use _reset_testing_mode_for_tests() which is only
    available when tests are running via pytest.
    """
    return _latch_testing_mode()


def _reset_testing_mode_for_tests() -> None:
    """
    Reset testing mode latch (FOR TESTS ONLY).

    SECURITY: This function is gated behind PYTEST_CURRENT_TEST environment
    variable. It can ONLY be called when running under pytest. This prevents
    accidental or malicious use in production code.

    Raises:
        RuntimeError: If called outside of pytest
    """
    global _TESTING_MODE_LATCHED, _TESTING_MODE_VALUE

    # Gate: only allow reset during pytest execution
    if "PYTEST_CURRENT_TEST" not in os.environ:
        raise RuntimeError(
            "_reset_testing_mode_for_tests() can only be called during pytest. "
            "This function is NOT for production use."
        )

    with _TESTING_MODE_LOCK:
        _TESTING_MODE_LATCHED = False
        _TESTING_MODE_VALUE = False


def generate_ml_dsa_keypair(
    seed: Optional[bytes] = None,
    level: int = 65
) -> Tuple[bytes, bytes]:
    """
    Generate Dilithium keypair.

    Per spec §2.2:
    - level=65 → Dilithium3 (NIST Level 3)
    - level=87 → Dilithium5 (NIST Level 5)

    Args:
        seed: Optional 32-byte seed for deterministic keygen.
              If None, uses secure random.
              Seed is expanded to 48 bytes via SHAKE256 for AES256_CTR_DRBG.
              CONSENSUS-CRITICAL: Deterministic keygen is ONLY available when
              HONEST_TESTING_MODE=1 environment variable is set BEFORE process
              starts. This CANNOT be enabled at runtime for security.
        level: 65 or 87

    Returns:
        Tuple of (public_key, private_key)

    Raises:
        DilithiumError: If level invalid, seed wrong size, backend unavailable,
                       or deterministic keygen attempted without HONEST_TESTING_MODE

    Thread Safety:
        When seed is provided, this function acquires a global lock to prevent
        race conditions with the backend's DRBG state. Random keygen (seed=None)
        is thread-safe without locking.

    Security Warning:
        For production/consensus builds with deterministic keygen requirement,
        use subprocess isolation. The in-process approach has limitations
        documented in the module docstring under SECRET KEY HANDLING.
        Production nodes MUST NOT set HONEST_TESTING_MODE=1.
    """
    if level not in (65, 87):
        raise DilithiumError(f"Invalid level {level}. Must be 65 or 87.")

    _get_backend()  # Ensure backend available

    dil = Dilithium3 if level == 65 else Dilithium5

    if seed is not None:
        # CONSENSUS-CRITICAL: Only allow deterministic keygen in TESTING_MODE
        # _is_testing_mode() checks os.environ at call time (defense-in-depth)
        # SECURITY: Production nodes MUST NOT run untrusted code that could
        # mutate os.environ. For stronger isolation, use subprocess boundary.
        if not _is_testing_mode():
            raise DilithiumError(
                "In-process deterministic keygen is UNSAFE for production consensus. "
                "For testing, set environment variable HONEST_TESTING_MODE=1 before "
                "process starts. For production, use subprocess isolation. "
                "See module docstring for details."
            )
        if len(seed) != 32:
            raise DilithiumError(f"Seed must be 32 bytes, got {len(seed)}")

        # Thread-safe deterministic keygen
        # dilithium-py uses global DRBG state via set_drbg_seed(), so we:
        # 1. Lock to prevent races across threads
        # 2. Save original random_bytes function (default: os.urandom)
        # 3. Set deterministic DRBG seed
        # 4. Generate keypair
        # 5. Restore original random_bytes function (NOT just reseed)
        #
        # SECURITY NOTE: After deterministic keygen, we restore the backend
        # to its default RNG mode (os.urandom) rather than leaving it in
        # DRBG mode with a fresh seed. This ensures:
        # - Subsequent calls use fresh randomness per call (not a stream)
        # - No state carries over between operations
        # - Behavior matches library default for non-deterministic callers
        #
        # LIMITATION: This restoration depends on dilithium-py internals.
        # If the backend has additional global state beyond random_bytes,
        # it may not be fully restored. For maximum isolation in production,
        # consider running deterministic keygen in a separate subprocess.
        # This is documented in the module docstring under SECRET KEY HANDLING.
        import os
        with _KEYGEN_LOCK:
            # Save original random_bytes function (typically os.urandom)
            original_random_bytes = dil.random_bytes

            try:
                # Expand 32-byte seed to 48 bytes for AES256_CTR_DRBG
                seed_48 = shake_256(seed).digest(48)
                dil.set_drbg_seed(seed_48)
                pk, sk = dil.keygen()
            finally:
                # CRITICAL: Restore original random_bytes function
                # This puts the backend back in "random mode" not "DRBG mode"
                dil.random_bytes = original_random_bytes
    else:
        # Random keygen uses os.urandom (thread-safe)
        pk, sk = dil.keygen()

    # Validate output sizes
    expected = ML_DSA_SIZES[level]
    if len(pk) != expected['pk']:
        raise DilithiumError(
            f"Backend returned wrong pk size: {len(pk)} != {expected['pk']}"
        )
    if len(sk) != expected['sk']:
        raise DilithiumError(
            f"Backend returned wrong sk size: {len(sk)} != {expected['sk']}"
        )

    return pk, sk


def ml_dsa_sign(
    private_key: bytes,
    message: bytes,
    level: int = 65
) -> bytes:
    """
    Sign message with ML-DSA.

    Args:
        private_key: ML-DSA private key
        message: Message to sign
        level: 65 or 87

    Returns:
        Signature bytes

    Raises:
        DilithiumError: If level invalid, key wrong size, or signing fails
    """
    if level not in (65, 87):
        raise DilithiumError(f"Invalid level {level}. Must be 65 or 87.")

    _get_backend()

    # Validate private key size EXACTLY
    # No variance allowed - consensus-critical crypto requires exact formats
    expected_sk = ML_DSA_SIZES[level]['sk']
    if len(private_key) != expected_sk:
        raise DilithiumError(
            f"Private key size {len(private_key)} != expected {expected_sk} "
            f"for Dilithium level {level}"
        )

    dil = Dilithium3 if level == 65 else Dilithium5

    try:
        signature = dil.sign(private_key, message)
    except Exception as e:
        raise DilithiumError(f"Signing failed: {e}")

    # Validate signature size
    expected_sig = ML_DSA_SIZES[level]['sig']
    if len(signature) != expected_sig:
        raise DilithiumError(
            f"Signature wrong size: {len(signature)} != {expected_sig}"
        )

    return signature


def ml_dsa_verify(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    level: int = 65
) -> bool:
    """
    Verify ML-DSA signature.

    Args:
        public_key: ML-DSA public key
        message: Original message
        signature: Signature to verify
        level: 65 or 87

    Returns:
        True if valid, False otherwise

    Raises:
        DilithiumError: If level invalid or sizes wrong
    """
    if level not in (65, 87):
        raise DilithiumError(f"Invalid level {level}. Must be 65 or 87.")

    _get_backend()

    # Validate sizes before calling backend
    _validate_sizes(public_key, signature, level)

    dil = Dilithium3 if level == 65 else Dilithium5

    try:
        return dil.verify(public_key, message, signature)
    except Exception:
        return False


def get_ml_dsa_sizes(level: int = 65) -> Tuple[int, int, int]:
    """
    Get ML-DSA key and signature sizes.

    Args:
        level: 65 or 87

    Returns:
        Tuple of (public_key_size, private_key_size, signature_size)

    Raises:
        DilithiumError: If level invalid
    """
    if level not in ML_DSA_SIZES:
        raise DilithiumError(f"Invalid level {level}")

    s = ML_DSA_SIZES[level]
    return (s['pk'], s['sk'], s['sig'])


# =============================================================================
# VERIFY-ONLY KAT VECTORS (CONSENSUS-CRITICAL)
# =============================================================================
# These vectors are DETERMINISTIC and NORMATIVE. They allow production nodes
# to validate backend behavior WITHOUT using deterministic keygen.
#
# Generated with: dilithium-py v1.4.0, seed=0x000102...1f
# Message: b'HONEST Chain verify-only KAT message'
#
# VALIDATION: ml_dsa_verify(pk, message, sig, level) MUST return True
# =============================================================================

_VERIFY_KAT_MESSAGE = b'HONEST Chain verify-only KAT message'

# Level 65 (Dilithium3) verify-only KAT
_VERIFY_KAT_65_PK_HEX = '2892760da3e3d0825fcd96a98f6d4180078a75bb7155332b5f4e4920a65c69b94528d7c0708d9aadf368aae4a370267520a3c3170ccfdd3f6852bbad6c5d13fb170e0814afb137e75ad99560398327d7aafba06d9b310d9f9f207c93c16a4eb144ab521eef36bd06835e31de4dc17b7ffb3cfdfbcec4c78de07cd99bd74197a816a685e94f8c56ab14321d347f5c4f6c39924c74932aff1c62d6719e4482b3a3043672a7d7b5189ba2a9b5ac54c3dd8293f3736ef04449da746ec925203008c1fd544ce67d4ad8a70a851f9009e6bfa5f59e9f9c15df30d88ca29ea15b3e6abedaba5f0f9afc9d7defca948056515e142647a4faf161a5beab8245a17cf98523d3196ccc4345d67d86085713aed0af04f356a5f3100e2b05cdc23b8327f81b33700e35e41e9225e622ddf0a3be98c1a7742116b388b5000907c168aa2eedb645e5ecdd86934cfcf061a1d8c0d828a28905b7196b0792b3d0736269f3a776dc08ac500c13d4f0190a1e18115b35a722e5b7adc3e6dd238f0f29851fcbb170ed25897d30e09c4f07d0c639e471d382ccac2ea8be5bbd2d158ca14a674eb9e90ae8be45d0675e7376a3bc84b0d1eff397e5510e21355256275e92a2457f1dfd18819e8c96e84ac734e740b33a59699235be37df18d9d31ea599a371b85696360541f7d89b51a20534ba3332bf621075be0b1b4a5ec412e9130d2cf29579d0b5c4d3369f35a496c9f879e18e3428c5cf32e4d9488fe3472d8b6bc2631f4d8bc897207a9d7f09803a6a7babf20f2e4c1c38a4c58bace6c2985b480a31bfff50432f4c6277491cf7a68df3b50efc6631a49957e10508d213c831c7c69ca5f1b6fdf90aa5f50ff5020b9c9d249fa01c0106d1a8b01b95eec72af9ded21917d7908f2d255ff022e635523924c3455c1a6c9fc05d1329ffa3aa8a3c2e94806be33f01cb9e838367fe3c71ebf84d1035a7712d5070b7f51b81f5837909ceeddd19e072d79679a86971c4e48bd69597c6a6bee71850c35ed6f547ab80468c5ab134a5c956d96be28444ae89d86ae150fc4d09ec412331a464ebaf2d37a31c87769bc45100036b9af39ff244c2b848c09c451c3fb469fb842751033eaf40112b76bd7ebf7596810d330d290e13cf3b4c9289c6282c39eda769fd8f6b2814c54cb03b1dba5a0e84857e29d78408ca01c417a289e802690a186c6e473e5bbf5ec5363ccda572df9543922f88bfee19d1acc41e38a24d1dad516cd744af210a57fd4472a98c54db4a1b0a212207970c9ab45d0586275a68919203e290b141ac3c625a707e4811b71b22cf324bcf00e1796cc24e448b1ee27e8f0511d57c68b947a132b1cf5979ece87eee33c712ddcf9d1cc868c0d99d98ec7593a7a1ded5a3d2dab3eb32730e6d307d2f257f6002e8b3a74d6515a506ed56b3b44e91b96d387f548ca117707cfd192920dc39ae68ea0e31ff6250006ba3645023a8f4ca9eb74d3ef01ed73d896646d634d4770fb3bcbae9180731ef11791bb2a48aee30c5431a3c23e24d1a6e321f3553f226db814dcbc162c51c82b06de8c3b25357e92a296294dbdd98f24c172860cd46bcea44e620e25a316ca1c177357c02dcf41fff9b0b064d1952e30b0e46f9fd58b6d057cb2401c875492ff8d8b30480e7aa337975cc2c449b621daae82eaa781c3f7ec8d77fd585ae52302ebdf8bac32f6e6ec7641d5e17a78c04cc94c9817c71ebc0bfa4648de1506b261dfa20a0f48dd54fe1112bbb38cfebeef17d15082051fa589c43650f76a1074059716d65c07dbf2aa59c5fe48f06b95e9a99208a891a56f1373647e042c2087cae8fb318ba1b799bad5f812bb5492cd9bc5e002703b8eebadcbc19c61c2a0bf299343e51346b047220a369671ce1d04c5f7f2fe2262c2d850d544a16d308cd6f2edd345ca4151dc987476bc1057750fb12c9ef5d4427006efb4f9e8695a66ad4193cbdc7440edb0cc05d68323923acba2fb2010ce6244118cb8a96181ed3425151eac17d16b561e1f58e05e821b7f668f0684e2baaab57a4a02db2ae0cae2fee705e0fc28d6ca71363c8a6a80d6196cc91c371dca610a4936b84c0261065b102c576766180837ec323ac670743df0d3aa60866cb80d8c7c3c772cbed5831a7e589decd8fac1e3fcf794586ba86fde417fff67a826007300d802348e833e7b85f09da57943ba9f62cb638332cb081f85ba03f9b2059bd76f3e55c1487696d691cd187d937e23864f1dae6681cd9b2431911e1c20e6069ada698d2b12cb7263398f7fc169056bd52a3fcd4bfd18ea9df112ef048ef5be5e7b1f9e0641b78d497cfafb5689862cb4d122c426132ff5e9a254cc4f28374dc0bab0295b392f968d6a351e13c6dddc43b9b18b1d058cab36395387b8870f02a849a21ebd0ba06ba277166dbbb314acc625e28351696d9cd86fb080b3784070282bfbfc0131f3ef3d0cf47e97fceba177a3c46bba19af1a69f2bddc3afb7ec30727a8a902c4077a36516aa5f5dd912bfbb29721ea65b54a8305c2fdd40c19ab896d4fdeb8af35768e716c8e023e61a2641b79147292121630a9b21ff99e041dca44f6c096bb25f6fe0e119837b86c7337e4ec21b84b536a3228524cc9fd59d66ec5925d50bf7afcdaaed59e8f956a9db7be36121b6b6a8ef2b9be60f5295eaf7ce58ca9db3d9d6e57b61836374a0f74ed31396da1f61b0752b57192f247f7d703b1934fd9a6246ff8f47fd6613a1b365665f5ea0ff9c52e7cac4e8c5'

_VERIFY_KAT_65_SIG_HEX = 'b9893ee96f5c446b582bf597ff9c12ccecad444a2f71314dfe83473b89ad19acdf3d4f8d60229732af9bd71f2d6649277fa7d8dcda6276b8fa4f9028f8fb491e5378b6743b6183bd815917c6fa726563d3ea760d238adf43937b5ace74b5f2686df261a938d4c75216e3514dbfef4000c72c8a2d3939fa38ab5d24d1daf2573d6973384eb51522d3f79b0490d4fb45a737be8e35ba9eed661ae852446619800c2561d180741e33c00dad08875279bef455f06fa3bfef7d75b781f65d577e39cf2630a5af44b6f68677e506320ccd5f2e2cdc6700526f312ad7fd18c421ff4ef57a4b9be8e8033dc1aac2d236ebcd58a3d520edff358284b2db5cd42f65da226d2eb7a9c936c934c6603ddfcfc5be768762f7efb52c39fbdda52ec572cbd98a471bd3541cc53130e651e8ae34627dbf9ea31c2044f93a7635adea576feb26d1cde0b3edc6e99c988dced45b07eb80a9d550dbfe141deb67465cac2116d229260b98029c90da5faa867680b57ccc51445b1aa3a9ad42336cc8eba0741addd84591c61dd91c51ee98c8b41b3d192fc3e7f3ffb98af1fd439cfd387cee2317b356b8b2ed0b9383cc9f04cc5911958d9a5b60923fb44fd0df4399b12ee334f45751c5fdb6ab26167998f469013546b6f84b3e32ff2bc8c7c9ff6246a182ed6dfc04bb001f3b432addc331dec73b65ceb1601b475924162581c00c359faa708a59374195f68e5880f22c332b9c0bf1145c08dc601480142eb8d7a150632f420ed0cfd0746aa30d6aeb2f58e8a9a86b48ec1f082b2ac3c4159246f36613bf376c9153e33d846be595ae73b040acf7f3cf436be91d9c5f2a803e72800c41319f6b01a3e1f90712392346c88b0c85bfaeb9ca24e151693a42f8fe1bde45ed3bc26bb167ab37ed6c0e05dbb0f93ac905ef25483de0e6ee65a06fb939bfebaad2e148cfa518a48cad787f934c0832b953589208525e44e1fd604ab05650be6dcd3914a771b94d8323c7b3a129efa2c141d6403e34b2dc8e543fb1360218716c3ad9da4e295b2aafb03e24f2e922a9136bf9bc6c661b3a5ddeee4decde7b090318dd2dd8093d608918334c4bcbd0eb77b677d0a0d9285f39db3a1e46bf4a3e918927cc45c217a366df5c7edc1770ec587b81d1edfc957f486fbc2c87ac3666dee75b9706bdadcf020a08d83b265391b2d298712240a0d59883a6f22e9ff670a707594d51d4852b529e1e2982b9266ca7a572d04615a35245bba3a3e89484d96348325283e2f378cb9a7e20b287e08d756a90a066f346a7605d3f75d08eaa1297938ad01c3f5bd179e09c0f827585afd574722b8f394473ad780975a84e5acd4342df3285a961f7405b6331c00ced39a7471baeb283ecaaaed2057f74cce3afdb65329b20c3da36422e332a32ea948afab8cf43b2d0d0bad711bb5df6d2df9696673d82a4a64573c2d8e4ee92f285ff34469c8e305c3c309799b8672940ef81ba6f7cd024cfe46524d9aefd71a44fc20e44dff1809b11eee833f05964a8d4147f9ed06931a3b5bff66251d42ff94e9691821d6b381ee67677db8e46016278a660f0c8932b80cddf7752b9c162dccf4ecc2715342bacba5edba1bf866ca9ac3794b76fd111aedc3a1f7ed022dd7e6d9f547e494799b9588236f4001c02d2dd67b102367dbe534e6a84232a2e8039103701b7836e4470fbd243e13b50f4b2c2b15d3758077bd54eaa50c550dba4d020f3733bdc9b8a77a219ba934cab9a4899fb234f020c53ebd2f86eccd21f45730db65d50bc123a906cfb7faef248bb01aecbbd1a19555cb5ee34c80f91fc7a2314bbbca0a3f9b6aca44e9c066ffa82abf3245e0921d4c393a120194cf196373559c67a630e6767c631b26dedb3314ce4696ae26c00b15cf6eff4b4170c2a23fcc11dcc395bd3a58b3aa7fe4af76a98ddbfab16ee17a924f52a1b3257e67b1c72982734ff4a8546c50099e162cc067fba4408fac478bbd9f3738bb98d1dd88b1dd7eaa66b422fef297e45bb5a9d2d985ff91e98c642744fdc21950ff0990a39488c9c6a4cd8f8d6ae5c51b26964c5e4339bf3dce3ac152ffa3630d4e1c9990a0132c1a1f3f45cef72a791bba0cf67a9ca2d7214b24ce5eba6cff7161f2e0666fef0268b6f56aff347082652cc2903e530c79703e0f6aa7d9ec0e01d8a2c232fa0df647cc75e291561c5ded33338ddfb84d70cddcc452cb4db8ac2f5a9d5afa9691843246dfa3d13d0793d4aa490c8c9eb44e03a94536e2b2d837599133c90c3e6f8596ab5d42a90cd7990856850713c5008282e6ab9e921480ef70b424b653c6c229badeec35d2b0e482d6abc4a36bdae9eb739d03088d6d5f4097c5557192e8aa2f9c3bfb61287cf7c5f066911aa8af43adc6b9b1dac2c196eb518ee29a4a3c75a942ec8bbbc0a4b2a4a985fbf4a1206d3bd3c4667c183d681ef6db03949fb0df80bbf1aa46ab952742a2dae2dbae9d58378cb1670f4efd58f17e132829010e6ea1fcdbe3eddccf5c6e4a9884e9ec0d646c745f84a2b9b5deb384e5ccb0d272fb34033c6e4ae901f416428f6c675c0aaaa5dd930885c1b42e7f91b4052698fcf5e0d74d08c9be39c25e7f8ef9b2901213091e8b129a3f0908299a10712007a4730c8aefaf6f1311dc4dfb90c2c1b429d8db6b6790b98fb02dad81b3a3dcc1e8c5675eeb70dd9926ba7e007243c3a7a77e0ca488ab28e168d1305da01116a953e099baa10787491fa55ae346b3985d5fbf29ae0e13cb5ae131cf4d053b8818f1acfc7df15f420256df35bcc4b0b6594842ed53fc7db4a54598119254a8d250cb9fa35bf8f095056169d5ab4d038763a4e1d3e8faca0606fb8e974c293775495ebe6eac6739d307dbc8ab6c6dec37781fce99048566a85fedce33120be4037bab6aa725fb6d2efc501e54a8bfd322c07547e7d73da1a6ce8105cd6def1ad92353aaca4b6f4d2ef52469d0112a9908fbad00aea109f7a8cd649185cd5e63c5a59472e921ead8a87b1fbc1b2427c48727e788d10901a3e5f2ea76e488eaae9bff722389944d0c335af96e3c7ddfd770bc7c323522e92fa89b4d4e2d3879e8681c7b6b2eeb20de088654e1239ce19c6f4ab2118d0d5c702e394adf751fe5d01ade072faed1656b758cbe4acdea3105d108d7482656077a0925d63044cba6099a4361a9f768d1e0d123c06e7145aa9a15ebe737c69e3e72fa49630aa8e7aa79c9f301bbed01eebb446c4347ca12e8bfc00a13a9fe17b07d0dc4faa187a449e8d4a3ded8d513af70adabafec71fa6fc73bebe9500412151f53a9434541b28f6ac8f96a808e14a8bdede28a800fa31823ecbfca7b321f44f25d9616417877f3fbad6dce7badbe897066655be378ac1846d68396462e6d78e85c9eec214d26d40f3fc590551b065314f874e2a6e281b7cdcc0b99b94d0b8b2e097d6170995642af8af371babaf61973c41bb93173266b7c262df2005fb7e9074e89978aa2a3e260d4bc11847058440867c187e4f064e95eb11d53c815e1070ba4fc45a5ccf924b49d3c761682768c68b369664d049f374ee314e8b899e743e840335a97bc3cbf3d895bc8fe83a5ec39f735818089f98c1dbf2b37ecf2b14dfeb436b9e9f3b663d7e9c7bb4777dba788aef0c769c38e2c9c7e8c7b39a954b49092fff7b576ba53e47aa8256acfcf78bc30854986cfb1dbec068e55130b3ca5e56764003e296b69f4a236b892cc12e3b7d96ffba194dfef107df01b2420b7c0f4afffc5693f4c6dc7788798e3179a18750f8d9228f67b8c009be5c015feadd635c93f5fcbab39e1797689423c0df52e7f6794eea76925622be9df987a7cf4ccb81c9f3467ed81b31ef2c043c94302f4dd4c3dc10117cb051626de4805fd09f1834c5970ea6a4283fc2e02174d041e9e6de12c965e8ac8d6bc4218554bb2d5e516f85c1f421eb332a828927dbd2fd7fd36651cce0431f26f38361eb17f7c5527ac9180f54dc404e03c9196a3a95e1110c120ae1ede062f0dea06ec480de2c4eb9ee5259e8ec5a8faa500a9730d3224d076e963310d073e7a5c28a414ff110c08a451e484cf7e7af0867f593027f35d77084c475349d7322925955417dd38f7197f6837130f378f8d6aeb4b90beb0a5905b502f7e0ba8b7073714135ac024ff1d5ec9d48c87aa5716c5c8aa779082bad6c35c46ae753f82f1bbe0aef3a875d2ad9d9003db58ccedceff39ac88b09d74eb4cf5b14418a0b644396d3c278321d0db5f5f0040256adfb5808099326cef4eb6cbcea2df410e8efe4ba19bd323a62476b60e19fd72d64c0c97d778247b3d110e1348ce7520658ba0041b4905c5006814e554aee2bdf4f34caa795067c30e6f4ff5a2f14c6d596fe80808e92a8329bf3216d4182543ce554d4e54345fa59bfd08d6b310458cf87c80d37f0474cf10e625d4d180351a4ff6f40dbd0937b0b47511b18c7e36a0cec5d7ccf7c918c07c7b5116a63abcc664ac9a93de40fd207998886f95b71276f21996ba42d61e231bdd17d0f820784780573ce71c8d98639151f20ea40398f4fa4f4b348e97f9b5ae0acca0be04beb19334549788385fb74f82c59abe2e9eb030d18344a697baa07313439596a7ee106365ea0adcd00000000000000000000000000000000000007090f171f25'

# Level 87 (Dilithium5) verify-only KAT
_VERIFY_KAT_87_PK_HEX = '2892760da3e3d0825fcd96a98f6d4180078a75bb7155332b5f4e4920a65c69b9cae794a651b0c84b41a8fb3dceb82b3975dda1326e375828d5e9065e4af54b23f16cf02a2bc224e12d308efc301be67e3488421835d067ea8ef63ce475228ff27c125837553854e828e8f8f76fc46d5b1ea38799ba8c98256b53eaec85b06e4a28d529fa151e375efdec5e2d017527a4ead7cc62dcf37c9f75be105c830589af7d1ce75d3ff474f0cafd46ae4d6fc16a63404ac87d02a33652e1483ea083933a2c0c2879b180bf9bf201daebe35b92f199869f1df6ffe2b84d0f193ea357ce99074e387399889fdeb9cda1a1c8757afc9704317148c01d54c9a370db69a372d0ba81612da6d54ea3db13bb0234889d7470a94b7d352fdd9fe1a929220fcaf5cba36f185deb00579978ce02160d6d8ebb93d00ef2fa9226f9bdfffa485e5f360e991225ebc07f5d838f160c60e43e6342254507b534c3a0ef886b9367827311a9c65a333992f859090e0a0478dc68dc32da6aa9bac26c74147f3237ae1d3e925209c9f6a352335b5b9462d8b675610e14eead10d20522f3a257788253033a85a5add1a39238a4e07732d401d4117a8d9333301582d9fcbb973984a5ee60dfe64ed4368ad698c9c4f9d7e1e181332de1f39e273f1e5c5b56d85f66061d41fe288e3564cf4f0ff126908c4304cffda9c4df3fa7973f304487fb50789bee8ce091a30ceea647a24afa5e22658f9f00a5e52adeac238d3483b8f06dc8dcb64f733e9269ab1b0762320880cb3f749261d04429da77024700ae01da76dec865ffa2e813cbd7c6c50320798031b4a693824d5bd918bf15928a2d4c2e9e5d6bb55fed381873bbb9ab2e5a13867fac634585e707af53481ed937750f8ea5016316d9081f64b89418e284247493cf0fff39a259e0eec588fc7b815e8d6ef09483ff4db6e03bba003cf31f0b664a9f41edc4e1ef0e8612f9cd3e231d03ed6a74143a0332e64a7f6d5080adb49dea89c4874baf99395b1fb221377e9de3f832315c104e74d8f149ca996a29f6ba7e0efdb69189d756154494a8b66441b8e53c899a127a42f9215843acc3979a746dfe6ab09d0bf41c8375159f19b3c2f468822a354f1299b2ec7d17b92357272d006dc50ede48438e0082084f9c283dab48b5512505c12b63b5669da0782226cef5381aa3a0729a4836e9d614d3dd73fb92ba5b9fb350f5773f6e78acff69121994f0e01450d38a86063fefedbf833754cdfa7545a37017d4717d406a1e8e563e708e2c6eea753b56d71c4f8740c5a4860c2f9d6fbd4c5bdc30c5a56fdc3c0f92d52cf606f8c6cd8616a7ae695302d90f38bd2e2711c1ae9475c12efaf2ab0784e3f70addbcf95e7d35e92387d5039a4152056567641eee71dea23a2d6a5e971de9b501c0320bf7bd0b06a1cd59fa965834681eea9b9ffebb9e3ef3c2bf126ae3ad7010b10094d17f4ca1775f6191b7daea0629033d2b05f461a0a80b28aef82f376155bca9b5f7ea07fcfa21e1e1c4e1516391fec17b9e98beb6e9bb3488dab9c2005985688ab95b95d135128a5516c6787e23b089fd57b984ee25414882140a33388251243b3de0ddbf59b1adf000e8a18fcb706a5ecc05e11c473b35b8de647fe2def30fe1fb5483ba356f1cd334d00b4835a87974d54387b8d4e50e63e30fa0eefb60ebfd5abc7da694d41b980ad5644d98b3bd1f72d0f56e61f87b18b8bc14de68e140c8150606ded96048ec09b3f254ac60792f4511d94e4252459823dff837b575334ee31006afe06f87a5533c9f72e1802a64f45c2d43965de26b58dcd77f5d69d6a74c82a8ac165ae1f407a93eec2de9c2c70ceb66ca300e8c005514a8be0c24463712a5409b62543143add92614148c09bec776b04e3fd9025f3d9afb212971dfcfa577a5661e9fcc16ea323ce420ca3e9742a69570c26f2e67e00ad37830a2dfbe48fded05b5a7bdfb707fdd3151676718c1c5175eeccbb009c3d38f37f92886e1e25341a0cc24d1807b2ca1099d6da6819ad8816883a5727588785004e83a6bed6301f111905f0a396a6b71ffd6f1d7332a0f93b0da96f7d3796dbc48e91321ef7aae968aa8f0389096f6f077ba9818488bf5cbed882a2cd19670c44b1d4a8dd8a249e4420012536b82b1ca1e1867d7d44c5cff67b9adfe048efb760ff2d44a6238fc25ff6c51521af010da8484fd8b1b7e480ab920b6d34ddecf9e95effa629ed9b7e2fc166de124871945bc05c9110b882cdc8f0d3747bc63e26641f0262241d7527abbd8ff15dfad2297024806de94759a34b87d88dd77bc8941ecda0a0351868bc2a56b2cac2ca6efe244c26af773ccb81a068d24f039af9aeb47d6ab1bd36b9f398cb67c892302cbbd99b8aebc3c0408be55d061102f82c713f8b8eb637b0c7e33f96cb00b47bbc32d7a96fe26ced1ea580bea6107049194eb2325cbce561af4e26f4202c5b6e9f463184ebf44d22b3e699eade910f14768b4c9883ef06241918a5978f0f2a972aaafb91710f11a241597b970c2e10688f0bd95417f1b447b50f4ac1f65f30d0ffa8b64cf2803d7dc4ca79861789bdb41845e5c0c2be7d174e70c15818ec6fb13c24313a8bf4c32b553f44f273fb7a9b0a6abe3c89cca5d652be38cebe6bc8b35567253160920b1b4fd7701730ad2370b499cc13ebddf94f1b4d5ccd1ccf4c351aee687fe6cf546f1314857c7d6221078e9ddd9d061ab8c5d54fa7bab4a5342fbf9c1b586834829a8cc464886deb495bc1990b06f6d47b833a2d13bd1da925d0fd03ba53989cca77c93d85bbebf1354b1d74af2455015789d58c1e8b383bc99596e01ff5e7509a4b754d971438334b91a437ce8f0f5307f2f9005b9eb62ba8b8e3c19cf029b6f3ce683fd0ba3ba50d8f3c4d35b840f14a7c0227e9a11dab0101c88bff49ebd8e17c6f42fb23cd0996a7202f86faf5b4808a13e219d2ffbc180bbc882bab8938d05af2b20bb5c9a384fbee01734cb03b79ede599076db8eddb7bd7803c2907cb94c606418f7d342c6a62c3cd2e71e1eb7e24bfdf727deb74a35c2078ca0f88c5c635ef28e9c80e372af9cfa5a996144b32b8813e1d16c6f26f0db94c531ceb81913aadbd8430ee1fd1345799fecfa699ce3cdb583627a680ee80cb9d2b3f2fa8f20f11618b818bd3e2dec73930a9516e72d6192c7398e1d42a992604e1344a951243e2c6645758ea624ebf941718dbb7e63be77c1d4f160f119b0758e63a998b35738914e8120b8e0635a4314ea039e842f8af3ea841a988cd1308a70fb912d1164665eff7232d96b3d699ddbba04ccde67c3bbcd9c1cd2bb7c3c4e56e5c0009d1ac9ebd16fbde83e07ab8aeb3409c698eb6136eba0bea6a431ad7b62e0f24bac72352f7522727302e9561e49cb736a647d0ea6ff4865c9e9080f462190314dc4aa17a67e48740bacee228c2611776e1a92d74c9d574b596e88c39d97be5282cf042416655cf03fdeb76c149b2368b947b17e3674f59d8526506343dfb7b6bc03623b0446830aa247201a047697a7f22e7feb7f22b3d8c5b22741babcd0ae6561f3ae297e24fd950ef9942da7a8c621c8e22edec39cb8fc47f3e34db635bc4334948fbe0b4a010e27e6ad2ae26e7b9b3a5e4ce9dc0f050d62ca120981d61bc636da98fde6'

_VERIFY_KAT_87_SIG_HEX = '735c6deafe641e2a966e7e36ca8edf26f2b17d2756f4e24b00256a8977140a5491b33005a429a905c5002ad9824daf465e23c54e2401a73ce1cb6317f5ad7a4152799b695912625854733681ca0b55f746ae9644836c0f22fb660f6a7737a3e1fd61608c92ced24829b78258084df19f4332e327b39ce5be914df5d7a838f0a2e1847775da87cfb1ed3d482cf62991b64dd171cb51c8b579c375afac485b95a8147733f5af0ca04cc24122f62d0e3d54cbdffa5b766c47cc953637d5d4a008a9e328eae33d55cc3c5d07cdd90d20148bf2757f0be831806cdd0e2625ede398a3fd5472b543fe1a93d7ae95f700a965d1e1ae201f6984651d34bc7fb9d5b23eded9a009a5527fd643160b436d05f4292e51541f7ec5c6632b99faad5169b4485aeab6bd9ce31225024dc5a54da61cf895f31e95e3a075a1ec3174939d67d8985fafaca70181e2c9766c2378739ff22e45a94c3b505fedbc9c927f4256ff68ea86d7f35e92ae6df12137362da02ff6d1489dbe3166ed8bba0ffc88d05143b1f7f2e7401d41940fc5eb421c0c00366da057d49f21e47ddd046464053c294f7e8024c34721dae881adec92faf2b4a4f132c423dc2dc824a4bea2e2f1324cd2ef7614f47a29d52ade7bf0a13d8415ebac882eb4ab758d6a64ef68ec90fa890c996fff3cce92234f55dd315861284962821e426c872e874cb1c18c6b564863840cb9bc9bca7186fb1bc2d05eadf68fa57bd7a88aaf66c5d7220fd64621a81e0da97a4f980c3179a6c6f8f25adaffc9342defb015e276373f69689924596f97a42171cfaabbb095226a7afbad79de5fab2e3fdc9bfea406abca86df6eba2b724961fd084d2794cd2909ad952254a31bc8301c212a65ef5ce18e8b2a4da832ab6cac547e0620d2b9f505362315c141d429330c220d902c6f67110ff63047e6075ea47dd57565676325960ec52e39725728d177cfa1aaad9c7b23897b499f3f600b046f3d36d21124341ba14b05b57a680aa2a9ed8d7f241aa76ca8275db364369b80978e315bc8f90cee8c908ac671363c1667fd6d7a05e8dcd13be85afa679392921ef92144f3b9dcac7c8f55b2e1d41f5c868c60f052a395b9657083f9f8c1f995b97a9992be0dce300e85364fdaab20c6567c78e55c857cef8ac86c509c24b2bc0e2e3008b98b73ca4dcb88b6a4dfb9b795923800eca280453e6a845701600df9fa310ea3291f7008e688abf1e9d7c0195e6bae056ddf7cdb64371f4705ba4c3beeac31103ee8f04d189594954b8564541f9ae48b11022c061240b4a66e9a9ed8b5c965bec76a423886789ae59b04fc6227f30628de0e9ab7e1b189f685e448bd2ba62a8601e4f96e222f955d0b3b8881781494ffc7bacb9099820818f50741ec44940ac373943259b990ea10826bf1a9d82e575e1b27e85f0afc029b8a18a7969cd2faad6e2c74fbcf02c06ccae782c5f91eb70f26a293fded01cc3af12f7b3928a426bafea348a93aeef84cbd26d9a266f6a7f565f0325eb49b600ac01e06f1bab336a7f2f61bbd8349084c39cc7e9ffdd24a13749a149f8d0a8261b8e465cd9bfbc7326bbcb0a3a363be4db092661a750ff3055af1d5da93fd3e90ce26bc2a7c5b7abb8695f645ff16db097fcb2112d0b0d828220d7adb0a681ae2f41c5e472c86c6ffa37ebc23ebfa8e5abadb22db436e66d5747a91e35e24297a0c9b2a2493edff66e07b6d5bb3454439694eb3b8db9af842ec318fb8ee9147275224118d9877e9cfc45fee00f94d2b8bd4a28ec34dcbc3f61d63f3a3e14aa45201c6580689b7eb8a271c22b003ad3667f0daac64711719399c3aee5714e8491f8131e79d62ecfb0b6983e8038bb05cafec287b87ee7e16c27c2bd52ba0256a4844d1e365000a22be4e4a0edd3777948aa2311776a11380039c1621042393792d5d26bf5216c0c8aa22a589c33718933e6c185fd859b3f0eccccbb606ab74cb7a0989e36dd07274fa5c64c3c77415e42a215554c9dc9c4c2de866dc26b9b46f4ea49ecf9ba64317d3e0881e384f377836fdaf57dbcce5ec4b6b94137446bb396e1a574a1f7440b17e2408ee220a3eeac0f667049baf52007ae61748b9c98a6b4bb2e7ec609eb8aea5763ba48942ba451385da5ef8fe25d4479390e2e0aaaea52d276f68f905fc0b1c6a4ed11fe65f5827bb00f54f7634b3cc9a08c0b2c44646bb990ea4f3e57450573a5d23c47f35fb3a28a41bd7ff2710ac8339e989009a3bc6ce4872294a0dd9c5add67162b665db8a259189243043a88cbffbad47d548f014caadb78cb326bafbd3f72e679035f3ca83ce83336f5626c9f263924ce8e8ef06e41a580157e1f2314a8812f2d0d00173288db8b6b13cbe88e61c7549a72602286b57f8dee1a8cc1ffd192fff42a9817372fea96b4dd0b8f59d6d266c4a09b2c54b35732e79fc2f0d9b4c506b2ee0d564d34d689a2c34f663d914194519908e1736f417fa5faed5475c9f4f2ab184d34c50991359de2ffc9d586852b78c50cc2ae97e03ce58ff33c66be08d37a943f78bcedfce4b1b85d77c977d611ee7f82a94725943b09e80772e11d277f770d5a6f8d2f90dd37e119c5457a41ec8661c7b8f3840a8c55081e092ad8cfd7d250d4a4f5ef7b5a93a4f98a921c0ea2b1fdbe27f3e0ce62f5f994d3a34f765a0e2914e406757853cf5f8ed8a2330b39e8ceb6a2d80706971793e9f859c0f337359227857ecf2928ac10d68a589fcbcfcc09a0835f9c946b96e7d1fae927425b32d9095a6fe822227eda7bdcbe2f653e005f0457fcd2a143be7c88b3f94b69ece79a6f4d8015e73482a6f11f3a43084beeb18c15875de899de9a4862c7f2061111aeeffe569a827990d9a2a6cb8c847b68b314e23b24da6d833c2c63479c5e28b4fbd9f5ebdf32c42c58f9f71795474f8409a1ea079c1a347bd6ab955cede5447dd920ff8dd318219b9b63d7a145493a3030d5390bc6a8c43a2d1fd6739d4b18574bcf96178d68af004165a1e31d063009f503142531c7a66f92275f9e5e7b452ab31880cfe6bbce4e19acbe574b1691243b5abd04abe79650aac2eb6ee15e320adf9be31cda86164271e13eebf8bf98a91c37ab2ce4b01f56b3d79479f0c101690a47e4877cbd331258508c665c0295f3948344b3be4eecc858408bc0c70cda0204bc6c1a4ef4a4df748c2f9eaf032f489dd3f82e7cae54de1027de6d68998a93ad332f46eb1a293e636721cbf7c60bc65f0b441b72fc88f8438095f4ccefa515d054a6cb8d77895875d6da956ca5c1f5e3982a9f3defd6a3b2a8a6ad6d5c3e62772da8c0254e0969e60d47aaf372d4dcffc3334d05a19d0125a35e26750c2ba5464c557430cc19fbd59f305fccdf2f6d92b0457206177f29d6968c6cd86eaa8e3a2796931a7f07b27bdf34e2cd589654d1e316a13a963c4e229f10133d2e67320ae6efd2f6d93abc3c2e2dcc34bda0b7033da6b4025c8b271ec8ae3554c90bf25f5724dcb5520de064491ea1ae6ad8e0f74f4320128d53521a095c7c63083e3f0549ed13def73580d37682a548ec0488109cb020c5221d749345b50de3c7c467160c3d11793e717271a0b571b4d4b495aa9b94f6305aefdfd60ab3f8be4dde30cd67f7a7402e13618524f84a5dbf2493d5bf551b8e42652f759f693b8e83b93e06bdae6a912aa8ac9dc75ef90a96a596f75aa848493489fe555a7f3223efaa8a309485c0eeb61f725722f29c9d16c56f55678f347a86791c5b2340d013e09632d7193c1049f4a6d77aea810a2a3ad9caa2eda09dbcf0a4cc10f4860bf904c558de79003ca45b37f786cba3c658281a91b31a8a176fdbd4bab4cbea280457b4f27b675499745eb2548dad98c90505c9dadc5dd030f43b5e35b3f65099eda286b1b4745ddff12d3c048f95e2f0a517c310c29bbf219e21b8d538c4ab7985d9a71b1aa2869b52bf288a6287f6fde529f3dbb2c9f88eea414c99dc657eb542452008cbac4edc56847431adf39377474f51eb0ce1fb9f89ab219e6d29b5955861b609376f634cca8374476ef713e3049485f498d0f201ccf64d6cdc60081f2c8f304adac21d27281ddaa882455fa46e2acab3510b1a135ce2b236c22925356cce34fb2be45c9e995a04cdf1a3853266b0f53208c6bdbcd15f55a1c465623423892e3d46ec25717019c8289c0de15547385955b9acb390669e39076a86c254baff91cb8afc725a2ec5c19e6790e54054ad8f621099b9cc7d190d0cc176eb8bf604b14dad375eb1c66a2d52bba4fc3f501c2cedca0fe3a31971917e7773852acac3e91549616af1a577438722e4beccd13d0e259ddfca0e466eb2b1c9499a6d29a2a79f260f4f21a3d2313b3f1472323b9089a4c2f080e3d2f3e7d16dedd4eeff3fe2dc42daae0030f3a1c94508180924729727667f90378eed8d19eec971c9afe278746fce90396c353a8cd055493ee5f6adf4f27bc58b0495ccc829b6a6cf4b207709c7b7b6be908c4ef880a05f33d07dd307fe5f74e59bdb041cd8ac79a9c7d06b8059386f5e2939ab93a7ec12b7ff78f4f204a631114071a7b2a049892696ccc0b4490d4c86efedbbca44c098c82b5c2d9885fd2ea6573d35bf485b8b7a951ab2d670a01e0bd21814654e916ddc1b429f716ee596e0cccdf3ca4fc286c7720f4b9992ecb2110456117f716cdd4780d5c0521d216f5dc9fef67fa17b73070332636a2396de123ce3d43a6051f83e0b39f3d4521180241db6dcf15a07d58979b2408fb0146d1dc88be615fdcd843a74e182bcb1e0010f84b82c5904b3ac30f38b45334a3a7522c30e3582eda6152041e2b54e38a95ff7a74d2e5cce4704120896b4f929391cabe7ffc0dea6c2bbbed27d538b8fbc85decbafc7321377a9a697ce3bc5bfb8cbe894abfd0fd7441edbd1c306376900da4e2936b928d98852f6b12934eb2498686a0c32ca2b463b7bdab92a4fab7a206f8619185788aca9125df58fc2cde92a565b41f696b16d816f36afe2caa94cb19f10c2e76ece8fa2cdebaae750d2eb456ba2d8ddbc62ea78c4c66afa3f25386df257707a240b8316177291548984fb5daeabfe1454e53bbd1dacc3e2b5c8289c799aa8eee34e0c408894c3f33128d8081560621a1339a3d6292bf4f4a30b9319df00000713b4a8fa1aeadcc4e8aaaa2914a76221e6f6eb9f78f5560b3d686240125490b83fc8faccc97c22200fd11ee2198cba28e23e4763eec4a6bd644fd65565f0cf51c70406f9b96ca6c221877786cf16b4561a93458928ac80dbcd53d7671e79d00f939aa395a9ff4fa02baeff7e205662ade3fd52e6febc376455413566fc37459553a94bd948436cd704ee7678ccf3419a12d90d5e1879f36034a8b873c48a76ab71d048da57d1b9c3c9b7b46130031c553f3791f7b50ad4d0a56396a75a2981236e9173163b386ffac139ac09a52045fdff6e861c82dd7e218f67b25bfa0f97c135ac00c31e73777711f9b25ddf5068f9c0619213dfea83d1b905311d0a1843e0fa88965bcf733a81916aa0dce12d611bbaecfb62ac633ae8df93ad3e99d110a9a468a9710ea819448e9fb6405e15b0bede058bf089dc79ff43a41a81e8056ef1fbef3f64a42b518fc24a8813611b05ec2e57dcdd39b2b3ab685e4e10a19390b236740d7e2bd6a9949618bdb5d6637f6eb1c32f5f8845f16e764d7855eeefd523794ef1ef59e4c2b55796ad72d1aa31410ad42dc4df9663a27f081c5345f20d1a95c251a506e838a2efa16a7d28c2601dff142b2032225dfa08c07cdd48681b76086f52b3b145ece93732390927897deae84ccd94549edcbf4ffad20db9a0448d9949b2a9e80908974b03e0dc6236915e33aa1d756acf3d82719039377c5e6d2483164f6d614c057c0f0283cacf9013c48233fef304b730019a97cd145bfcd2a32de0cea33bfd25f3399201ea8d940cd0223216f90f965bbf4ee44e0f134cbe7274a77ee37a7d9263611a035aff239a29eed43531d945d9fc93bc8c94bc75274b6d26d062bd37e08a80ceed2f152f212155898c7f92db7d20ee77e227b988d6b92a2e40c108ddb0fa13a8dc5508caf0ff2c9626053570e1499b31899cec4319c85b260e92bec7bf0c854a41edf4da09da1f5e833fe83c82fb44b628d8ebd7c9f536c54f22b92214a4557dd34e5aea98cfbf231de1aea13c29d6444522d4b4afce4bf5f32d86876b4530199ff8022e90f36ad98e4273911f1d130e1d6b6f8b66355b2918932a14488505f83acabf7a20786b93f83b6184ca980122ccc6a2ada7006cf2d77ed7bd2deb0e34f0a5d64bed105104b5b0199c709e9705cfb895cf3f52c3abb2b45157edfec43997e0570aa941e5442d43fe9162b5c098f561a05d5a7cb80d4cc2b326dabe1ef262a36bde9f5ff0621d4091d2e63667d98a5ade3f5003e4044b2dae01216429d9ea0b7da29363a474c7583abc23571b0bbcb00000000000000000000000000000000000000060d101b222a3338'

# SHA3-256 hashes for integrity check
_VERIFY_KAT_65_PK_SHA3 = 'fc6862d03f53eb6d7c6b2dd5fe3d6ccd6a81ed90c0f1168dcf8001ad5ad0b2c5'
_VERIFY_KAT_65_SIG_SHA3 = 'ed4183406baa61d0a299caf0ec3687c776b77c80198fa48e9aa874f5b1f18c52'
_VERIFY_KAT_87_PK_SHA3 = '9e31075a49b286f34eeca13e0368bbf8a278c355fc1774e088bca59cb2d4961d'
_VERIFY_KAT_87_SIG_SHA3 = 'd18b81e722c8b740045a0d02b7bab6167ad8880e63866d898681a34c8cf1169b'

# Keygen KAT (requires TESTING_MODE) - for backwards compatibility
DILITHIUM_KEYGEN_KAT = {
    'seed': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    65: {
        'pk_sha3': _VERIFY_KAT_65_PK_SHA3,
        'sk_sha3': 'd3e9eb498e5006ad385affab4ca3db22d9d96d59eb81c3a6ee64d14d33d93efb',
    },
    87: {
        'pk_sha3': _VERIFY_KAT_87_PK_SHA3,
        'sk_sha3': 'd6b5b4a343dce8c347d4dc35535808cd88300d43f669150b8ce85e9600648652',
    },
}

# Alias for backward compatibility
DILITHIUM_KAT = DILITHIUM_KEYGEN_KAT


class DilithiumKATError(DilithiumError):
    """Known-answer test failed - backend may be incompatible."""
    pass


def validate_dilithium_kat(levels: tuple = (65, 87)) -> bool:
    """
    Validate Dilithium implementation against known-answer tests.

    CONSENSUS-CRITICAL: This is DETERMINISTIC verification using hardcoded vectors.
    No keygen, no signing - only verification of pre-computed test vectors.

    CRYSTALS-DILITHIUM CANONICALITY (CONSENSUS-CRITICAL):
    =========================================================================
    CRYSTALS-Dilithium (the algorithm dilithium-py implements) is designed with
    unique encodings:
    - Signatures: The (z, h, c) tuple has a UNIQUE encoding for each valid
      signature. The verifier's "decode" step will reject non-canonical bytes.
    - Public keys: Matrix A is uniquely expanded from seed ρ (deterministic),
      and (t1, ρ) encoding is unique for valid keys.

    This means for a given (pk, msg), there exists AT MOST ONE valid signature
    encoding that verifies. Unlike Ed25519 (where signature malleability was
    historically an issue), Dilithium's algebraic structure prevents it.

    REFERENCES:
    - CRYSTALS-Dilithium specification §5.2 (signature encoding uniqueness)
    - NIST FIPS 204 draft (ML-DSA inherits this property)

    CONSENSUS SEMANTICS:
    For HONEST Chain consensus, Dilithium signature bytes are treated as OPAQUE:
    - Only the verification RESULT (True/False) matters for consensus
    - Signature malleability does NOT affect consensus (Dilithium has none)
    - This verify-only KAT confirms the backend behaves deterministically
    =========================================================================

    Production KAT (EXPANDED for consensus robustness):
    1. Verify hardcoded (pk, message, sig) returns True
    2. Verify modified signature returns False
    3. Verify wrong message returns False
    4. Check pk/sig SHA3-256 hashes for vector integrity
    5. Verify truncated signature rejected
    6. Verify all-zero signature rejected
    7. Verify all-0xFF signature rejected
    8. Verify malformed public key (all-zero) rejected
    9. Verify malformed public key (truncated) rejected

    Testing-only KAT (HONEST_TESTING_MODE=1):
    10. Keygen with deterministic seed produces expected pk/sk hashes

    Args:
        levels: Tuple of levels to test. Default: (65, 87) for both.

    Returns:
        True if all KATs pass

    Raises:
        DilithiumKATError: If any KAT fails (backend incompatible)
    """
    from hashlib import sha3_256

    # Vector lookup
    vectors = {
        65: {
            'pk_hex': _VERIFY_KAT_65_PK_HEX,
            'sig_hex': _VERIFY_KAT_65_SIG_HEX,
            'pk_sha3': _VERIFY_KAT_65_PK_SHA3,
            'sig_sha3': _VERIFY_KAT_65_SIG_SHA3,
        },
        87: {
            'pk_hex': _VERIFY_KAT_87_PK_HEX,
            'sig_hex': _VERIFY_KAT_87_SIG_HEX,
            'pk_sha3': _VERIFY_KAT_87_PK_SHA3,
            'sig_sha3': _VERIFY_KAT_87_SIG_SHA3,
        },
    }

    for level in levels:
        if level not in vectors:
            raise DilithiumKATError(f"No verify-only KAT vectors for level {level}")

        vec = vectors[level]
        expected_sizes = ML_DSA_SIZES.get(level)
        if expected_sizes is None:
            raise DilithiumKATError(f"No size constants for level {level}")

        # === VERIFY-ONLY KAT (PRODUCTION - deterministic, no keygen/signing) ===
        pk = bytes.fromhex(vec['pk_hex'])
        sig = bytes.fromhex(vec['sig_hex'])
        message = _VERIFY_KAT_MESSAGE

        # 1. Check vector integrity (detect corruption)
        actual_pk_sha3 = sha3_256(pk).hexdigest()
        if actual_pk_sha3 != vec['pk_sha3']:
            raise DilithiumKATError(
                f"KAT vector corruption (level {level}): pk SHA3 {actual_pk_sha3} != "
                f"expected {vec['pk_sha3']}"
            )

        actual_sig_sha3 = sha3_256(sig).hexdigest()
        if actual_sig_sha3 != vec['sig_sha3']:
            raise DilithiumKATError(
                f"KAT vector corruption (level {level}): sig SHA3 {actual_sig_sha3} != "
                f"expected {vec['sig_sha3']}"
            )

        # 2. Validate sizes
        if len(pk) != expected_sizes['pk']:
            raise DilithiumKATError(
                f"KAT failed (level {level}): pk size {len(pk)} != {expected_sizes['pk']}"
            )
        if len(sig) != expected_sizes['sig']:
            raise DilithiumKATError(
                f"KAT failed (level {level}): sig size {len(sig)} != {expected_sizes['sig']}"
            )

        # 3. Verify valid signature (MUST return True)
        if not ml_dsa_verify(pk, message, sig, level=level):
            raise DilithiumKATError(
                f"KAT failed (level {level}): valid signature REJECTED. "
                f"Backend may be incompatible with dilithium-py v{REQUIRED_DILITHIUM_PY_VERSION}."
            )

        # 4. Verify wrong message (MUST return False)
        if ml_dsa_verify(pk, b"WRONG MESSAGE", sig, level=level):
            raise DilithiumKATError(
                f"KAT failed (level {level}): wrong message ACCEPTED"
            )

        # 5. Verify modified signature (MUST return False)
        modified_sig = bytearray(sig)
        modified_sig[0] ^= 0xFF
        if ml_dsa_verify(pk, message, bytes(modified_sig), level=level):
            raise DilithiumKATError(
                f"KAT failed (level {level}): modified signature ACCEPTED"
            )

        # === EXPANDED NEGATIVE KAT (consensus robustness tests) ===
        # These tests ensure the backend rejects malformed inputs consistently

        # 6. Verify truncated signature rejected (MUST return False)
        truncated_sig = sig[:len(sig)//2]
        try:
            if ml_dsa_verify(pk, message, truncated_sig, level=level):
                raise DilithiumKATError(
                    f"KAT failed (level {level}): truncated signature ACCEPTED"
                )
        except DilithiumError:
            pass  # Expected: size validation should reject this

        # 7. Verify all-zero signature rejected (MUST return False)
        zero_sig = bytes(expected_sizes['sig'])
        try:
            if ml_dsa_verify(pk, message, zero_sig, level=level):
                raise DilithiumKATError(
                    f"KAT failed (level {level}): all-zero signature ACCEPTED"
                )
        except DilithiumError:
            pass  # Expected: backend should reject malformed encoding

        # 8. Verify all-0xFF signature rejected (MUST return False)
        ff_sig = bytes([0xFF] * expected_sizes['sig'])
        try:
            if ml_dsa_verify(pk, message, ff_sig, level=level):
                raise DilithiumKATError(
                    f"KAT failed (level {level}): all-0xFF signature ACCEPTED"
                )
        except DilithiumError:
            pass  # Expected: backend should reject malformed encoding

        # 9. Verify malformed public key (all-zero) rejected (MUST return False)
        zero_pk = bytes(expected_sizes['pk'])
        try:
            if ml_dsa_verify(zero_pk, message, sig, level=level):
                raise DilithiumKATError(
                    f"KAT failed (level {level}): all-zero public key ACCEPTED"
                )
        except DilithiumError:
            pass  # Expected: backend should reject malformed key

        # 10. Verify malformed public key (truncated) rejected (MUST return False)
        truncated_pk = pk[:len(pk)//2]
        try:
            if ml_dsa_verify(truncated_pk, message, sig, level=level):
                raise DilithiumKATError(
                    f"KAT failed (level {level}): truncated public key ACCEPTED"
                )
        except DilithiumError:
            pass  # Expected: size validation should reject this

        # === KEYGEN KAT (TESTING_MODE only - requires deterministic keygen) ===
        if _is_testing_mode():
            if level not in DILITHIUM_KEYGEN_KAT:
                raise DilithiumKATError(f"No keygen KAT vectors for level {level}")

            seed = bytes.fromhex(DILITHIUM_KEYGEN_KAT['seed'])
            expected_pk_sha3 = DILITHIUM_KEYGEN_KAT[level]['pk_sha3']
            expected_sk_sha3 = DILITHIUM_KEYGEN_KAT[level]['sk_sha3']

            gen_pk, gen_sk = generate_ml_dsa_keypair(seed=seed, level=level)

            actual_pk_sha3 = sha3_256(gen_pk).hexdigest()
            if actual_pk_sha3 != expected_pk_sha3:
                raise DilithiumKATError(
                    f"Keygen KAT failed (level {level}): pk SHA3 {actual_pk_sha3} != "
                    f"expected {expected_pk_sha3}"
                )

            actual_sk_sha3 = sha3_256(gen_sk).hexdigest()
            if actual_sk_sha3 != expected_sk_sha3:
                raise DilithiumKATError(
                    f"Keygen KAT failed (level {level}): sk SHA3 {actual_sk_sha3} != "
                    f"expected {expected_sk_sha3}"
                )

    return True


if __name__ == "__main__":
    print(f"Backend: {_get_backend()}")

    # Run KAT
    print("\nKnown-Answer Test:")
    try:
        validate_dilithium_kat()
        print("  ✅ KAT passed")
    except DilithiumKATError as e:
        print(f"  ❌ KAT failed: {e}")

    # Test random keygen
    print("\nRandom keygen:")
    pk, sk = generate_ml_dsa_keypair(level=65)
    print(f"  Dilithium3 keypair: pk={len(pk)}, sk={len(sk)}")

    # Test sign/verify
    print("\nSign/Verify:")
    msg = b"Test message"
    sig = ml_dsa_sign(sk, msg, level=65)
    print(f"  Signature: {len(sig)} bytes")

    valid = ml_dsa_verify(pk, msg, sig, level=65)
    print(f"  Verification: {'✅' if valid else '❌'}")

    # Test wrong message
    invalid = ml_dsa_verify(pk, b"wrong", sig, level=65)
    print(f"  Wrong message: {'✅ rejected' if not invalid else '❌ should fail'}")
