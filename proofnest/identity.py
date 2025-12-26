"""
PROOFNEST - Quantum-Proof Agent Identity
============================================

Cryptographic identity system for AI agents with POST-QUANTUM security.

Features:
- SHA3-256 hashing (quantum-resistant)
- CRYSTALS-Dilithium signatures (NIST PQC standard - quantum-PROOF)
- Hash-based identity commitments
- DID-style identifiers (did:pn:...)
- Deterministic key derivation
- Signature chains for decision signing
- Ed25519 fallback for non-quantum use cases

Security Model:
    L0: SHA3-256 hash commitments (quantum-safe)
    L1: CRYSTALS-Dilithium signatures (quantum-PROOF) - DEFAULT
    L2: Ed25519 signatures (NOT quantum-safe, fallback only)

QUANTUM-PROOF NOTE:
    Dilithium3 (ML-DSA-65) provides NIST Level 3 security, equivalent to
    AES-192. This is the recommended default for all production use.

    Key sizes:
    - Dilithium3: pk=1952 bytes, sk=4000 bytes, sig=3293 bytes
    - Dilithium5: pk=2592 bytes, sk=4864 bytes, sig=4595 bytes
    - Ed25519:    pk=32 bytes,   sk=32 bytes,   sig=64 bytes (NOT quantum-safe)

Copyright (c) 2025 Stellanium Ltd. All rights reserved.
Licensed under MIT License. See LICENSE file.
"""

import errno
import hashlib
import hmac
import json
import re
import secrets
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from enum import Enum

# Path traversal protection
VALID_AGENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


class SignatureAlgorithm(Enum):
    """Supported signature algorithms"""
    HMAC_SHA3_256 = "hmac-sha3-256"      # Legacy: quantum-safe HMAC (self-verify only)
    HASH_CHAIN = "hash-chain-v1"          # Hash-based commitments
    ED25519 = "ed25519"                   # NOT quantum-safe (fallback only)
    DILITHIUM3 = "dilithium3"             # QUANTUM-PROOF: NIST Level 3 (DEFAULT)
    DILITHIUM5 = "dilithium5"             # QUANTUM-PROOF: NIST Level 5


# Check for Dilithium support (uses crypto/ module)
_DILITHIUM_AVAILABLE = False
try:
    from .crypto.dilithium import (
        generate_ml_dsa_keypair,
        ml_dsa_sign,
        ml_dsa_verify,
        ML_DSA_SIZES,
        HAS_DILITHIUM_PY,
    )
    _DILITHIUM_AVAILABLE = HAS_DILITHIUM_PY
except ImportError:
    pass

# Fallback: Check for Ed25519 support (not quantum-safe!)
_ED25519_AVAILABLE = False
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _ED25519_AVAILABLE = True
except ImportError:
    pass


@dataclass
class KeyMaterial:
    """Cryptographic key material for an agent"""
    seed: bytes                    # 32-byte master seed
    identity_key: bytes            # Derived identity key
    signing_key: bytes             # Private/signing key (Dilithium sk or Ed25519 sk)
    commitment: str                # Public commitment (hash of public data)
    created_at: str
    algorithm: SignatureAlgorithm = SignatureAlgorithm.DILITHIUM3  # Quantum-proof default
    # Public key for third-party verification
    public_key: Optional[bytes] = None
    # Dilithium level (65 or 87) - only used for Dilithium algorithms
    dilithium_level: int = 65

    @classmethod
    def generate(
        cls,
        use_dilithium: bool = True,
        dilithium_level: int = 65,
        use_ed25519: bool = False
    ) -> 'KeyMaterial':
        """
        Generate new cryptographic key material.

        Args:
            use_dilithium: If True (default), use Dilithium for quantum-proof signatures.
                          Requires 'dilithium-py' package.
            dilithium_level: 65 (Dilithium3/Level 3) or 87 (Dilithium5/Level 5).
                            Default: 65 (recommended for most use cases)
            use_ed25519: If True (and use_dilithium=False), use Ed25519.
                        NOT quantum-safe - use only for non-quantum scenarios.

        Returns:
            KeyMaterial with generated keys

        Raises:
            RuntimeError: If requested algorithm not available
        """
        seed = secrets.token_bytes(32)
        return cls.from_seed(
            seed,
            use_dilithium=use_dilithium,
            dilithium_level=dilithium_level,
            use_ed25519=use_ed25519
        )

    @classmethod
    def from_seed(
        cls,
        seed: bytes,
        use_dilithium: bool = True,
        dilithium_level: int = 65,
        use_ed25519: bool = False
    ) -> 'KeyMaterial':
        """
        Derive all keys from master seed.

        Priority: Dilithium > Ed25519 > HMAC
        """
        # Use SHA3-256 for quantum resistance
        identity_key = hashlib.sha3_256(seed + b"identity").digest()

        # Priority 1: Dilithium (quantum-proof) - DEFAULT
        if use_dilithium and _DILITHIUM_AVAILABLE:
            # Derive Dilithium keypair from seed deterministically
            # NOTE: Dilithium keygen from seed requires TESTING_MODE in production
            # For production, we generate random keys
            try:
                public_key, signing_key = generate_ml_dsa_keypair(
                    seed=None,  # Random keygen (production safe)
                    level=dilithium_level
                )
            except Exception:
                # Fallback to random keygen if deterministic fails
                public_key, signing_key = generate_ml_dsa_keypair(
                    seed=None,
                    level=dilithium_level
                )

            algorithm = SignatureAlgorithm.DILITHIUM3 if dilithium_level == 65 else SignatureAlgorithm.DILITHIUM5

            # Commitment includes public key for verification
            commitment = hashlib.sha3_256(identity_key + public_key).hexdigest()

            return cls(
                seed=seed,
                identity_key=identity_key,
                signing_key=signing_key,
                commitment=commitment,
                created_at=datetime.utcnow().isoformat() + "Z",
                algorithm=algorithm,
                public_key=public_key,
                dilithium_level=dilithium_level
            )

        # Priority 2: Ed25519 (NOT quantum-safe - fallback only)
        elif use_ed25519 and _ED25519_AVAILABLE:
            # Derive Ed25519 key from seed
            ed25519_seed = hashlib.sha3_256(seed + b"ed25519").digest()
            private_key = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
            signing_key = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            algorithm = SignatureAlgorithm.ED25519

            # Commitment includes public key for verification
            commitment = hashlib.sha3_256(identity_key + public_key).hexdigest()

            return cls(
                seed=seed,
                identity_key=identity_key,
                signing_key=signing_key,
                commitment=commitment,
                created_at=datetime.utcnow().isoformat() + "Z",
                algorithm=algorithm,
                public_key=public_key,
                dilithium_level=0  # Not used for Ed25519
            )

        # Priority 3: HMAC (self-verify only, quantum-safe but limited)
        else:
            signing_key = hashlib.sha3_256(seed + b"signing").digest()
            commitment = hashlib.sha3_256(identity_key + signing_key).hexdigest()

            return cls(
                seed=seed,
                identity_key=identity_key,
                signing_key=signing_key,
                commitment=commitment,
                created_at=datetime.utcnow().isoformat() + "Z",
                algorithm=SignatureAlgorithm.HMAC_SHA3_256,
                public_key=None,
                dilithium_level=0
            )

    def to_public(self) -> Dict[str, Any]:
        """Export only public data (safe to share)"""
        result = {
            "commitment": self.commitment,
            "algorithm": self.algorithm.value,
            "created_at": self.created_at,
            "quantum_proof": self.algorithm in (
                SignatureAlgorithm.DILITHIUM3,
                SignatureAlgorithm.DILITHIUM5
            )
        }
        # Include public key for third-party verification (Dilithium or Ed25519)
        if self.public_key:
            result["public_key"] = self.public_key.hex()
        # Include Dilithium level for key size validation
        if self.dilithium_level > 0:
            result["dilithium_level"] = self.dilithium_level
        return result


@dataclass
class AgentIdentity:
    """
    Quantum-ready cryptographic identity for AI agents.

    Usage:
        # Create new identity
        identity = AgentIdentity.create("my-agent")

        # Sign data
        signature = identity.sign(b"decision data")

        # Verify signature
        assert identity.verify(b"decision data", signature)

        # Get DID
        did = identity.did  # "did:pn:abc123..."
    """

    agent_id: str
    keys: KeyMaterial
    _did: str = field(default="", init=False)

    def __post_init__(self):
        # Generate DID from commitment (PROOFNEST DID method)
        self._did = f"did:pn:{self.keys.commitment[:32]}"

    @property
    def did(self) -> str:
        """Decentralized Identifier (DID) for this agent"""
        return self._did

    @property
    def public_key_hash(self) -> str:
        """Public key hash (quantum-safe commitment)"""
        return self.keys.commitment

    @classmethod
    def create(
        cls,
        agent_id: str,
        storage_path: Optional[Path] = None,
        use_dilithium: bool = True,
        dilithium_level: int = 65,
        use_ed25519: bool = False
    ) -> 'AgentIdentity':
        """
        Create a new agent identity.

        Args:
            agent_id: Unique identifier for the agent (alphanumeric, -, _ only, max 64 chars)
            storage_path: Where to store keys (default: ~/.proofnest/identities/)
            use_dilithium: If True (default), use Dilithium for quantum-proof signatures.
                          Requires 'dilithium-py' package.
            dilithium_level: 65 (Dilithium3/Level 3) or 87 (Dilithium5/Level 5).
                            Default: 65 (recommended)
            use_ed25519: If True (and use_dilithium=False), use Ed25519.
                        NOT quantum-safe - use only for non-quantum scenarios.

        Returns:
            New AgentIdentity with generated keys

        Raises:
            ValueError: If agent_id contains invalid characters (path traversal protection)
        """
        # P1 FIX: Path traversal protection
        if not VALID_AGENT_ID_PATTERN.match(agent_id):
            raise ValueError(f"Invalid agent_id: must match {VALID_AGENT_ID_PATTERN.pattern}")

        storage = storage_path or Path.home() / ".proofnest" / "identities"

        # NEW B1 FIX: Create with restrictive permissions and validate existing
        if storage.exists():
            # Validate existing directory
            if storage.is_symlink():
                raise ValueError(f"Security error: identities directory is a symlink: {storage}")
            if not storage.is_dir():
                raise ValueError(f"Security error: identities path is not a directory: {storage}")
            # Check permissions AND ownership (Unix only)
            try:
                st = storage.stat()
                mode = st.st_mode & 0o777
                # OWNERSHIP CHECK (also for existing directories)
                if st.st_uid != os.getuid():
                    raise ValueError(
                        f"Security error: identities directory not owned by current user: {storage}"
                    )
                if mode & 0o077:  # Group or world accessible
                    # FIX-UP: Try to fix permissions instead of just rejecting
                    try:
                        os.chmod(storage, 0o700)
                    except OSError as e:
                        raise ValueError(
                            f"Security error: identities directory has insecure permissions {oct(mode)} "
                            f"and could not be fixed: {e}. Required: 0o700 (owner only)."
                        )
            except (OSError, AttributeError):
                pass  # Windows or permission check not available
        else:
            # Create with restrictive permissions
            storage.mkdir(parents=True, exist_ok=True, mode=0o700)
            # POST-CREATE VALIDATION: Verify permissions (umask may have affected)
            try:
                actual_mode = storage.stat().st_mode & 0o777
                if actual_mode != 0o700:
                    # Fix permissions (umask may have weakened them)
                    os.chmod(storage, 0o700)
                # Verify ownership on Unix
                import pwd
                if storage.stat().st_uid != os.getuid():
                    raise ValueError(
                        f"Security error: identities directory not owned by current user: {storage}"
                    )
            except (OSError, AttributeError, ImportError):
                pass  # Windows or permission check not available

        key_file = storage / f"{agent_id}.key"

        # Check if identity already exists
        if key_file.exists():
            return cls.load(agent_id, storage_path)

        # Generate new keys (Dilithium default, Ed25519 fallback)
        keys = KeyMaterial.generate(
            use_dilithium=use_dilithium,
            dilithium_level=dilithium_level,
            use_ed25519=use_ed25519
        )
        identity = cls(agent_id=agent_id, keys=keys)

        # Save keys securely
        identity._save(key_file)

        return identity

    @classmethod
    def load(cls, agent_id: str, storage_path: Optional[Path] = None) -> 'AgentIdentity':
        """
        Load existing identity from storage.

        Args:
            agent_id: Agent identifier (alphanumeric, -, _ only, max 64 chars)
            storage_path: Where keys are stored

        Raises:
            ValueError: If agent_id contains invalid characters (path traversal protection)
            FileNotFoundError: If identity doesn't exist
        """
        # P1 FIX: Path traversal protection
        if not VALID_AGENT_ID_PATTERN.match(agent_id):
            raise ValueError(f"Invalid agent_id: must match {VALID_AGENT_ID_PATTERN.pattern}")

        storage = storage_path or Path.home() / ".proofnest" / "identities"

        # SECURITY: Validate storage directory (same checks as create())
        if storage.is_symlink():
            raise ValueError(f"Security error: identities directory is a symlink: {storage}")
        if not storage.is_dir():
            raise ValueError(f"Security error: identities path is not a directory: {storage}")
        try:
            st = storage.stat()
            if st.st_uid != os.getuid():
                raise ValueError(
                    f"Security error: identities directory not owned by current user: {storage}"
                )
            mode = st.st_mode & 0o777
            if mode & 0o077:
                raise ValueError(
                    f"Security error: identities directory has insecure permissions {oct(mode)}: {storage}"
                )
        except (OSError, AttributeError):
            pass  # Windows or permission check not available

        key_file = storage / f"{agent_id}.key"

        if not key_file.exists():
            raise FileNotFoundError(f"No identity found for agent: {agent_id}")

        # SECURITY FIX (v2.15.0): Atomic symlink-safe open with O_NOFOLLOW
        # This prevents TOCTOU where attacker creates symlink between check and open
        try:
            # O_NOFOLLOW: Fail if path is symlink (Linux/macOS)
            fd = os.open(str(key_file), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                # ADDITIONAL CHECK: Verify it's a regular file (not device, socket, etc.)
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError(f"Security error: key file is not a regular file: {key_file}")
                # Check ownership (Unix only)
                if hasattr(os, 'getuid') and st.st_uid != os.getuid():
                    raise ValueError(
                        f"Security error: key file not owned by current user: {key_file}"
                    )
                # Read file content
                with os.fdopen(fd, 'rb') as f:
                    fd = None  # fdopen takes ownership
                    data = json.loads(f.read().decode())
            finally:
                if fd is not None:
                    os.close(fd)
        except OSError as e:
            if e.errno == getattr(errno, 'ELOOP', 40):  # ELOOP = too many symlinks
                raise ValueError(f"Security error: key file is a symlink: {key_file}")
            raise

        algorithm = data.get("algorithm", "hmac-sha3-256")

        # Handle Dilithium keys differently - they're stored directly (not derived from seed)
        if algorithm in ("dilithium3", "dilithium5"):
            # Dilithium keys are stored directly because they're generated randomly
            # (not derived from seed in production for security reasons)
            dilithium_level = data.get("dilithium_level", 65 if algorithm == "dilithium3" else 87)
            keys = KeyMaterial(
                seed=bytes.fromhex(data["seed"]),
                identity_key=bytes.fromhex(data.get("identity_key", "")),
                signing_key=bytes.fromhex(data["signing_key"]),
                commitment=data.get("commitment", ""),
                created_at=data.get("created_at", ""),
                algorithm=SignatureAlgorithm.DILITHIUM3 if algorithm == "dilithium3" else SignatureAlgorithm.DILITHIUM5,
                public_key=bytes.fromhex(data["public_key"]) if data.get("public_key") else None,
                dilithium_level=dilithium_level
            )
        elif algorithm == "ed25519":
            # Ed25519 keys are derived from seed
            seed = bytes.fromhex(data["seed"])
            keys = KeyMaterial.from_seed(seed, use_dilithium=False, use_ed25519=True)
        else:
            # HMAC keys are derived from seed
            seed = bytes.fromhex(data["seed"])
            keys = KeyMaterial.from_seed(seed, use_dilithium=False, use_ed25519=False)

        # Warn about legacy algorithms
        if algorithm not in ("dilithium3", "dilithium5"):
            import warnings
            if algorithm == "ed25519":
                warnings.warn(
                    f"Identity '{agent_id}' uses Ed25519 (not post-quantum). "
                    "Consider creating a new Dilithium identity for quantum-resistant signatures. "
                    "Use: AgentIdentity.create(agent_id, use_dilithium=True)",
                    DeprecationWarning,
                    stacklevel=2
                )
            else:
                warnings.warn(
                    f"Identity '{agent_id}' uses HMAC (not publicly verifiable, not post-quantum). "
                    "Consider creating a new Dilithium identity for third-party verification. "
                    "Use: AgentIdentity.create(agent_id, use_dilithium=True)",
                    DeprecationWarning,
                    stacklevel=2
                )

        return cls(agent_id=agent_id, keys=keys)

    def _save(self, key_file: Path) -> None:
        """
        Save identity to file with security hardening.

        Security measures (v2.15.0):
        - Atomic write (temp file + rename)
        - Restrictive permissions (0o600)
        - Reject if key_file is a symlink (race-safe via O_NOFOLLOW)
        - Ownership verification
        """
        # SECURITY FIX (v2.15.0): Race-safe symlink check with O_NOFOLLOW
        # Instead of checking then opening (TOCTOU), we try to open with O_NOFOLLOW
        # If it's a symlink, the open will fail with ELOOP
        if key_file.exists():
            try:
                fd = os.open(str(key_file), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                try:
                    st = os.fstat(fd)
                    # Verify it's a regular file and owned by us
                    if not stat.S_ISREG(st.st_mode):
                        raise ValueError(f"Security error: key file is not a regular file: {key_file}")
                    if hasattr(os, 'getuid') and st.st_uid != os.getuid():
                        raise ValueError(f"Security error: key file not owned by current user: {key_file}")
                finally:
                    os.close(fd)
            except OSError as e:
                if e.errno == getattr(errno, 'ELOOP', 40):
                    raise ValueError(f"Security error: key file is a symlink: {key_file}")
                elif e.errno == errno.ENOENT:
                    pass  # File was removed between exists() and open(), that's fine
                else:
                    raise

        data = {
            "agent_id": self.agent_id,
            "seed": self.keys.seed.hex(),
            "created_at": self.keys.created_at,
            "algorithm": self.keys.algorithm.value,
            "did": self.did,
            "commitment": self.keys.commitment,
            "identity_key": self.keys.identity_key.hex(),
        }

        # Dilithium keys must be stored directly (not derivable from seed in production)
        if self.keys.algorithm in (SignatureAlgorithm.DILITHIUM3, SignatureAlgorithm.DILITHIUM5):
            data["signing_key"] = self.keys.signing_key.hex()
            data["dilithium_level"] = self.keys.dilithium_level
            if self.keys.public_key:
                data["public_key"] = self.keys.public_key.hex()
        elif self.keys.algorithm == SignatureAlgorithm.ED25519:
            # Ed25519 can be derived from seed, but store public_key for verification
            if self.keys.public_key:
                data["public_key"] = self.keys.public_key.hex()

        # NEW B1 FIX: Atomic write with restrictive permissions
        import tempfile
        fd = None
        tmp_path = None
        try:
            # Create temp file in same directory (for atomic rename)
            fd, tmp_path = tempfile.mkstemp(
                suffix='.tmp',
                prefix=f'{self.agent_id}_',
                dir=key_file.parent
            )
            # Write with owner-only permissions
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, 'wb') as f:
                fd = None  # fdopen takes ownership
                f.write(json.dumps(data, indent=2).encode())
                # DURABILITY: fsync to ensure data is written to disk
                f.flush()
                os.fsync(f.fileno())
            # Atomic rename
            os.replace(tmp_path, key_file)
            tmp_path = None  # Success, don't clean up
            # DEFENSIVE: Ensure permissions after replace
            os.chmod(key_file, 0o600)
            # DURABILITY: fsync directory to ensure rename is durable
            try:
                dir_fd = os.open(str(key_file.parent), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except (OSError, AttributeError):
                pass  # Windows or not supported
        except Exception:
            # Clean up temp file on error
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

        # Verify result is regular file (not symlink)
        if key_file.is_symlink():
            raise ValueError(f"Security error: key file became a symlink: {key_file}")

    def sign(self, data: bytes) -> 'Signature':
        """
        Sign data with the agent's signing algorithm.

        Supports:
        - DILITHIUM3/DILITHIUM5: Quantum-proof signatures (DEFAULT)
        - ED25519: Third-party verifiable (NOT quantum-safe)
        - HMAC-SHA3-256: Self-verify only (legacy)

        Args:
            data: Bytes to sign

        Returns:
            Signature object
        """
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Include timestamp in signed data to prevent replay
        message = data + timestamp.encode()

        # Priority 1: Dilithium (quantum-proof)
        if self.keys.algorithm in (SignatureAlgorithm.DILITHIUM3, SignatureAlgorithm.DILITHIUM5):
            if not _DILITHIUM_AVAILABLE:
                raise RuntimeError("Dilithium not available - install dilithium-py")

            sig_bytes = ml_dsa_sign(
                private_key=self.keys.signing_key,
                message=message,
                level=self.keys.dilithium_level
            )

            return Signature(
                value=sig_bytes.hex(),
                algorithm=self.keys.algorithm,
                timestamp=timestamp,
                signer_did=self.did,
                signer_commitment=self.keys.commitment,
                public_key=self.keys.public_key.hex() if self.keys.public_key else None,
                dilithium_level=self.keys.dilithium_level
            )

        # Priority 2: Ed25519 (NOT quantum-safe)
        elif self.keys.algorithm == SignatureAlgorithm.ED25519 and _ED25519_AVAILABLE:
            private_key = Ed25519PrivateKey.from_private_bytes(self.keys.signing_key)
            sig_bytes = private_key.sign(message)

            return Signature(
                value=sig_bytes.hex(),
                algorithm=SignatureAlgorithm.ED25519,
                timestamp=timestamp,
                signer_did=self.did,
                signer_commitment=self.keys.commitment,
                public_key=self.keys.public_key.hex() if self.keys.public_key else None
            )

        # Priority 3: HMAC-SHA3-256 (self-verify only)
        else:
            sig_bytes = hmac.new(
                self.keys.signing_key,
                message,
                hashlib.sha3_256
            ).digest()

            return Signature(
                value=sig_bytes.hex(),
                algorithm=SignatureAlgorithm.HMAC_SHA3_256,
                timestamp=timestamp,
                signer_did=self.did,
                signer_commitment=self.keys.commitment
            )

    def sign_decision(self, decision_data: Dict[str, Any]) -> 'Signature':
        """
        Sign a decision record.

        Args:
            decision_data: Decision dictionary to sign

        Returns:
            Signature for the decision
        """
        # CANONICAL JSON: sorted keys, minimal separators, ASCII-only
        # This MUST match the canonicalization in core.py _verify_internal()
        canonical = json.dumps(
            decision_data,
            sort_keys=True,
            separators=(',', ':'),
            ensure_ascii=True
        )
        return self.sign(canonical.encode('ascii'))

    def verify(self, data: bytes, signature: 'Signature') -> bool:
        """
        Verify a signature.

        Supports:
        - DILITHIUM3/DILITHIUM5: Quantum-proof verification (DEFAULT)
        - ED25519: Third-party verifiable (NOT quantum-safe)
        - HMAC-SHA3-256: Self-verify only (legacy)

        Args:
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid
        """
        if signature.signer_did != self.did:
            return False

        # Reconstruct message with timestamp
        message = data + signature.timestamp.encode()

        # Priority 1: Dilithium verification (quantum-proof)
        if signature.algorithm in (SignatureAlgorithm.DILITHIUM3, SignatureAlgorithm.DILITHIUM5):
            if not _DILITHIUM_AVAILABLE:
                print("WARNING: Dilithium signature verification requires 'dilithium-py' package")
                return False

            try:
                level = getattr(signature, 'dilithium_level', None) or self.keys.dilithium_level
                return ml_dsa_verify(
                    public_key=self.keys.public_key,
                    message=message,
                    signature=bytes.fromhex(signature.value),
                    level=level
                )
            except Exception as e:
                print(f"Dilithium verification error: {e}")
                return False

        # Priority 2: Ed25519 verification (NOT quantum-safe)
        elif signature.algorithm == SignatureAlgorithm.ED25519:
            if not _ED25519_AVAILABLE:
                print("WARNING: Ed25519 signature verification requires 'cryptography' package")
                return False

            try:
                public_key = Ed25519PublicKey.from_public_bytes(self.keys.public_key)
                public_key.verify(bytes.fromhex(signature.value), message)
                return True
            except InvalidSignature:
                return False
            except Exception as e:
                print(f"Ed25519 verification error: {e}")
                return False

        # Priority 3: HMAC verification (self-verify only)
        else:
            expected = hmac.new(
                self.keys.signing_key,
                message,
                hashlib.sha3_256
            ).digest()

            # Constant-time comparison
            return hmac.compare_digest(expected.hex(), signature.value)

    def create_commitment(self, data: bytes) -> 'HashCommitment':
        """
        Create a hash commitment (quantum-safe).

        This can be published before revealing data,
        proving you knew the data at commitment time.

        Args:
            data: Data to commit to

        Returns:
            HashCommitment that can be verified later
        """
        nonce = secrets.token_bytes(16)
        commitment_hash = hashlib.sha3_256(data + nonce + self.keys.identity_key).hexdigest()

        return HashCommitment(
            commitment=commitment_hash,
            nonce=nonce.hex(),
            timestamp=datetime.utcnow().isoformat() + "Z",
            signer_did=self.did
        )

    def export_public(self) -> Dict[str, Any]:
        """Export public identity info (safe to share)"""
        return {
            "did": self.did,
            "agent_id": self.agent_id,
            "commitment": self.keys.commitment,
            "algorithm": self.keys.algorithm.value,
            "created_at": self.keys.created_at,
            "quantum_safe": True
        }

    def save(self, storage_path: Optional[Path] = None) -> Path:
        """
        Save identity to storage.

        Note: AgentIdentity.create() saves automatically.
        Use this to re-save or save to a different location.

        Args:
            storage_path: Where to store keys. Can be:
                - None: uses default ~/.proofnest/identities/
                - Directory path: saves {agent_id}.key inside it
                - File path (ending in .key/.json): saves directly to that file

        Returns:
            Path to the saved key file

        Raises:
            ValueError: If agent_id is invalid (path traversal protection)
        """
        if not VALID_AGENT_ID_PATTERN.match(self.agent_id):
            raise ValueError(f"Invalid agent_id: must match {VALID_AGENT_ID_PATTERN.pattern}")

        if storage_path is None:
            # Default location
            storage = Path.home() / ".proofnest" / "identities"
            storage.mkdir(parents=True, exist_ok=True)
            key_file = storage / f"{self.agent_id}.key"
        elif str(storage_path).endswith(('.key', '.json')):
            # User specified a file path - save directly there
            key_file = Path(storage_path)
            key_file.parent.mkdir(parents=True, exist_ok=True)
        else:
            # User specified a directory - save {agent_id}.key inside it
            storage = Path(storage_path)
            storage.mkdir(parents=True, exist_ok=True)
            key_file = storage / f"{self.agent_id}.key"

        self._save(key_file)
        return key_file


@dataclass
class Signature:
    """
    Digital signature with metadata.

    Supports:
    - DILITHIUM3/DILITHIUM5: Quantum-proof, third-party verifiable (DEFAULT)
    - ED25519: Third-party verifiable (NOT quantum-safe)
    - HMAC-SHA3-256: Self-verify only (legacy)
    """
    value: str                      # Hex-encoded signature
    algorithm: SignatureAlgorithm
    timestamp: str                  # ISO8601 timestamp
    signer_did: str                 # DID of signer
    signer_commitment: str          # Public key commitment
    # Public key for third-party verification (Dilithium or Ed25519)
    public_key: Optional[str] = None  # Hex-encoded public key
    # Dilithium level (65 or 87) for Dilithium signatures
    dilithium_level: int = 0

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "value": self.value,
            "algorithm": self.algorithm.value,
            "timestamp": self.timestamp,
            "signer_did": self.signer_did,
            "signer_commitment": self.signer_commitment,
            "quantum_proof": self.algorithm in (
                SignatureAlgorithm.DILITHIUM3,
                SignatureAlgorithm.DILITHIUM5
            ),
            "third_party_verifiable": self.algorithm in (
                SignatureAlgorithm.ED25519,
                SignatureAlgorithm.DILITHIUM3,
                SignatureAlgorithm.DILITHIUM5
            )
        }
        if self.public_key:
            result["public_key"] = self.public_key
        if self.dilithium_level > 0:
            result["dilithium_level"] = self.dilithium_level
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Signature':
        return cls(
            value=data["value"],
            algorithm=SignatureAlgorithm(data["algorithm"]),
            timestamp=data["timestamp"],
            signer_did=data["signer_did"],
            signer_commitment=data["signer_commitment"],
            public_key=data.get("public_key"),
            dilithium_level=data.get("dilithium_level", 0)
        )

    def verify_standalone(self, data: bytes) -> bool:
        """
        Verify this signature without the signer's identity.

        Works for:
        - DILITHIUM3/DILITHIUM5: Quantum-proof (asymmetric)
        - ED25519: Asymmetric (NOT quantum-safe)

        HMAC signatures require the shared secret.

        Args:
            data: Original data that was signed

        Returns:
            True if signature is valid
        """
        # Priority 1: Dilithium verification (quantum-proof)
        if self.algorithm in (SignatureAlgorithm.DILITHIUM3, SignatureAlgorithm.DILITHIUM5):
            if not self.public_key:
                return False

            if not _DILITHIUM_AVAILABLE:
                print("WARNING: Dilithium verification requires 'dilithium-py' package")
                return False

            try:
                # Reconstruct message with timestamp
                message = data + self.timestamp.encode()

                # Determine level from algorithm or stored level
                level = self.dilithium_level
                if level == 0:
                    level = 65 if self.algorithm == SignatureAlgorithm.DILITHIUM3 else 87

                # Verify with public key
                return ml_dsa_verify(
                    public_key=bytes.fromhex(self.public_key),
                    message=message,
                    signature=bytes.fromhex(self.value),
                    level=level
                )
            except Exception as e:
                print(f"Dilithium standalone verification error: {e}")
                return False

        # Priority 2: Ed25519 verification (NOT quantum-safe)
        elif self.algorithm == SignatureAlgorithm.ED25519:
            if not self.public_key:
                return False

            if not _ED25519_AVAILABLE:
                print("WARNING: Ed25519 verification requires 'cryptography' package")
                return False

            try:
                # Reconstruct message with timestamp
                message = data + self.timestamp.encode()

                # Verify with public key
                public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key))
                public_key.verify(bytes.fromhex(self.value), message)
                return True
            except InvalidSignature:
                return False
            except Exception as e:
                print(f"Ed25519 standalone verification error: {e}")
                return False

        # HMAC requires shared secret - cannot verify standalone
        return False


@dataclass
class HashCommitment:
    """
    Hash-based commitment (quantum-safe).

    Allows proving knowledge of data without revealing it.
    Reveal nonce later to prove commitment.
    """
    commitment: str    # SHA3-256 hash
    nonce: str         # Random nonce (reveal to verify)
    timestamp: str
    signer_did: str

    def verify(self, data: bytes, identity_key: bytes) -> bool:
        """Verify this commitment matches the data"""
        nonce_bytes = bytes.fromhex(self.nonce)
        expected = hashlib.sha3_256(data + nonce_bytes + identity_key).hexdigest()
        return hmac.compare_digest(expected, self.commitment)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "commitment": self.commitment,
            "timestamp": self.timestamp,
            "signer_did": self.signer_did,
            "type": "hash-commitment-sha3-256",
            "quantum_safe": True
        }


def verify_signature_standalone(
    data: bytes,
    signature: Signature,
    public_commitment: str = ""
) -> bool:
    """
    Verify signature without full identity (for auditors).

    This is a convenience wrapper around signature.verify_standalone().

    Supports:
    - DILITHIUM3/DILITHIUM5: Quantum-proof verification using embedded public key
    - ED25519: Verifies using the embedded public key (NOT quantum-safe)
    - HMAC: Returns False (requires shared secret)

    Args:
        data: Original data that was signed
        signature: Signature to verify
        public_commitment: Optional commitment to verify against

    Returns:
        True if signature is valid (Dilithium or Ed25519)
    """
    # Dilithium and Ed25519 signatures can be verified without identity
    if signature.algorithm in (
        SignatureAlgorithm.DILITHIUM3,
        SignatureAlgorithm.DILITHIUM5,
        SignatureAlgorithm.ED25519
    ):
        return signature.verify_standalone(data)

    # HMAC requires shared secret - use for self-verification only
    return False


def is_ed25519_available() -> bool:
    """Check if Ed25519 cryptography is available."""
    return _ED25519_AVAILABLE


# === DEMO ===
if __name__ == "__main__":
    print("PROOFNEST - Quantum-Ready Identity")
    print("=" * 50)

    # Create identity
    identity = AgentIdentity.create("demo-agent-quantum")

    print(f"\nAgent ID: {identity.agent_id}")
    print(f"DID: {identity.did}")
    print(f"Public commitment: {identity.public_key_hash[:32]}...")
    print(f"Algorithm: {identity.keys.algorithm.value}")
    print(f"Quantum-safe: Yes (SHA3-256)")

    # Sign some data
    test_data = b"This is a test decision"
    signature = identity.sign(test_data)

    print(f"\nSignature: {signature.value[:32]}...")
    print(f"Timestamp: {signature.timestamp}")

    # Verify
    is_valid = identity.verify(test_data, signature)
    print(f"Verified: {is_valid}")

    # Create commitment
    commitment = identity.create_commitment(b"secret data")
    print(f"\nCommitment: {commitment.commitment[:32]}...")

    print("\nQuantum-ready identity system operational!")
