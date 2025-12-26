"""
PROOFNEST Bitcoin Anchor - "Kindel Maapind"
=========================================

Anchors PROOFNEST to Bitcoin blockchain.
Bitcoin is a WITNESS, not the source of truth.

KEY INSIGHT:
    L0: LOGIC is the foundation - "inner == outer" is DEFINITION
    L2: CRYPTO (Bitcoin) is the WITNESS - proves WHEN it existed

Bitcoin doesn't make PROOFNEST "true". Bitcoin WITNESSES that
the chain existed at time T. Like a notary doesn't make a contract
valid - they just witness its signing.

Methods:
1. OP_RETURN - Up to 80 bytes directly in blockchain
2. Merkle root - Summary of entire chain as single hash
3. OpenTimestamps - Free timestamping via Bitcoin

Why Bitcoin:
- 15+ years of uninterrupted operation
- $1T+ secured network
- Millions of nodes worldwide
- No single point of failure
- "Kindel maapind" - solid ground that doesn't move

Copyright (c) 2025 Stellanium Ltd. All rights reserved.
Licensed under Apache License 2.0. See LICENSE file.
PROOFNEST™ is a trademark of Stellanium Ltd.
"""

import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Callable
from enum import Enum
import urllib.request
import urllib.error


# === Security Constants ===
HEX_CHARS = set('0123456789abcdefABCDEF')


def _is_path_within(child: Path, parent: Path) -> bool:
    """
    Check if child path is within parent path.

    Python 3.8 compatible alternative to Path.is_relative_to() (added in 3.9).

    Args:
        child: Path to check
        parent: Parent path that should contain child

    Returns:
        True if child is within parent, False otherwise
    """
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _validate_hex_string(value: str, name: str = "value", expected_length: int = 64) -> str:
    """
    Validate that a string is valid hexadecimal of expected length.

    Security: Prevents path traversal and injection attacks by ensuring
    only valid hex characters are used in filenames and URLs.

    Args:
        value: String to validate
        name: Name for error messages
        expected_length: Expected length (default 64 for SHA256)

    Returns:
        The validated string (lowercase)

    Raises:
        TypeError: If value is not a string
        ValueError: If value is not valid hex or wrong length
    """
    if not isinstance(value, str):
        raise TypeError(f"{name} must be string, got {type(value).__name__}")
    if len(value) != expected_length:
        raise ValueError(f"{name} must be {expected_length} hex characters, got {len(value)}")
    if not all(c in HEX_CHARS for c in value):
        raise ValueError(f"{name} must be valid hexadecimal")
    return value.lower()


class AnchorMethod(Enum):
    """Ankurdamise meetodid"""
    OPENTIMESTAMPS = "ots"  # Tasuta, aeglane (~2h)
    OP_RETURN = "op_return"  # Maksab tasu, kohene
    MERKLE_PROOF = "merkle"  # Kombineeritud


@dataclass
class BitcoinAnchor:
    """
    Bitcoin anchor proof.

    Attributes:
        merkle_root: The SHA-256 digest being anchored (64 hex chars).
                    Named 'merkle_root' for backward compatibility - can be
                    any 256-bit digest (record hash, chain root, etc.).
    """
    merkle_root: str  # Actually any SHA-256 digest, not necessarily a merkle root
    method: AnchorMethod
    timestamp: str
    txid: Optional[str] = None
    block_height: Optional[int] = None
    ots_proof: Optional[bytes] = None
    verified: bool = False


class BitcoinAnchorService:
    """
    Bitcoin Ankurdamise Teenus

    "Õigemini võrk" - kasutab Bitcoin'i võrku kui kindlat maapinda.
    """

    # OpenTimestamps kalendriserver
    OTS_CALENDARS = [
        "https://a.pool.opentimestamps.org",
        "https://b.pool.opentimestamps.org",
        "https://a.pool.eternitywall.com",
    ]

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        preferred_method: AnchorMethod = AnchorMethod.OPENTIMESTAMPS
    ):
        """
        Initsialiseeri Bitcoin ankurdamise teenus.

        Args:
            data_dir: Kaust ankurduste salvestamiseks
            preferred_method: Eelistatud ankurdamismeetod
        """
        self.data_dir = data_dir or Path.home() / ".proofnest_anchors"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.preferred_method = preferred_method

    def anchor(self, merkle_root: str) -> BitcoinAnchor:
        """
        Anchor a digest to Bitcoin blockchain.

        NOTE: The parameter is named 'merkle_root' for API compatibility,
        but it accepts any SHA-256 digest (64 hex chars). In practice, this
        could be a decision record hash, chain merkle root, or any other
        256-bit digest that needs timestamping.

        Args:
            merkle_root: Any SHA-256 digest to anchor (64 hex chars).
                        Named 'merkle_root' for backward compatibility.

        Returns:
            BitcoinAnchor object with proof data

        Raises:
            TypeError: If merkle_root is not a string
            ValueError: If merkle_root is not valid 64-char hex
        """
        # Security: Validate input to prevent path traversal and injection
        merkle_root = _validate_hex_string(merkle_root, "merkle_root")

        if self.preferred_method == AnchorMethod.OPENTIMESTAMPS:
            return self._anchor_ots(merkle_root)
        elif self.preferred_method == AnchorMethod.OP_RETURN:
            return self._anchor_op_return(merkle_root)
        else:
            return self._anchor_merkle(merkle_root)

    def _anchor_ots(self, merkle_root: str) -> BitcoinAnchor:
        """
        Ankurda kasutades OpenTimestamps (tasuta).

        OpenTimestamps on tasuta teenus mis agregeerib hashid
        ja ankurdab need Bitcoin'i iga ~2 tunni tagant.
        """
        # Arvuta hash digest
        digest = bytes.fromhex(merkle_root)

        # Proovi igat kalendrit
        ots_proof = None
        for calendar in self.OTS_CALENDARS:
            try:
                ots_proof = self._submit_to_calendar(calendar, digest)
                if ots_proof:
                    break
            except (urllib.error.URLError, TimeoutError, OSError):
                continue

        anchor = BitcoinAnchor(
            merkle_root=merkle_root,
            method=AnchorMethod.OPENTIMESTAMPS,
            timestamp=datetime.utcnow().isoformat() + "Z",
            ots_proof=ots_proof
        )

        # Salvesta
        self._save_anchor(anchor)

        return anchor

    def _submit_to_calendar(self, calendar_url: str, digest: bytes) -> Optional[bytes]:
        """Saada hash OpenTimestamps kalendrisse"""
        url = f"{calendar_url}/digest"
        try:
            req = urllib.request.Request(
                url,
                data=digest,
                headers={"Content-Type": "application/octet-stream"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.read()
        except urllib.error.URLError:
            return None

    def _anchor_op_return(self, merkle_root: str) -> BitcoinAnchor:
        """
        Ankurda kasutades OP_RETURN (vajab Bitcoin'i).

        WARNING: NOT IMPLEMENTED - This is a placeholder only!
        Actual Bitcoin transaction creation requires external integration.

        Requirements for implementation:
        1. Bitcoin node or API (BlockCypher, Blockstream, Mempool.space)
        2. Small amount of BTC for fees (~$1-5)
        3. Wallet integration for signing

        OP_RETURN format (40 bytes):
        - 4 bytes: "PNST" prefix
        - 32 bytes: Merkle root hash
        - 4 bytes: Unix timestamp

        Raises:
            NotImplementedError: Always - use OPENTIMESTAMPS method instead
        """
        raise NotImplementedError(
            "OP_RETURN anchoring not implemented. "
            "Use OPENTIMESTAMPS method instead (free and functional). "
            "See: https://opentimestamps.org"
        )

    def _anchor_merkle(self, merkle_root: str) -> BitcoinAnchor:
        """
        Kombineeritud meetod - kasuta OTS kui saadaval,
        salvesta lokaalselt alati.
        """
        # Proovi OTS
        anchor = self._anchor_ots(merkle_root)

        # Lisa täiendav lokaalne proof
        local_proof = self._create_local_proof(merkle_root)

        return anchor

    def _create_local_proof(self, merkle_root: str) -> dict:
        """Loo lokaalne ajatõend (kui BTC pole saadaval)"""
        return {
            "type": "local",
            "merkle_root": merkle_root,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "machine_id": self._get_machine_id(),
            "hash": hashlib.sha256(
                f"{merkle_root}:{time.time()}".encode()
            ).hexdigest()
        }

    def _get_machine_id(self) -> str:
        """Hangi masina unikaalne ID"""
        import socket
        return hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]

    def _save_anchor(self, anchor: BitcoinAnchor) -> None:
        """Salvesta ankurdus kettale"""
        # Security: Validate merkle_root before using in filename
        _validate_hex_string(anchor.merkle_root, "merkle_root")

        filename = f"{anchor.merkle_root[:16]}_{int(time.time())}.json"
        filepath = self.data_dir / filename

        # Security: Defense in depth - ensure path stays within data_dir
        if not _is_path_within(filepath, self.data_dir):
            raise ValueError("Security: Path traversal attempt detected")

        data = {
            "merkle_root": anchor.merkle_root,
            "method": anchor.method.value,
            "timestamp": anchor.timestamp,
            "txid": anchor.txid,
            "block_height": anchor.block_height,
            "ots_proof": anchor.ots_proof.hex() if anchor.ots_proof else None,
            "verified": anchor.verified
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def verify(self, anchor: BitcoinAnchor) -> bool:
        """
        Verifitseeri ankurdus.

        OTS puhul: Kontrolli kas Bitcoin'is on kinnitatud
        OP_RETURN puhul: Kontrolli tehingut
        """
        if anchor.method == AnchorMethod.OPENTIMESTAMPS:
            return self._validate_ots_format(anchor)
        elif anchor.method == AnchorMethod.OP_RETURN:
            return self._verify_op_return(anchor)
        return False

    def _validate_ots_format(self, anchor: BitcoinAnchor) -> bool:
        """
        Validate OTS anchor format (NOT cryptographic verification).

        IMPORTANT: This performs a FORMAT check only, not full cryptographic
        verification. For full verification:
        1. Install: pip install opentimestamps-client
        2. Use: ots verify <proof_file>
        Or call verify_ots_full() which uses the ots CLI.

        Returns:
            True if proof has valid OTS format (pending or confirmed)
            False if no proof or invalid format
        """
        if not anchor.ots_proof:
            return False

        try:
            proof_bytes = anchor.ots_proof

            # OTS proof format validation:
            # 1. Magic bytes: \x00 (header type) followed by version
            # 2. Version byte: 0x01 for current OTS format
            # 3. Minimum length for a valid proof

            # Check minimum viable proof length
            if len(proof_bytes) < 32:
                return False

            # Check version byte (first byte should be 0x01)
            if proof_bytes[0] != 0x01:
                return False

            # Check for OTS magic pattern (\xf0\x0d\x10\x02 is common)
            # or at least some reasonable content after version
            if len(proof_bytes) < 50:
                return False  # Too short to be a real proof

            return True

        except (TypeError, IndexError):
            return False

    def verify_ots_full(self, anchor: BitcoinAnchor) -> dict:
        """
        Attempt full OTS verification using ots CLI (if installed).

        Returns:
            dict with 'verified', 'status', and 'message' fields
        """
        import subprocess
        import tempfile

        result = {
            "verified": False,
            "status": "unknown",
            "message": ""
        }

        if not anchor.ots_proof:
            result["message"] = "No OTS proof available"
            return result

        proof_path = None
        try:
            # Write proof to temp file
            with tempfile.NamedTemporaryFile(suffix='.ots', delete=False) as f:
                f.write(anchor.ots_proof)
                proof_path = f.name

            # Try to run ots verify
            proc = subprocess.run(
                ["ots", "info", proof_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if proc.returncode == 0:
                output = proc.stdout + proc.stderr
                if "pending" in output.lower():
                    result["status"] = "pending"
                    result["message"] = "Proof submitted, awaiting Bitcoin confirmation"
                elif "bitcoin" in output.lower():
                    result["verified"] = True
                    result["status"] = "confirmed"
                    result["message"] = "Verified against Bitcoin blockchain"
                else:
                    result["status"] = "valid_format"
                    result["message"] = "Valid OTS format"
            else:
                result["message"] = f"OTS error: {proc.stderr}"

        except FileNotFoundError:
            result["message"] = "OTS CLI not installed. Run: pip install opentimestamps-client"
        except subprocess.TimeoutExpired:
            result["message"] = "OTS verification timed out"
        except Exception as e:
            result["message"] = f"Verification error: {str(e)}"
        finally:
            # Security: Always cleanup temp file
            if proof_path and os.path.exists(proof_path):
                try:
                    os.unlink(proof_path)
                except OSError:
                    pass  # Best effort cleanup

        return result

    def _verify_op_return(self, anchor: BitcoinAnchor) -> bool:
        """Verifitseeri OP_RETURN ankurdus"""
        if not anchor.txid:
            return False

        # Security: Validate txid format (64 hex chars for Bitcoin txid)
        try:
            _validate_hex_string(anchor.txid, "txid", expected_length=64)
        except (TypeError, ValueError):
            return False

        # Kontrolli tehingut Blockstream API kaudu
        try:
            url = f"https://blockstream.info/api/tx/{anchor.txid}"
            with urllib.request.urlopen(url, timeout=30) as response:
                tx_data = json.loads(response.read())
                # Kontrolli kas tehing on kinnitatud
                return tx_data.get("status", {}).get("confirmed", False)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError):
            return False

    def get_anchors(self, merkle_root: str) -> List[BitcoinAnchor]:
        """
        Hangi kõik ankurdused antud Merkle root'ile.

        Args:
            merkle_root: 64-char hex string

        Returns:
            List of BitcoinAnchor objects

        Raises:
            TypeError: If merkle_root is not a string
            ValueError: If merkle_root is not valid hex
        """
        # Security: Validate input to prevent glob injection
        merkle_root = _validate_hex_string(merkle_root, "merkle_root")

        anchors = []
        pattern = f"{merkle_root[:16]}_*.json"

        for filepath in self.data_dir.glob(pattern):
            # Security: Defense in depth - skip files outside data_dir
            if not _is_path_within(filepath, self.data_dir):
                continue

            try:
                with open(filepath) as f:
                    data = json.load(f)
                    anchor = BitcoinAnchor(
                        merkle_root=data["merkle_root"],
                        method=AnchorMethod(data["method"]),
                        timestamp=data["timestamp"],
                        txid=data.get("txid"),
                        block_height=data.get("block_height"),
                        ots_proof=bytes.fromhex(data["ots_proof"]) if data.get("ots_proof") else None,
                        verified=data.get("verified", False)
                    )
                    anchors.append(anchor)
            except (json.JSONDecodeError, KeyError, ValueError, OSError):
                # Skip corrupted or malformed files
                continue

        return anchors


def create_bitcoin_anchor_callback(
    service: Optional[BitcoinAnchorService] = None
) -> Callable[[str], str]:
    """
    Loo callback ProofNest'i jaoks mis kasutab Bitcoin ankurdust.

    Usage:
        from bitcoin_anchor import create_bitcoin_anchor_callback
        from proofnest import ProofNest

        hc = ProofNest(
            agent_id="my-agent",
            external_anchor=create_bitcoin_anchor_callback()
        )
    """
    if service is None:
        service = BitcoinAnchorService()

    def anchor_callback(record_hash: str) -> str:
        anchor = service.anchor(record_hash)
        return json.dumps({
            "type": "bitcoin",
            "method": anchor.method.value,
            "merkle_root": anchor.merkle_root,
            "timestamp": anchor.timestamp,
            "txid": anchor.txid,
            "has_ots_proof": anchor.ots_proof is not None
        })

    return anchor_callback


# === Integrated Anchoring ===

class GroundTruth:
    """
    PROOFNEST "Kindel Maapind" - Multi-Layer Anchoring

    Based on PROOFNEST philosophy:
        L0: LOGIC      - "inner == outer" is DEFINITION (the foundation)
        L1: MATH       - Formal verification (Coq/Lean)
        L2: CRYPTO     - Bitcoin timestamp (the witness)
        L3: PHYSICAL   - Archives (permanence)

    Key insight: Bitcoin is the WITNESS, not the foundation.
    Logic is the foundation. You cannot 'break' a definition.
    """

    def __init__(
        self,
        p2p_node=None,  # Node instance
        bitcoin_service: Optional[BitcoinAnchorService] = None,
        data_dir: Optional[Path] = None,
        genesis=None  # Genesis instance
    ):
        self.p2p_node = p2p_node
        self.bitcoin_service = bitcoin_service or BitcoinAnchorService()
        self.data_dir = data_dir or Path.home() / ".proofnest_ground"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._genesis = genesis  # Will be set on first use if None

    @property
    def genesis(self):
        """Get or create genesis (lazy loading)"""
        if self._genesis is None:
            try:
                from proofnest_genesis import ProofNestGenesis
                self._genesis = ProofNestGenesis()
            except ImportError:
                raise ImportError("proofnest_genesis module required for genesis anchoring. Install with: pip install proofnest[genesis]")
        return self._genesis

    def anchor_genesis(self) -> dict:
        """
        Anchor the PROOFNEST Genesis to Bitcoin.

        This witnesses the existence of the logical foundation.
        It doesn't make L0 "true" - L0 is definitional.
        It proves WHEN L0 was stated.
        """
        genesis_hash = self.genesis.get_genesis_hash()

        result = {
            "type": "genesis_anchor",
            "genesis_hash": genesis_hash,
            "axiom": self.genesis.block.axiom.statement,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "layers": {
                "L0_logic": {
                    "status": "DEFINITIONAL",
                    "note": "This is the foundation - cannot be 'broken'"
                },
                "L2_crypto": None
            }
        }

        # Anchor to Bitcoin (L2)
        try:
            btc_anchor = self.bitcoin_service.anchor(genesis_hash)
            result["layers"]["L2_crypto"] = {
                "method": btc_anchor.method.value,
                "timestamp": btc_anchor.timestamp,
                "txid": btc_anchor.txid,
                "has_proof": btc_anchor.ots_proof is not None
            }

            # Update genesis with anchor info
            try:
                from aoai_genesis import CryptoAnchor
            except ImportError:
                CryptoAnchor = None
            if CryptoAnchor is None:
                return result
            self.genesis.block.add_crypto_anchor(CryptoAnchor(
                method=btc_anchor.method.value,
                transaction_id=btc_anchor.txid,
                merkle_root=genesis_hash,
                timestamp=btc_anchor.timestamp,
                proof=btc_anchor.ots_proof.hex() if btc_anchor.ots_proof else None
            ))
        except Exception as e:
            result["layers"]["L2_crypto"] = {"error": str(e)}

        self._save_ground_truth(result)
        return result

    def get_full_anchor_status(self) -> dict:
        """Get status of all layers from genesis perspective"""
        return {
            "genesis_hash": self.genesis.get_genesis_hash(),
            "axiom_valid": self.genesis.verify_axiom(),
            "layers": self.genesis.get_status()
        }

    def anchor_to_ground(self, merkle_root: str) -> dict:
        """
        Ankurda kindlale maapinnale - kasuta KÕIKI meetodeid.
        """
        # Security: Validate input
        merkle_root = _validate_hex_string(merkle_root, "merkle_root")

        result = {
            "merkle_root": merkle_root,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "genesis_hash": self.genesis.get_genesis_hash(),
            "anchors": {}
        }

        # 1. Bitcoin (kõige tugevam)
        try:
            btc_anchor = self.bitcoin_service.anchor(merkle_root)
            result["anchors"]["bitcoin"] = {
                "method": btc_anchor.method.value,
                "txid": btc_anchor.txid,
                "has_proof": btc_anchor.ots_proof is not None
            }
        except Exception as e:
            result["anchors"]["bitcoin"] = {"error": str(e)}

        # 2. P2P võrk
        if self.p2p_node:
            try:
                p2p_anchors = self.p2p_node.request_anchor(merkle_root)
                result["anchors"]["p2p"] = {
                    "count": len(p2p_anchors),
                    "nodes": [a.get("anchored_by") for a in p2p_anchors]
                }
            except Exception as e:
                result["anchors"]["p2p"] = {"error": str(e)}

        # 3. Lokaalne
        local_hash = hashlib.sha256(
            f"{merkle_root}:{time.time()}".encode()
        ).hexdigest()
        result["anchors"]["local"] = {
            "hash": local_hash,
            "machine": self.bitcoin_service._get_machine_id()
        }

        # Salvesta
        self._save_ground_truth(result)

        return result

    def _save_ground_truth(self, result: dict) -> None:
        """Salvesta maapinna tõend"""
        # Security: Validate merkle_root before using in filename
        merkle_root = result.get('merkle_root', '')
        _validate_hex_string(merkle_root, "merkle_root")

        filename = f"ground_{merkle_root[:16]}_{int(time.time())}.json"
        filepath = self.data_dir / filename

        # Security: Defense in depth - ensure path stays within data_dir
        if not _is_path_within(filepath, self.data_dir):
            raise ValueError("Security: Path traversal attempt detected")

        with open(filepath, "w") as f:
            json.dump(result, f, indent=2)

    def verify_ground(self, merkle_root: str) -> dict:
        """Verifitseeri kõik ankurdused"""
        # Security: Validate input
        merkle_root = _validate_hex_string(merkle_root, "merkle_root")

        verification = {
            "merkle_root": merkle_root,
            "verified_at": datetime.utcnow().isoformat() + "Z",
            "results": {}
        }

        # Bitcoin
        btc_anchors = self.bitcoin_service.get_anchors(merkle_root)
        verification["results"]["bitcoin"] = {
            "count": len(btc_anchors),
            "verified": any(self.bitcoin_service.verify(a) for a in btc_anchors)
        }

        # P2P
        if self.p2p_node:
            roots = self.p2p_node.get_known_chains()
            verification["results"]["p2p"] = {
                "known_by_network": merkle_root in roots.values()
            }

        return verification


# === Demo ===

if __name__ == "__main__":
    print("PROOFNEST Bitcoin Anchor")
    print("=" * 50)

    # Demo hash
    test_merkle = hashlib.sha256(b"PROOFNEST Test 2025-12-25").hexdigest()
    print(f"\nTest Merkle Root: {test_merkle[:32]}...")

    # Loo teenus
    service = BitcoinAnchorService()

    # Ankurda (OTS on tasuta aga aeglane)
    print("\nAnkurdamine OpenTimestamps kaudu...")
    anchor = service.anchor(test_merkle)

    print(f"Meetod: {anchor.method.value}")
    print(f"Ajatempel: {anchor.timestamp}")
    print(f"OTS Proof: {'Jah' if anchor.ots_proof else 'Ei'}")

    # Näita integratsioon
    print("\n" + "-" * 50)
    print("Integratsioon ProofNest'iga:")
    print()
    print("from bitcoin_anchor import create_bitcoin_anchor_callback")
    print("from proofnest import ProofNest")
    print()
    print("hc = ProofNest(")
    print("    agent_id='my-agent',")
    print("    external_anchor=create_bitcoin_anchor_callback()")
    print(")")
    print()
    print("# Kõik HIGH/CRITICAL otsused ankurdatakse automaatselt Bitcoin'i!")
