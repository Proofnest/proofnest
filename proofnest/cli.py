"""
PROOFNEST CLI

Command-line interface for ProofNest SDK.
"""

import argparse
import json
import sys
from pathlib import Path


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="proofnest",
        description="PROOFNEST - Proof, not promises. Quantum-ready trust infrastructure.",
    )
    parser.add_argument(
        "--version", "-v",
        action="store_true",
        help="Show version"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a ProofBundle")
    verify_parser.add_argument("file", help="Path to ProofBundle JSON file")
    verify_parser.add_argument("--pubkey", help="Public key (hex) for signature verification")

    # info command
    info_parser = subparsers.add_parser("info", help="Show bundle info")
    info_parser.add_argument("file", help="Path to ProofBundle JSON file")

    args = parser.parse_args()

    if args.version:
        from proofnest import __version__
        print(f"proofnest {__version__}")
        return 0

    if args.command == "verify":
        return cmd_verify(args)
    elif args.command == "info":
        return cmd_info(args)
    else:
        parser.print_help()
        return 0


def cmd_verify(args) -> int:
    """Verify a ProofBundle."""
    from proofnest import Bundle

    path = Path(args.file)

    # Security: check symlink BEFORE resolve
    if path.is_symlink():
        print(f"ERROR: Symlinks not allowed: {args.file}", file=sys.stderr)
        return 1

    if not path.exists():
        print(f"ERROR: File not found: {args.file}", file=sys.stderr)
        return 1

    try:
        bundle = Bundle.from_file(str(path.resolve()))

        if args.pubkey:
            pubkey_bytes = bytes.fromhex(args.pubkey)
            valid = bundle.verify(pubkey_bytes)
            if valid:
                print(f"VALID: Signature verified for {bundle.proof_id}")
                return 0
            else:
                print(f"INVALID: Signature verification failed", file=sys.stderr)
                return 1
        else:
            # Schema-only validation
            print(f"Bundle: {bundle.proof_id}")
            print(f"Type: {bundle.type}")
            print(f"Version: {bundle.proofbundle_version}")
            print("Schema: VALID")
            print("(Use --pubkey for signature verification)")
            return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


def cmd_info(args) -> int:
    """Show bundle info."""
    from proofnest import Bundle

    path = Path(args.file)

    if path.is_symlink():
        print(f"ERROR: Symlinks not allowed: {args.file}", file=sys.stderr)
        return 1

    if not path.exists():
        print(f"ERROR: File not found: {args.file}", file=sys.stderr)
        return 1

    try:
        bundle = Bundle.from_file(str(path.resolve()))

        print(f"Proof ID: {bundle.proof_id}")
        print(f"Type: {bundle.type}")
        print(f"Version: {bundle.proofbundle_version}")
        print(f"Timestamp: {bundle.timestamp}")

        if hasattr(bundle, 'payload') and bundle.payload:
            print(f"Payload Type: {bundle.payload.type if hasattr(bundle.payload, 'type') else 'N/A'}")

        if hasattr(bundle, 'signer') and bundle.signer:
            print(f"Signer DID: {bundle.signer.did if hasattr(bundle.signer, 'did') else 'N/A'}")

        return 0

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
