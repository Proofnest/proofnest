# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.2] - 2025-12-26

### Changed
- Renamed `_verify_ots()` to `_validate_ots_format()` for clarity (it validates format, not cryptographic proof)
- Replaced `print()` with proper `logging.warning()` for anchor failures
- Improved documentation for `merkle_root` parameter (clarifies it accepts any SHA-256 digest)

### Security
- Production hardening based on GPT-5.2 code audit
- Proper logging instead of silent print statements

## [1.2.1] - 2025-12-26

### Changed
- `OP_RETURN` anchoring now raises `NotImplementedError` (was placeholder)
- Improved OTS verification with better format checking
- Replaced bare `except` clauses with specific exception types

### Fixed
- Honest disclosure: OP_RETURN was pretending to work but returning `txid=None`

## [1.2.0] - 2025-12-26

### Added
- Exception hierarchy: `ProofNestError`, `TimestampViolationError`, `ChainIntegrityError`, `SignatureError`
- Timestamp monotonicity enforcement in `decide()` method (prevents backdating attacks)
- `.gitignore` for Python projects

### Changed
- `DecisionRecord` is now immutable (`frozen=True`, `slots=True`)
- `alternatives` field changed from `List[str]` to `tuple` for immutability
- Version bump from 1.1.2 to 1.2.0

### Security
- **Immutability**: Decision records cannot be modified after creation
- **Backdating prevention**: Timestamps must be monotonically increasing

## [1.1.2] - 2025-12-24

### Added
- Initial public release
- `ProofNest` core class for decision logging
- `DecisionRecord` dataclass with hash chain
- `AgentIdentity` with SHA3-256 + Dilithium3 (quantum-proof)
- DID-style agent identifiers (`did:pn:...`)
- `ProofBundle` format for portable verification
- Bitcoin anchoring support (`BitcoinAnchorService`)
- P2P network primitives (`Node`, `Peer`, `Message`)
- GitHub Actions CI/CD pipeline
- SECURITY.md and CONTRIBUTING.md

### Security
- Quantum-safe cryptographic signatures (Dilithium3)
- SHA3-256 hashing for all decision records
- Hash chain integrity verification

[Unreleased]: https://github.com/Proofnest/proofnest/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Proofnest/proofnest/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/Proofnest/proofnest/releases/tag/v1.1.2
