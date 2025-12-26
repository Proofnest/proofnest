# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email us at:

**security@stellanium.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Scope

The following are in scope:
- proofnest Python package
- Cryptographic implementations
- Chain integrity mechanisms
- Bitcoin anchoring system
- P2P protocol security

### Out of Scope

- Third-party dependencies (report to their maintainers)
- Social engineering attacks
- Physical attacks
- Denial of service attacks

## Security Best Practices

When using ProofNest:

1. **Keep Updated**: Always use the latest version
2. **Protect Keys**: Store private keys securely (0600 permissions)
3. **Verify Chains**: Regularly verify chain integrity
4. **Monitor Anchors**: Track Bitcoin anchor confirmations
5. **Audit Logs**: Review decision logs periodically

## Cryptographic Notice

ProofNest uses:
- **Dilithium3 (ML-DSA-65)**: Post-quantum signatures (NIST Level 3)
- **Ed25519**: Classical signatures (deprecated, use Dilithium)
- **SHA3-256**: Hashing
- **OpenTimestamps**: Bitcoin anchoring

**Note**: This is NOT a FIPS-validated implementation. For FIPS compliance, additional certification is required.

## Acknowledgments

We thank security researchers who help keep ProofNest secure. Contributors will be acknowledged here (with permission).

---

*Last updated: December 2025*
