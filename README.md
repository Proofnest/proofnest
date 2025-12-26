# PROOFNEST

**Proof, not promises.**

Quantum-ready trust infrastructure for AI agents. Every decision cryptographically signed. High-risk decisions automatically anchored to Bitcoin.

[![PyPI](https://img.shields.io/pypi/v/proofnest)](https://pypi.org/project/proofnest/)
[![Python](https://img.shields.io/pypi/pyversions/proofnest)](https://pypi.org/project/proofnest/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

## Why PROOFNEST?

AI agents make decisions. Those decisions need to be:

- **Verifiable** - Did the agent actually make this decision?
- **Tamper-evident** - Has anyone modified the record?
- **Timestamped** - When was this decision made?
- **Auditable** - Can regulators verify the trail?

PROOFNEST provides all of this with **Bitcoin anchoring enabled by default**.

## Installation

```bash
pip install proofnest
```

## Quick Start

```python
from proofnest import ProofNest, RiskLevel

# Create decision logger (Bitcoin anchoring ON by default!)
pn = ProofNest(agent_id="loan-agent")

# Your agent's DID (Decentralized Identifier)
print(pn.did)  # did:pn:a1b2c3...

# Log decisions (automatically signed with post-quantum crypto)
pn.decide(
    action="Approved loan application",
    reasoning="Credit score 750+, income verified, DTI < 40%",
    risk_level=RiskLevel.LOW
)

# HIGH/CRITICAL decisions are auto-anchored to Bitcoin!
pn.decide(
    action="Approved high-value transaction",
    reasoning="All fraud checks passed, customer verified",
    risk_level=RiskLevel.HIGH  # -> Anchored to Bitcoin via OpenTimestamps
)

# Verify chain integrity + signatures
assert pn.verify()

# Export portable proof bundle
bundle = pn.export()
bundle.to_file("audit_trail.json")
```

## Features

### Bitcoin Anchoring (Default!)

HIGH and CRITICAL risk decisions are automatically anchored to Bitcoin via OpenTimestamps. This provides:

- **Immutable timestamps** - Proven existence at specific time
- **Public verification** - Anyone can verify via Bitcoin blockchain
- **No vendor lock-in** - OpenTimestamps is free and open

```python
# Bitcoin anchoring is ON by default
pn = ProofNest(agent_id="my-agent")

# To disable (not recommended):
pn = ProofNest(agent_id="my-agent", enable_bitcoin=False)
```

### Post-Quantum Signatures

All decisions are signed with **Dilithium3** (NIST ML-DSA-65), providing quantum-proof security:

- NIST Level 3 security (equivalent to AES-192)
- Survives future quantum computer attacks
- Third-party verifiable

### Decentralized Identifiers (DIDs)

Each agent gets a unique DID:

```python
pn = ProofNest(agent_id="my-agent")
print(pn.did)  # did:pn:a1b2c3d4e5f6...
```

### Tamper Detection

Any modification to the decision chain is detected:

```python
pn.decide(action="Original", reasoning="...", risk_level=RiskLevel.LOW)

# If someone tampers with the record...
pn.chain[0].action = "TAMPERED"

# Verification fails!
assert pn.verify() == False
```

### Thread-Safe

Safe for concurrent use in multi-threaded applications.

### ProofBundle - Portable Proofs

Export decisions as self-contained, verifiable bundles:

```python
bundle = pn.export()
bundle.to_file("audit.json")

# Save public key for third-party verification
public_key = pn.identity.keys.public_key
with open("public_key.bin", "wb") as f:
    f.write(public_key)

# Third parties can verify later
from proofnest import ProofBundle
loaded = ProofBundle.from_file("audit.json")
with open("public_key.bin", "rb") as f:
    public_key = f.read()
assert loaded.verify(public_key)
```

## CLI

```bash
# Check version
proofnest --version

# Verify a proof bundle
proofnest verify audit.json

# Verbose output
proofnest verify audit.json --verbose
```

## Third-Party Verification

Auditors can verify proofs with the agent's public key:

```python
from proofnest import ProofBundle, verify_proofbundle_standalone

# Load the proof bundle and public key
bundle = ProofBundle.from_file("audit_trail.json")
with open("public_key.bin", "rb") as f:
    public_key = f.read()

# Verify signature (post-quantum Dilithium)
assert bundle.verify(public_key)

# Or verify with raw JSON
json_str = open("audit_trail.json").read()
is_valid = verify_proofbundle_standalone(json_str, public_key)
```

## Risk Levels

```python
from proofnest import RiskLevel

RiskLevel.LOW       # Routine decisions
RiskLevel.MEDIUM    # Notable decisions
RiskLevel.HIGH      # Auto-anchored to Bitcoin
RiskLevel.CRITICAL  # Auto-anchored to Bitcoin
```

## Integration Examples

### LangChain

```python
from langchain.agents import AgentExecutor
from proofnest import ProofNest, RiskLevel

pn = ProofNest(agent_id="langchain-agent")

def log_decision(action: str, reasoning: str):
    pn.decide(action=action, reasoning=reasoning, risk_level=RiskLevel.MEDIUM)

# Use in your agent callbacks
```

### FastAPI

```python
from fastapi import FastAPI
from proofnest import ProofNest, RiskLevel

app = FastAPI()
pn = ProofNest(agent_id="api-agent")

@app.post("/decide")
def make_decision(action: str, reasoning: str):
    record = pn.decide(action=action, reasoning=reasoning, risk_level=RiskLevel.LOW)
    return {"decision_id": record.decision_id, "hash": record.record_hash}

@app.get("/audit")
def get_audit():
    bundle = pn.export()
    return bundle.to_dict()
```

## Security

- **Path traversal protection** - Agent IDs validated
- **Symlink rejection** - File operations are symlink-safe
- **Atomic writes** - No corrupted files on crash
- **Restrictive permissions** - Keys stored with 0600 mode

## EU AI Act Compliance

PROOFNEST helps meet EU AI Act Article 12 (Record-keeping) requirements:

- Automatic logging of AI decisions
- Tamper-evident records
- Timestamped audit trails
- Exportable for regulators

## API Reference

### ProofNest

```python
pn = ProofNest(
    agent_id: str,              # Unique agent identifier (alphanumeric, -, _)
    agent_model: str = "unknown",  # Model name (e.g., "gpt-4", "claude-3")
    storage_path: Path = None,  # Custom storage location
    enable_bitcoin: bool = True,  # Bitcoin anchoring (default: ON)
    enable_signatures: bool = True  # Quantum-safe signatures
)

pn.decide(
    action: str,                # What was decided
    reasoning: str,             # Why (THE KEY for transparency)
    alternatives: List[str] = None,  # Other options considered
    confidence: float = 0.8,    # 0.0 to 1.0
    risk_level: RiskLevel = RiskLevel.LOW
) -> DecisionRecord

pn.verify() -> bool             # Verify chain + signatures
pn.export() -> ProofBundle      # Export portable bundle
pn.get_merkle_root() -> str     # Single hash of entire chain
```

### ProofBundle

```python
ProofBundle.decision(content, private_key, public_key) -> ProofBundle
ProofBundle.from_file(path) -> ProofBundle
bundle.to_file(path)
bundle.verify(public_key: bytes) -> bool
bundle.to_json() -> str
```

## Documentation

- [GitHub Repository](https://github.com/proofnest/proofnest)
- [ProofBundle Specification](https://github.com/proofnest/proofnest/blob/main/docs/PROOFBUNDLE.md)

## License

Apache-2.0. Copyright (c) 2025 Stellanium Ltd.

PROOFNEST is a trademark of Stellanium Ltd.
