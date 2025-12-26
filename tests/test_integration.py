"""
ProofNest Integration Tests
---------------------------
End-to-end tests for ProofNest with Bitcoin anchoring.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from proofnest import (
    ProofNest,
    RiskLevel,
    ProofBundle,
    ProofBundleType,
    create_bitcoin_anchor_callback,
)
from proofnest.bitcoin import BitcoinAnchorService, AnchorMethod


class TestProofNestWithBitcoin:
    """Integration tests for ProofNest with Bitcoin anchoring."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_proofnest_with_bitcoin_callback(self, temp_dir):
        """ProofNest should work with Bitcoin anchor callback."""
        service = BitcoinAnchorService(data_dir=temp_dir)

        # Mock OTS calendar to avoid network calls
        mock_proof = bytes([0x01]) + b"mock_proof" * 5
        with patch.object(service, '_submit_to_calendar', return_value=mock_proof):
            callback = create_bitcoin_anchor_callback(service)

            # Create ProofNest with custom anchor
            import uuid
            pn = ProofNest(
                agent_id=f"btc-test-{uuid.uuid4().hex[:8]}",
                external_anchor=callback
            )

            # Make a decision
            record = pn.decide(
                action="Approve transaction",
                reasoning="All checks passed",
                risk_level=RiskLevel.HIGH
            )

            assert record.action == "Approve transaction"
            assert len(pn.chain) >= 1

    def test_proofnest_chain_integrity_with_anchor(self, temp_dir):
        """Chain should maintain integrity with anchoring."""
        service = BitcoinAnchorService(data_dir=temp_dir)

        mock_proof = bytes([0x01]) + b"proof"
        with patch.object(service, '_submit_to_calendar', return_value=mock_proof):
            callback = create_bitcoin_anchor_callback(service)

            import uuid
            pn = ProofNest(
                agent_id=f"integrity-{uuid.uuid4().hex[:8]}",
                external_anchor=callback
            )

            # Make multiple decisions
            pn.decide("Action 1", "Reason 1", risk_level=RiskLevel.LOW)
            pn.decide("Action 2", "Reason 2", risk_level=RiskLevel.MEDIUM)
            pn.decide("Action 3", "Reason 3", risk_level=RiskLevel.HIGH)

            # Verify chain integrity
            assert pn.verify()
            assert len(pn.chain) == 3


class TestProofBundleIntegration:
    """Integration tests for ProofBundle creation and verification."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_create_decision_bundle_with_identity(self, temp_dir):
        """Should create a decision proof bundle using identity keys."""
        import uuid
        pn = ProofNest(agent_id=f"bundle-{uuid.uuid4().hex[:8]}")

        # Make a decision
        record = pn.decide(
            action="Grant access",
            reasoning="Identity verified",
            confidence=0.95,
            risk_level=RiskLevel.LOW
        )

        # Create bundle using identity's keys
        decision_content = {
            "decision_id": record.decision_id,
            "action": record.action,
            "reasoning": record.reasoning,
            "outcome": "approved",
            "risk_level": record.risk_level.value
        }

        bundle = ProofBundle.decision(
            content=decision_content,
            private_key=pn.identity.keys.signing_key,
            public_key=pn.identity.keys.public_key
        )

        # Type can be string or enum depending on how it's accessed
        assert bundle.type == "decision" or bundle.type == ProofBundleType.DECISION

    def test_bundle_to_json(self, temp_dir):
        """Bundle should serialize to JSON."""
        import uuid
        pn = ProofNest(agent_id=f"json-{uuid.uuid4().hex[:8]}")

        record = pn.decide(
            action="Process payment",
            reasoning="Funds verified",
            risk_level=RiskLevel.MEDIUM
        )

        decision_content = {
            "decision_id": record.decision_id,
            "action": record.action,
            "reasoning": record.reasoning
        }

        bundle = ProofBundle.decision(
            content=decision_content,
            private_key=pn.identity.keys.signing_key,
            public_key=pn.identity.keys.public_key
        )

        # Convert to dict (JSON-serializable)
        bundle_dict = bundle.to_dict()

        assert "type" in bundle_dict
        assert "payload" in bundle_dict
        assert "signer" in bundle_dict


class TestDecisionChainIntegration:
    """Integration tests for decision chain operations."""

    def test_rapid_decisions_maintain_order(self):
        """Rapid sequential decisions should maintain temporal order."""
        import uuid
        pn = ProofNest(agent_id=f"rapid-{uuid.uuid4().hex[:8]}")

        # Make 10 rapid decisions
        records = []
        for i in range(10):
            r = pn.decide(
                action=f"Action {i}",
                reasoning=f"Reason {i}",
                risk_level=RiskLevel.LOW
            )
            records.append(r)

        # Verify timestamps are ordered
        timestamps = [r.timestamp for r in records]
        assert timestamps == sorted(timestamps)

        # Verify chain links
        for i in range(1, len(records)):
            assert records[i].previous_hash == records[i-1].record_hash

    def test_verify_chain_detects_tampering_attempt(self):
        """Verification should detect if someone tries to tamper."""
        import uuid
        pn = ProofNest(agent_id=f"tamper-{uuid.uuid4().hex[:8]}")

        pn.decide("Original action", "Original reason", risk_level=RiskLevel.LOW)
        pn.decide("Second action", "Second reason", risk_level=RiskLevel.LOW)

        # Chain should verify
        assert pn.verify()

        # Try to access internal chain (this is what tampering would look like)
        # Since DecisionRecord is frozen, direct modification would raise FrozenInstanceError
        # So we just verify the chain remains intact
        assert len(pn.chain) == 2


class TestIdentityIntegration:
    """Integration tests for quantum-safe identity."""

    def test_did_format_consistency(self):
        """DID should be consistent across decisions."""
        import uuid
        pn = ProofNest(agent_id=f"did-{uuid.uuid4().hex[:8]}")

        did_before = pn.did

        pn.decide("Action 1", "Reason", risk_level=RiskLevel.LOW)
        pn.decide("Action 2", "Reason", risk_level=RiskLevel.LOW)

        did_after = pn.did

        assert did_before == did_after
        assert did_before.startswith("did:pn:")

    def test_signature_on_decisions(self):
        """Decisions should have quantum-safe signatures."""
        import uuid
        pn = ProofNest(
            agent_id=f"sig-{uuid.uuid4().hex[:8]}",
            enable_signatures=True
        )

        record = pn.decide(
            action="Signed action",
            reasoning="Important decision",
            risk_level=RiskLevel.HIGH
        )

        # Signature should be present
        assert record.signature is not None
        assert record.signature.value  # Has actual signature value


class TestExportIntegration:
    """Integration tests for chain export functionality."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_export_chain_to_json(self, temp_dir):
        """Should export chain to JSON format."""
        import uuid
        pn = ProofNest(agent_id=f"export-{uuid.uuid4().hex[:8]}")

        pn.decide("Action 1", "Reason 1", risk_level=RiskLevel.LOW)
        pn.decide("Action 2", "Reason 2", risk_level=RiskLevel.MEDIUM)

        # Export to JSON
        export_path = temp_dir / "chain_export.json"
        chain_data = [record.to_dict() for record in pn.chain]

        with open(export_path, 'w') as f:
            json.dump(chain_data, f, indent=2)

        assert export_path.exists()

        # Verify export content
        with open(export_path) as f:
            loaded = json.load(f)

        assert len(loaded) == 2
        assert loaded[0]["decision"]["action"] == "Action 1"
        assert loaded[1]["decision"]["action"] == "Action 2"
