"""
ProofNest Core Tests
--------------------
Tests for core functionality: ProofNest, DecisionRecord, Actor.
"""

import pytest
from proofnest import (
    ProofNest,
    DecisionRecord,
    Actor,
    ActorType,
    RiskLevel,
    ProofNestError,
)


class TestProofNestInitialization:
    """Tests for ProofNest initialization."""

    def test_basic_initialization(self):
        """ProofNest should initialize with agent_id."""
        import uuid
        unique_id = f"test-{uuid.uuid4().hex[:8]}"
        pn = ProofNest(agent_id=unique_id)
        assert pn.actor.id == unique_id
        assert len(pn.chain) == 0

    def test_initialization_with_model(self):
        """ProofNest should accept agent_model parameter."""
        pn = ProofNest(agent_id="test", agent_model="gpt-4")
        assert pn.actor.model == "gpt-4"

    def test_did_format(self):
        """DID should follow did:pn:... format."""
        pn = ProofNest(agent_id="test")
        assert pn.did.startswith("did:pn:")

    def test_invalid_agent_id_special_chars(self):
        """Agent ID with special chars should be rejected."""
        with pytest.raises((ValueError, ProofNestError)):
            ProofNest(agent_id="test/../../../etc/passwd")

    def test_invalid_agent_id_too_long(self):
        """Agent ID over 64 chars should be rejected."""
        with pytest.raises((ValueError, ProofNestError)):
            ProofNest(agent_id="a" * 100)


class TestDecisions:
    """Tests for decision making."""

    def test_make_decision(self, proofnest_instance):
        """Should successfully make a decision."""
        record = proofnest_instance.decide(
            action="Approve request",
            reasoning="All criteria met",
            risk_level=RiskLevel.LOW
        )
        assert record.action == "Approve request"
        assert record.reasoning == "All criteria met"
        assert record.risk_level == RiskLevel.LOW

    def test_decision_adds_to_chain(self):
        """Decision should be added to chain."""
        import uuid
        pn = ProofNest(agent_id=f"add-chain-{uuid.uuid4().hex[:8]}")
        initial_len = len(pn.chain)
        pn.decide(
            action="Test",
            reasoning="Test",
            risk_level=RiskLevel.LOW
        )
        assert len(pn.chain) == initial_len + 1

    def test_decision_has_hash(self, proofnest_instance):
        """Decision record should have computed hash."""
        record = proofnest_instance.decide(
            action="Test",
            reasoning="Test",
            risk_level=RiskLevel.LOW
        )
        assert record.record_hash
        assert len(record.record_hash) == 64  # SHA3-256 hex

    def test_chain_links_correctly(self):
        """Each decision should link to previous hash."""
        import uuid
        pn = ProofNest(agent_id=f"link-test-{uuid.uuid4().hex[:8]}")
        r1 = pn.decide("Action 1", "Reason 1", risk_level=RiskLevel.LOW)
        r2 = pn.decide("Action 2", "Reason 2", risk_level=RiskLevel.LOW)

        # First record may have previous_hash if chain was loaded from disk
        # But r2 must link to r1
        assert r2.previous_hash == r1.record_hash

    def test_decision_with_alternatives(self, proofnest_instance):
        """Should accept alternatives as tuple."""
        record = proofnest_instance.decide(
            action="Option A",
            reasoning="Best option",
            alternatives=["Option B", "Option C"],
            risk_level=RiskLevel.LOW
        )
        assert record.alternatives == ("Option B", "Option C")

    def test_decision_with_confidence(self, proofnest_instance):
        """Should accept confidence level."""
        record = proofnest_instance.decide(
            action="Test",
            reasoning="Test",
            confidence=0.85,
            risk_level=RiskLevel.LOW
        )
        assert record.confidence == 0.85


class TestVerification:
    """Tests for chain verification."""

    def test_empty_chain_verifies(self, proofnest_instance):
        """Empty chain should verify successfully."""
        assert proofnest_instance.verify()

    def test_chain_with_decisions_verifies(self, proofnest_with_decisions):
        """Chain with valid decisions should verify."""
        assert proofnest_with_decisions.verify()

    def test_hash_determinism(self, sample_decision_record):
        """Same data should produce same hash."""
        actor = Actor(id="test", type=ActorType.AI, model="model")
        r1 = DecisionRecord(
            decision_id="id1",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="action",
            reasoning="reason",
            alternatives=("a", "b"),
            confidence=0.5,
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )
        r2 = DecisionRecord(
            decision_id="id1",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="action",
            reasoning="reason",
            alternatives=("a", "b"),
            confidence=0.5,
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )
        assert r1.record_hash == r2.record_hash


class TestActor:
    """Tests for Actor class."""

    def test_actor_creation(self):
        """Actor should be created with id and type."""
        actor = Actor(id="agent-1", type=ActorType.AI)
        assert actor.id == "agent-1"
        assert actor.type == ActorType.AI

    def test_actor_to_dict(self, sample_actor):
        """Actor should serialize to dict."""
        d = sample_actor.to_dict()
        assert d["id"] == "test-actor"
        assert d["type"] == "ai"
        assert d["model"] == "gpt-4"

    def test_actor_from_dict(self):
        """Actor should deserialize from dict."""
        data = {"id": "test", "type": "human", "model": "N/A"}
        actor = Actor.from_dict(data)
        assert actor.id == "test"
        assert actor.type == ActorType.HUMAN


class TestDecisionRecordSerialization:
    """Tests for DecisionRecord serialization."""

    def test_to_dict(self, sample_decision_record):
        """DecisionRecord should serialize to HCP-compliant dict."""
        d = sample_decision_record.to_dict()
        assert d["decision_id"] == "test-123"
        assert d["decision"]["action"] == "Test action"
        assert d["chain"]["record_hash"] == sample_decision_record.record_hash
        assert d["quantum_safe"] is True

    def test_alternatives_as_list_in_dict(self, sample_decision_record):
        """Alternatives tuple should become list in dict."""
        d = sample_decision_record.to_dict()
        assert isinstance(d["decision"]["alternatives_considered"], list)
        assert d["decision"]["alternatives_considered"] == ["option-a", "option-b"]
