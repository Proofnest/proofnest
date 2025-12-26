"""
ProofNest Immutability Tests
-----------------------------
Tests for DecisionRecord immutability (frozen dataclass).
Security: Prevents tampering after record creation.
"""

import pytest
from dataclasses import FrozenInstanceError
from proofnest import DecisionRecord, Actor, ActorType, RiskLevel


class TestDecisionRecordImmutability:
    """Tests that DecisionRecord is truly immutable."""

    @pytest.fixture
    def immutable_record(self):
        """Create a record for immutability testing."""
        actor = Actor(id="test", type=ActorType.AI, model="test")
        return DecisionRecord(
            decision_id="imm-test",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="Original action",
            reasoning="Original reasoning",
            alternatives=("a", "b"),
            confidence=0.9,
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )

    def test_cannot_modify_action(self, immutable_record):
        """Attempting to modify action should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.action = "Modified action"

    def test_cannot_modify_reasoning(self, immutable_record):
        """Attempting to modify reasoning should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.reasoning = "Modified reasoning"

    def test_cannot_modify_confidence(self, immutable_record):
        """Attempting to modify confidence should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.confidence = 0.1

    def test_cannot_modify_risk_level(self, immutable_record):
        """Attempting to modify risk_level should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.risk_level = RiskLevel.CRITICAL

    def test_cannot_modify_decision_id(self, immutable_record):
        """Attempting to modify decision_id should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.decision_id = "hacked-id"

    def test_cannot_modify_timestamp(self, immutable_record):
        """Attempting to modify timestamp should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.timestamp = "1970-01-01T00:00:00Z"

    def test_cannot_modify_record_hash(self, immutable_record):
        """Attempting to modify record_hash should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.record_hash = "0" * 64

    def test_cannot_modify_previous_hash(self, immutable_record):
        """Attempting to modify previous_hash should raise FrozenInstanceError."""
        with pytest.raises(FrozenInstanceError):
            immutable_record.previous_hash = "fake_hash"

    def test_cannot_add_new_attribute(self, immutable_record):
        """Attempting to add new attribute should raise an error (slots)."""
        # slots=True combined with frozen=True can raise TypeError or AttributeError
        with pytest.raises((AttributeError, TypeError)):
            immutable_record.malicious_field = "hacked"

    def test_alternatives_is_tuple(self, immutable_record):
        """Alternatives should be a tuple (immutable sequence)."""
        assert isinstance(immutable_record.alternatives, tuple)

    def test_alternatives_tuple_immutable(self, immutable_record):
        """Tuple alternatives cannot be modified."""
        # Tuples don't have append
        with pytest.raises(AttributeError):
            immutable_record.alternatives.append("c")

    def test_record_hash_computed_at_creation(self, immutable_record):
        """Hash should be computed and set during __post_init__."""
        assert immutable_record.record_hash
        assert len(immutable_record.record_hash) == 64


class TestHashIntegrity:
    """Tests for hash integrity - changing data changes hash."""

    def test_different_action_different_hash(self):
        """Different actions should produce different hashes."""
        actor = Actor(id="test", type=ActorType.AI, model="test")
        r1 = DecisionRecord(
            decision_id="id",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="Action A",
            reasoning="reason",
            alternatives=(),
            confidence=0.5,
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )
        r2 = DecisionRecord(
            decision_id="id",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="Action B",  # Different action
            reasoning="reason",
            alternatives=(),
            confidence=0.5,
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )
        assert r1.record_hash != r2.record_hash

    def test_different_confidence_different_hash(self):
        """Different confidence levels should produce different hashes."""
        actor = Actor(id="test", type=ActorType.AI, model="test")
        r1 = DecisionRecord(
            decision_id="id",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="action",
            reasoning="reason",
            alternatives=(),
            confidence=0.9,
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )
        r2 = DecisionRecord(
            decision_id="id",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="action",
            reasoning="reason",
            alternatives=(),
            confidence=0.1,  # Different confidence
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )
        assert r1.record_hash != r2.record_hash

    def test_different_risk_level_different_hash(self):
        """Different risk levels should produce different hashes."""
        actor = Actor(id="test", type=ActorType.AI, model="test")
        r1 = DecisionRecord(
            decision_id="id",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="action",
            reasoning="reason",
            alternatives=(),
            confidence=0.5,
            risk_level=RiskLevel.LOW,
            previous_hash=None
        )
        r2 = DecisionRecord(
            decision_id="id",
            timestamp="2025-01-01T00:00:00Z",
            actor=actor,
            action="action",
            reasoning="reason",
            alternatives=(),
            confidence=0.5,
            risk_level=RiskLevel.CRITICAL,  # Different risk
            previous_hash=None
        )
        assert r1.record_hash != r2.record_hash
