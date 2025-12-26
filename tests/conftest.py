"""
ProofNest Test Fixtures
-----------------------
Shared fixtures for all tests.
"""

import pytest
from proofnest import ProofNest, RiskLevel, DecisionRecord, Actor, ActorType


@pytest.fixture
def proofnest_instance():
    """Create a fresh ProofNest instance for testing."""
    return ProofNest(agent_id="test-agent", agent_model="test-model")


@pytest.fixture
def proofnest_with_decisions():
    """Create a ProofNest instance with some decisions already made."""
    pn = ProofNest(agent_id="test-agent")
    pn.decide(
        action="Test action 1",
        reasoning="Test reasoning 1",
        risk_level=RiskLevel.LOW
    )
    pn.decide(
        action="Test action 2",
        reasoning="Test reasoning 2",
        risk_level=RiskLevel.MEDIUM
    )
    return pn


@pytest.fixture
def sample_actor():
    """Create a sample Actor for testing."""
    return Actor(id="test-actor", type=ActorType.AI, model="gpt-4")


@pytest.fixture
def sample_decision_record(sample_actor):
    """Create a sample DecisionRecord for testing."""
    return DecisionRecord(
        decision_id="test-123",
        timestamp="2025-01-01T00:00:00Z",
        actor=sample_actor,
        action="Test action",
        reasoning="Test reasoning",
        alternatives=("option-a", "option-b"),
        confidence=0.95,
        risk_level=RiskLevel.LOW,
        previous_hash=None
    )
