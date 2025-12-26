"""
ProofNest Timestamp Monotonicity Tests
--------------------------------------
Tests for timestamp ordering enforcement (anti-backdating).
Security: Prevents inserting historical records to falsify history.
"""

import pytest
import time
from datetime import datetime, timedelta
from proofnest import ProofNest, RiskLevel, TimestampViolationError


class TestTimestampMonotonicity:
    """Tests for timestamp monotonicity enforcement."""

    def test_sequential_decisions_have_increasing_timestamps(self):
        """Sequential decisions should have monotonically increasing timestamps."""
        pn = ProofNest(agent_id="test")

        r1 = pn.decide("Action 1", "Reason 1", risk_level=RiskLevel.LOW)
        time.sleep(0.01)  # Small delay to ensure different timestamps
        r2 = pn.decide("Action 2", "Reason 2", risk_level=RiskLevel.LOW)

        assert r2.timestamp > r1.timestamp

    def test_rapid_decisions_still_ordered(self):
        """Even rapid decisions should maintain order."""
        pn = ProofNest(agent_id="test")

        records = []
        for i in range(10):
            r = pn.decide(f"Action {i}", f"Reason {i}", risk_level=RiskLevel.LOW)
            records.append(r)

        for i in range(1, len(records)):
            assert records[i].timestamp >= records[i-1].timestamp

    def test_chain_preserves_temporal_order(self):
        """Chain should preserve temporal ordering."""
        pn = ProofNest(agent_id="test")

        for i in range(5):
            pn.decide(f"Action {i}", f"Reason {i}", risk_level=RiskLevel.LOW)
            time.sleep(0.001)

        timestamps = [r.timestamp for r in pn.chain]
        assert timestamps == sorted(timestamps)


class TestTimestampFormat:
    """Tests for timestamp format compliance."""

    def test_timestamp_is_iso_format(self):
        """Timestamp should be in ISO 8601 format."""
        pn = ProofNest(agent_id="test")
        r = pn.decide("Test", "Test", risk_level=RiskLevel.LOW)

        # Should be parseable as ISO format
        try:
            # Format: 2025-01-01T00:00:00.123456Z
            datetime.fromisoformat(r.timestamp.replace('Z', '+00:00'))
        except ValueError:
            pytest.fail(f"Timestamp {r.timestamp} is not valid ISO format")

    def test_timestamp_ends_with_z(self):
        """Timestamp should end with Z (UTC indicator)."""
        pn = ProofNest(agent_id="test")
        r = pn.decide("Test", "Test", risk_level=RiskLevel.LOW)

        assert r.timestamp.endswith('Z')

    def test_timestamp_contains_date_and_time(self):
        """Timestamp should contain both date and time components."""
        pn = ProofNest(agent_id="test")
        r = pn.decide("Test", "Test", risk_level=RiskLevel.LOW)

        assert 'T' in r.timestamp  # ISO separator
        assert '-' in r.timestamp.split('T')[0]  # Date dashes
        assert ':' in r.timestamp.split('T')[1]  # Time colons


class TestTimestampIntegrity:
    """Tests for timestamp integrity in chain verification."""

    def test_chain_with_valid_timestamps_verifies(self):
        """Chain with valid monotonic timestamps should verify."""
        pn = ProofNest(agent_id="test")

        for i in range(3):
            pn.decide(f"Action {i}", f"Reason {i}", risk_level=RiskLevel.LOW)
            time.sleep(0.001)

        assert pn.verify()

    def test_timestamp_is_recent(self):
        """Timestamp should be recent (within last minute)."""
        pn = ProofNest(agent_id="test")
        r = pn.decide("Test", "Test", risk_level=RiskLevel.LOW)

        # Parse timestamp
        ts = datetime.fromisoformat(r.timestamp.replace('Z', '+00:00'))
        now = datetime.now(ts.tzinfo)

        # Should be within last minute
        assert (now - ts).total_seconds() < 60


class TestTimestampViolationError:
    """Tests for TimestampViolationError exception."""

    def test_exception_exists(self):
        """TimestampViolationError should be importable."""
        from proofnest import TimestampViolationError
        assert issubclass(TimestampViolationError, Exception)

    def test_exception_is_proofnest_error(self):
        """TimestampViolationError should inherit from ProofNestError."""
        from proofnest import TimestampViolationError, ProofNestError
        assert issubclass(TimestampViolationError, ProofNestError)

    def test_exception_message(self):
        """Exception should have informative message."""
        exc = TimestampViolationError("Backdating attempt detected")
        assert "Backdating" in str(exc)
