"""
ProofNest Bitcoin Anchor Tests
------------------------------
Tests for Bitcoin anchoring functionality.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from proofnest.bitcoin import (
    BitcoinAnchorService,
    BitcoinAnchor,
    AnchorMethod,
    GroundTruth,
    create_bitcoin_anchor_callback,
)


class TestBitcoinAnchorService:
    """Tests for BitcoinAnchorService."""

    @pytest.fixture
    def temp_data_dir(self):
        """Create temporary directory for anchor storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def service(self, temp_data_dir):
        """Create service with temp directory."""
        return BitcoinAnchorService(data_dir=temp_data_dir)

    def test_initialization_default(self):
        """Service should initialize with defaults."""
        service = BitcoinAnchorService()
        assert service.preferred_method == AnchorMethod.OPENTIMESTAMPS
        assert service.data_dir.exists()

    def test_initialization_custom_dir(self, temp_data_dir):
        """Service should use custom data directory."""
        service = BitcoinAnchorService(data_dir=temp_data_dir)
        assert service.data_dir == temp_data_dir

    def test_initialization_custom_method(self, temp_data_dir):
        """Service should accept custom preferred method."""
        service = BitcoinAnchorService(
            data_dir=temp_data_dir,
            preferred_method=AnchorMethod.MERKLE_PROOF
        )
        assert service.preferred_method == AnchorMethod.MERKLE_PROOF


class TestOTSAnchoring:
    """Tests for OpenTimestamps anchoring."""

    @pytest.fixture
    def temp_data_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def service(self, temp_data_dir):
        return BitcoinAnchorService(data_dir=temp_data_dir)

    def test_ots_anchor_with_mock_calendar(self, service):
        """OTS anchoring should work with mocked calendar."""
        test_hash = "a" * 64  # Valid 64-char hex

        # Mock successful calendar submission (need 50+ bytes)
        mock_proof = bytes([0x01]) + b"mock_ots_proof_data" * 4
        with patch.object(service, '_submit_to_calendar', return_value=mock_proof):
            anchor = service._anchor_ots(test_hash)

        assert anchor.merkle_root == test_hash
        assert anchor.method == AnchorMethod.OPENTIMESTAMPS
        assert anchor.ots_proof == mock_proof
        assert anchor.timestamp.endswith('Z')

    def test_ots_anchor_saves_to_disk(self, service, temp_data_dir):
        """OTS anchor should be saved to disk."""
        test_hash = "b" * 64

        mock_proof = bytes([0x01]) + b"proof_data" * 10  # Need 50+ bytes
        with patch.object(service, '_submit_to_calendar', return_value=mock_proof):
            anchor = service._anchor_ots(test_hash)

        # Check file was created
        files = list(temp_data_dir.glob(f"{test_hash[:16]}_*.json"))
        assert len(files) == 1

        # Check file content
        with open(files[0]) as f:
            data = json.load(f)
        assert data["merkle_root"] == test_hash
        assert data["method"] == "ots"

    def test_ots_anchor_all_calendars_fail(self, service):
        """OTS anchor should handle all calendar failures gracefully."""
        test_hash = "c" * 64

        with patch.object(service, '_submit_to_calendar', return_value=None):
            anchor = service._anchor_ots(test_hash)

        assert anchor.merkle_root == test_hash
        assert anchor.ots_proof is None  # No proof obtained


class TestOPReturnAnchoring:
    """Tests for OP_RETURN anchoring (not implemented)."""

    @pytest.fixture
    def temp_data_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def service(self, temp_data_dir):
        return BitcoinAnchorService(
            data_dir=temp_data_dir,
            preferred_method=AnchorMethod.OP_RETURN
        )

    def test_op_return_raises_not_implemented(self, service):
        """OP_RETURN should raise NotImplementedError."""
        test_hash = "d" * 64

        with pytest.raises(NotImplementedError) as exc_info:
            service._anchor_op_return(test_hash)

        assert "not implemented" in str(exc_info.value).lower()
        assert "OPENTIMESTAMPS" in str(exc_info.value)

    def test_anchor_with_op_return_method_raises(self, service):
        """anchor() with OP_RETURN method should raise."""
        test_hash = "e" * 64

        with pytest.raises(NotImplementedError):
            service.anchor(test_hash)


class TestVerification:
    """Tests for anchor verification."""

    @pytest.fixture
    def temp_data_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def service(self, temp_data_dir):
        return BitcoinAnchorService(data_dir=temp_data_dir)

    def test_verify_ots_valid_proof(self, service):
        """Valid OTS proof should verify."""
        # Valid proof: version byte 0x01 + at least 50 bytes total
        valid_proof = bytes([0x01]) + b"x" * 60
        anchor = BitcoinAnchor(
            merkle_root="f" * 64,
            method=AnchorMethod.OPENTIMESTAMPS,
            timestamp="2025-01-01T00:00:00Z",
            ots_proof=valid_proof
        )

        assert service._validate_ots_format(anchor) is True

    def test_verify_ots_no_proof(self, service):
        """No OTS proof should not verify."""
        anchor = BitcoinAnchor(
            merkle_root="f" * 64,
            method=AnchorMethod.OPENTIMESTAMPS,
            timestamp="2025-01-01T00:00:00Z",
            ots_proof=None
        )

        assert service._validate_ots_format(anchor) is False

    def test_verify_ots_too_short(self, service):
        """Too short OTS proof should not verify."""
        short_proof = bytes([0x01]) + b"x" * 30  # Only 31 bytes, need 50
        anchor = BitcoinAnchor(
            merkle_root="f" * 64,
            method=AnchorMethod.OPENTIMESTAMPS,
            timestamp="2025-01-01T00:00:00Z",
            ots_proof=short_proof
        )

        assert service._validate_ots_format(anchor) is False

    def test_verify_ots_wrong_version(self, service):
        """Wrong version byte should not verify."""
        wrong_version = bytes([0x02]) + b"x" * 60
        anchor = BitcoinAnchor(
            merkle_root="f" * 64,
            method=AnchorMethod.OPENTIMESTAMPS,
            timestamp="2025-01-01T00:00:00Z",
            ots_proof=wrong_version
        )

        assert service._validate_ots_format(anchor) is False

    def test_verify_op_return_no_txid(self, service):
        """OP_RETURN without txid should not verify."""
        anchor = BitcoinAnchor(
            merkle_root="f" * 64,
            method=AnchorMethod.OP_RETURN,
            timestamp="2025-01-01T00:00:00Z",
            txid=None
        )

        assert service._verify_op_return(anchor) is False


class TestAnchorRetrieval:
    """Tests for retrieving saved anchors."""

    @pytest.fixture
    def temp_data_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def service(self, temp_data_dir):
        return BitcoinAnchorService(data_dir=temp_data_dir)

    def test_get_anchors_empty(self, service):
        """Should return empty list for unknown hash."""
        anchors = service.get_anchors("0" * 64)
        assert anchors == []

    def test_get_anchors_finds_saved(self, service):
        """Should find previously saved anchors."""
        test_hash = "1" * 64

        mock_proof = bytes([0x01]) + b"proof" * 15  # Need 50+ bytes
        with patch.object(service, '_submit_to_calendar', return_value=mock_proof):
            service._anchor_ots(test_hash)

        anchors = service.get_anchors(test_hash)
        assert len(anchors) == 1
        assert anchors[0].merkle_root == test_hash


class TestBitcoinAnchorCallback:
    """Tests for the callback factory."""

    def test_create_callback(self):
        """Should create a callable callback."""
        callback = create_bitcoin_anchor_callback()
        assert callable(callback)

    def test_callback_returns_json(self):
        """Callback should return valid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            service = BitcoinAnchorService(data_dir=Path(tmpdir))
            callback = create_bitcoin_anchor_callback(service)

            mock_proof = bytes([0x01]) + b"proof" * 15  # Need 50+ bytes
            with patch.object(service, '_submit_to_calendar', return_value=mock_proof):
                result = callback("a" * 64)

            data = json.loads(result)
            assert data["type"] == "bitcoin"
            assert data["method"] == "ots"
            assert "merkle_root" in data


class TestBitcoinAnchorDataclass:
    """Tests for BitcoinAnchor dataclass."""

    def test_anchor_creation(self):
        """Should create anchor with required fields."""
        anchor = BitcoinAnchor(
            merkle_root="a" * 64,
            method=AnchorMethod.OPENTIMESTAMPS,
            timestamp="2025-01-01T00:00:00Z"
        )
        assert anchor.merkle_root == "a" * 64
        assert anchor.txid is None
        assert anchor.verified is False

    def test_anchor_with_all_fields(self):
        """Should create anchor with all optional fields."""
        anchor = BitcoinAnchor(
            merkle_root="b" * 64,
            method=AnchorMethod.OP_RETURN,
            timestamp="2025-01-01T00:00:00Z",
            txid="txid123",
            block_height=800000,
            ots_proof=b"proof",
            verified=True
        )
        assert anchor.txid == "txid123"
        assert anchor.block_height == 800000
        assert anchor.verified is True
