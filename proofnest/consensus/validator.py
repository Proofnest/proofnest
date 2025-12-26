"""
HONEST Chain - Validator Management

Implements PoS validator lifecycle:
- Registration with stake deposit
- Delegation from other accounts
- Jailing for misbehavior
- Unbonding with lockup period
- Commission rates

Per GPT-5.2:
    "Use a conservative base: PoS with BFT finality."

GPT-5.2 REVIEWED: 2025-12-23
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum, auto
import hashlib
import time
import json


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Minimum stake to become validator (in base units)
MIN_VALIDATOR_STAKE = 100_000_000_000  # 100,000 HONEST (assuming 6 decimals)

# Minimum delegation amount
MIN_DELEGATION = 1_000_000  # 1 HONEST

# Maximum validators in active set
MAX_ACTIVE_VALIDATORS = 100

# Unbonding period in blocks (~21 days at 6s blocks)
UNBONDING_PERIOD = 302_400

# Maximum commission rate (basis points, 10000 = 100%)
MAX_COMMISSION_RATE = 5000  # 50%

# Commission rate change cooldown (blocks)
COMMISSION_CHANGE_COOLDOWN = 14_400  # ~1 day

# Jail duration for minor offenses (blocks)
JAIL_DURATION_MINOR = 28_800  # ~2 days

# Jail duration for major offenses (blocks)
JAIL_DURATION_MAJOR = 302_400  # ~21 days


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

class ValidatorStatus(Enum):
    """Validator lifecycle status."""
    UNBONDED = 0        # Not active, no stake locked
    UNBONDING = 1       # Exiting, stake locked for unbonding period
    BONDED = 2          # Active validator
    JAILED = 3          # Jailed for misbehavior


class JailReason(Enum):
    """Reasons for jailing a validator."""
    DOWNTIME = 1                # Missed too many blocks
    DOUBLE_SIGN = 2             # Signed conflicting blocks
    INVALID_PROPOSAL = 3        # Proposed invalid block
    GOVERNANCE_VIOLATION = 4    # Violated governance rules


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ValidatorDescription:
    """
    Human-readable validator description.
    """
    moniker: str                  # Validator name
    identity: str = ""            # Keybase/other identity
    website: str = ""             # Website URL
    security_contact: str = ""    # Security email
    details: str = ""             # Description

    def to_dict(self) -> dict:
        return {
            'moniker': self.moniker,
            'identity': self.identity,
            'website': self.website,
            'security_contact': self.security_contact,
            'details': self.details,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'ValidatorDescription':
        return cls(
            moniker=data.get('moniker', ''),
            identity=data.get('identity', ''),
            website=data.get('website', ''),
            security_contact=data.get('security_contact', ''),
            details=data.get('details', ''),
        )


@dataclass
class Commission:
    """
    Validator commission configuration.
    """
    rate: int                     # Current rate (basis points)
    max_rate: int                 # Maximum rate (cannot increase above)
    max_change_rate: int          # Max rate change per period
    last_change_height: int = 0   # Block height of last change

    def can_change(self, new_rate: int, current_height: int) -> Tuple[bool, str]:
        """Check if commission rate change is allowed."""
        # Check cooldown
        if current_height - self.last_change_height < COMMISSION_CHANGE_COOLDOWN:
            return False, "Commission change cooldown not elapsed"

        # Check max rate
        if new_rate > self.max_rate:
            return False, f"New rate {new_rate} exceeds max rate {self.max_rate}"

        # Check max change
        change = abs(new_rate - self.rate)
        if change > self.max_change_rate:
            return False, f"Rate change {change} exceeds max change {self.max_change_rate}"

        # Check bounds
        if new_rate < 0 or new_rate > MAX_COMMISSION_RATE:
            return False, f"Rate must be 0-{MAX_COMMISSION_RATE}"

        return True, ""

    def to_dict(self) -> dict:
        return {
            'rate': self.rate,
            'max_rate': self.max_rate,
            'max_change_rate': self.max_change_rate,
            'last_change_height': self.last_change_height,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Commission':
        return cls(
            rate=data['rate'],
            max_rate=data['max_rate'],
            max_change_rate=data['max_change_rate'],
            last_change_height=data.get('last_change_height', 0),
        )


@dataclass
class Delegation:
    """
    Delegation from an account to a validator.
    """
    delegator: bytes              # Delegator address
    validator: bytes              # Validator pubkey
    shares: int                   # Delegation shares (not tokens)
    created_height: int           # When delegation was created

    def to_dict(self) -> dict:
        return {
            'delegator': self.delegator.hex(),
            'validator': self.validator.hex(),
            'shares': self.shares,
            'created_height': self.created_height,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Delegation':
        return cls(
            delegator=bytes.fromhex(data['delegator']),
            validator=bytes.fromhex(data['validator']),
            shares=data['shares'],
            created_height=data['created_height'],
        )


@dataclass
class UnbondingEntry:
    """
    Entry for tokens being unbonded.
    """
    delegator: bytes              # Who is unbonding
    validator: bytes              # From which validator
    amount: int                   # Token amount
    completion_height: int        # When unbonding completes
    created_height: int           # When unbonding started

    def is_mature(self, current_height: int) -> bool:
        """Check if unbonding period has completed."""
        return current_height >= self.completion_height

    def to_dict(self) -> dict:
        return {
            'delegator': self.delegator.hex(),
            'validator': self.validator.hex(),
            'amount': self.amount,
            'completion_height': self.completion_height,
            'created_height': self.created_height,
        }


@dataclass
class JailRecord:
    """
    Record of validator jailing.
    """
    reason: JailReason
    jailed_at_height: int
    unjail_height: int            # When can unjail
    evidence_hash: bytes = b""    # Hash of evidence
    slashed_amount: int = 0       # Amount slashed

    def can_unjail(self, current_height: int) -> bool:
        """Check if validator can be unjailed."""
        return current_height >= self.unjail_height

    def to_dict(self) -> dict:
        return {
            'reason': self.reason.value,
            'jailed_at_height': self.jailed_at_height,
            'unjail_height': self.unjail_height,
            'evidence_hash': self.evidence_hash.hex(),
            'slashed_amount': self.slashed_amount,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATOR
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Validator:
    """
    Validator in HONEST Chain PoS.

    Validators:
    - Propose and vote on blocks
    - Earn rewards from block production
    - Can be delegated to by other accounts
    - Subject to slashing for misbehavior
    """

    # IDENTITY
    pubkey: bytes                 # Dilithium public key (consensus key)
    operator: bytes               # Operator address (can change)

    # STAKE
    tokens: int = 0               # Total bonded tokens (self + delegated)
    delegator_shares: int = 0     # Total delegation shares

    # STATUS
    status: ValidatorStatus = ValidatorStatus.UNBONDED
    jailed: bool = False
    jail_record: Optional[JailRecord] = None

    # COMMISSION
    commission: Commission = field(default_factory=lambda: Commission(
        rate=1000,          # 10% default
        max_rate=5000,      # 50% max
        max_change_rate=100 # 1% max change
    ))

    # DESCRIPTION
    description: ValidatorDescription = field(
        default_factory=lambda: ValidatorDescription(moniker="")
    )

    # METRICS
    blocks_proposed: int = 0
    blocks_signed: int = 0
    blocks_missed: int = 0

    # TIMING
    created_at_height: int = 0
    unbonding_height: int = 0     # When unbonding started (if status=UNBONDING)

    # DELEGATIONS (tracked separately in ValidatorSet)
    # self_delegation tracked here
    self_delegation: int = 0

    @property
    def voting_power(self) -> int:
        """Get voting power (proportional to stake)."""
        if self.status != ValidatorStatus.BONDED:
            return 0
        return self.tokens

    @property
    def is_active(self) -> bool:
        """Check if validator is active."""
        return self.status == ValidatorStatus.BONDED and not self.jailed

    def tokens_from_shares(self, shares: int) -> int:
        """Convert delegation shares to tokens."""
        if self.delegator_shares == 0:
            return 0
        return (shares * self.tokens) // self.delegator_shares

    def shares_from_tokens(self, tokens: int) -> int:
        """Convert tokens to delegation shares."""
        if self.tokens == 0:
            return tokens  # 1:1 for first delegation
        return (tokens * self.delegator_shares) // self.tokens

    def add_tokens(self, amount: int) -> int:
        """
        Add tokens and return new shares.

        Returns number of new shares created.
        """
        new_shares = self.shares_from_tokens(amount)
        self.tokens += amount
        self.delegator_shares += new_shares
        return new_shares

    def remove_tokens(self, shares: int) -> int:
        """
        Remove tokens by burning shares.

        Returns number of tokens removed.
        """
        tokens_removed = self.tokens_from_shares(shares)
        self.tokens -= tokens_removed
        self.delegator_shares -= shares
        return tokens_removed

    def uptime_percentage(self) -> float:
        """Calculate uptime percentage."""
        total = self.blocks_signed + self.blocks_missed
        if total == 0:
            return 100.0
        return (self.blocks_signed / total) * 100

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'pubkey': self.pubkey.hex(),
            'operator': self.operator.hex(),
            'tokens': self.tokens,
            'delegator_shares': self.delegator_shares,
            'status': self.status.value,
            'jailed': self.jailed,
            'jail_record': self.jail_record.to_dict() if self.jail_record else None,
            'commission': self.commission.to_dict(),
            'description': self.description.to_dict(),
            'blocks_proposed': self.blocks_proposed,
            'blocks_signed': self.blocks_signed,
            'blocks_missed': self.blocks_missed,
            'created_at_height': self.created_at_height,
            'unbonding_height': self.unbonding_height,
            'self_delegation': self.self_delegation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Validator':
        """Deserialize from dictionary."""
        validator = cls(
            pubkey=bytes.fromhex(data['pubkey']),
            operator=bytes.fromhex(data['operator']),
            tokens=data.get('tokens', 0),
            delegator_shares=data.get('delegator_shares', 0),
            status=ValidatorStatus(data.get('status', 0)),
            jailed=data.get('jailed', False),
            commission=Commission.from_dict(data['commission']),
            description=ValidatorDescription.from_dict(data['description']),
            blocks_proposed=data.get('blocks_proposed', 0),
            blocks_signed=data.get('blocks_signed', 0),
            blocks_missed=data.get('blocks_missed', 0),
            created_at_height=data.get('created_at_height', 0),
            unbonding_height=data.get('unbonding_height', 0),
            self_delegation=data.get('self_delegation', 0),
        )
        return validator


# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATOR SET
# ═══════════════════════════════════════════════════════════════════════════════

class ValidatorSet:
    """
    Manages the validator set.

    Handles:
    - Validator registration/removal
    - Delegations
    - Active set selection
    - Jailing/unjailing
    """

    def __init__(self, max_validators: int = MAX_ACTIVE_VALIDATORS):
        self.max_validators = max_validators

        # All validators (by pubkey)
        self._validators: Dict[bytes, Validator] = {}

        # Active validator set (top N by stake)
        self._active_set: List[bytes] = []

        # Delegations: (delegator, validator) -> Delegation
        self._delegations: Dict[Tuple[bytes, bytes], Delegation] = {}

        # Unbonding queue
        self._unbonding: List[UnbondingEntry] = []

        # Current height (for operations)
        self._current_height: int = 0

    @property
    def total_bonded(self) -> int:
        """Get total bonded tokens."""
        return sum(v.tokens for v in self._validators.values()
                   if v.status == ValidatorStatus.BONDED)

    @property
    def active_validators(self) -> List[Validator]:
        """Get active validator list."""
        return [self._validators[pk] for pk in self._active_set
                if pk in self._validators]

    def set_height(self, height: int) -> None:
        """Set current block height."""
        self._current_height = height

    def get_validator(self, pubkey: bytes) -> Optional[Validator]:
        """Get validator by pubkey."""
        return self._validators.get(pubkey)

    def register_validator(
        self,
        pubkey: bytes,
        operator: bytes,
        self_delegation: int,
        commission: Commission,
        description: ValidatorDescription,
    ) -> Tuple[bool, str]:
        """
        Register a new validator.

        Args:
            pubkey: Consensus public key (Dilithium)
            operator: Operator address
            self_delegation: Initial self-delegation amount
            commission: Commission configuration
            description: Validator description

        Returns:
            (success, error_message)
        """
        # Check if already registered
        if pubkey in self._validators:
            return False, "Validator already registered"

        # Check minimum stake
        if self_delegation < MIN_VALIDATOR_STAKE:
            return False, f"Self-delegation {self_delegation} below minimum {MIN_VALIDATOR_STAKE}"

        # Check commission bounds
        if commission.rate > MAX_COMMISSION_RATE:
            return False, f"Commission rate {commission.rate} exceeds max {MAX_COMMISSION_RATE}"

        # Create validator
        validator = Validator(
            pubkey=pubkey,
            operator=operator,
            tokens=self_delegation,
            delegator_shares=self_delegation,  # 1:1 for first delegation
            status=ValidatorStatus.BONDED,
            commission=commission,
            description=description,
            created_at_height=self._current_height,
            self_delegation=self_delegation,
        )

        self._validators[pubkey] = validator

        # Create self-delegation record
        self._delegations[(operator, pubkey)] = Delegation(
            delegator=operator,
            validator=pubkey,
            shares=self_delegation,
            created_height=self._current_height,
        )

        # Update active set
        self._update_active_set()

        return True, ""

    def delegate(
        self,
        delegator: bytes,
        validator_pubkey: bytes,
        amount: int,
    ) -> Tuple[bool, str, int]:
        """
        Delegate tokens to a validator.

        Args:
            delegator: Delegator address
            validator_pubkey: Validator to delegate to
            amount: Token amount

        Returns:
            (success, error_message, shares_received)
        """
        # Check validator exists
        validator = self._validators.get(validator_pubkey)
        if not validator:
            return False, "Validator not found", 0

        # Check validator is active
        if validator.status != ValidatorStatus.BONDED:
            return False, "Validator is not active", 0

        # Check minimum
        if amount < MIN_DELEGATION:
            return False, f"Delegation {amount} below minimum {MIN_DELEGATION}", 0

        # Add tokens and get shares
        new_shares = validator.add_tokens(amount)

        # Update or create delegation
        key = (delegator, validator_pubkey)
        if key in self._delegations:
            self._delegations[key].shares += new_shares
        else:
            self._delegations[key] = Delegation(
                delegator=delegator,
                validator=validator_pubkey,
                shares=new_shares,
                created_height=self._current_height,
            )

        # Update active set
        self._update_active_set()

        return True, "", new_shares

    def undelegate(
        self,
        delegator: bytes,
        validator_pubkey: bytes,
        shares: int,
    ) -> Tuple[bool, str, int]:
        """
        Undelegate tokens from a validator.

        Args:
            delegator: Delegator address
            validator_pubkey: Validator to undelegate from
            shares: Shares to undelegate

        Returns:
            (success, error_message, tokens_unbonding)
        """
        # Check delegation exists
        key = (delegator, validator_pubkey)
        delegation = self._delegations.get(key)
        if not delegation:
            return False, "Delegation not found", 0

        # Check sufficient shares
        if shares > delegation.shares:
            return False, f"Insufficient shares: have {delegation.shares}, want {shares}", 0

        # Get validator
        validator = self._validators.get(validator_pubkey)
        if not validator:
            return False, "Validator not found", 0

        # Remove tokens
        tokens = validator.remove_tokens(shares)

        # Update delegation
        delegation.shares -= shares
        if delegation.shares == 0:
            del self._delegations[key]

        # Create unbonding entry
        self._unbonding.append(UnbondingEntry(
            delegator=delegator,
            validator=validator_pubkey,
            amount=tokens,
            completion_height=self._current_height + UNBONDING_PERIOD,
            created_height=self._current_height,
        ))

        # Update active set
        self._update_active_set()

        return True, "", tokens

    def jail(
        self,
        validator_pubkey: bytes,
        reason: JailReason,
        evidence_hash: bytes = b"",
        slash_fraction: float = 0.0,
    ) -> Tuple[bool, str]:
        """
        Jail a validator for misbehavior.

        Args:
            validator_pubkey: Validator to jail
            reason: Reason for jailing
            evidence_hash: Hash of evidence
            slash_fraction: Fraction of stake to slash (0-1)

        Returns:
            (success, error_message)
        """
        validator = self._validators.get(validator_pubkey)
        if not validator:
            return False, "Validator not found"

        if validator.jailed:
            return False, "Validator already jailed"

        # Determine jail duration
        if reason == JailReason.DOUBLE_SIGN:
            jail_duration = JAIL_DURATION_MAJOR
        else:
            jail_duration = JAIL_DURATION_MINOR

        # Calculate slash amount
        slashed = int(validator.tokens * slash_fraction)

        # Apply slashing
        if slashed > 0:
            validator.tokens -= slashed
            # Also reduce delegator shares proportionally
            if validator.delegator_shares > 0:
                slash_ratio = slashed / (validator.tokens + slashed)
                validator.delegator_shares = int(
                    validator.delegator_shares * (1 - slash_ratio)
                )

        # Jail validator
        validator.jailed = True
        validator.jail_record = JailRecord(
            reason=reason,
            jailed_at_height=self._current_height,
            unjail_height=self._current_height + jail_duration,
            evidence_hash=evidence_hash,
            slashed_amount=slashed,
        )

        # Remove from active set
        self._update_active_set()

        return True, ""

    def unjail(self, validator_pubkey: bytes) -> Tuple[bool, str]:
        """
        Unjail a validator.

        Args:
            validator_pubkey: Validator to unjail

        Returns:
            (success, error_message)
        """
        validator = self._validators.get(validator_pubkey)
        if not validator:
            return False, "Validator not found"

        if not validator.jailed:
            return False, "Validator is not jailed"

        if validator.jail_record and not validator.jail_record.can_unjail(self._current_height):
            return False, f"Cannot unjail until height {validator.jail_record.unjail_height}"

        # Unjail
        validator.jailed = False

        # Update active set
        self._update_active_set()

        return True, ""

    def process_unbonding(self) -> List[UnbondingEntry]:
        """
        Process mature unbonding entries.

        Returns list of completed unbonding entries.
        """
        mature = []
        remaining = []

        for entry in self._unbonding:
            if entry.is_mature(self._current_height):
                mature.append(entry)
            else:
                remaining.append(entry)

        self._unbonding = remaining
        return mature

    def _update_active_set(self) -> None:
        """Update the active validator set based on stake."""
        # Get all bonded, non-jailed validators
        eligible = [
            v for v in self._validators.values()
            if v.status == ValidatorStatus.BONDED and not v.jailed
        ]

        # Sort by tokens (descending)
        eligible.sort(key=lambda v: v.tokens, reverse=True)

        # Take top N
        self._active_set = [v.pubkey for v in eligible[:self.max_validators]]

    def get_delegation(self, delegator: bytes, validator: bytes) -> Optional[Delegation]:
        """Get delegation for a specific delegator-validator pair."""
        return self._delegations.get((delegator, validator))

    def get_delegations_by_delegator(self, delegator: bytes) -> List[Delegation]:
        """Get all delegations for a delegator."""
        return [d for (del_, val), d in self._delegations.items()
                if del_ == delegator]

    def get_delegations_by_validator(self, validator: bytes) -> List[Delegation]:
        """Get all delegations to a validator."""
        return [d for (del_, val), d in self._delegations.items()
                if val == validator]

    def stats(self) -> dict:
        """Get validator set statistics."""
        return {
            'total_validators': len(self._validators),
            'active_validators': len(self._active_set),
            'total_bonded': self.total_bonded,
            'total_delegations': len(self._delegations),
            'unbonding_entries': len(self._unbonding),
        }

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            'validators': {pk.hex(): v.to_dict() for pk, v in self._validators.items()},
            'active_set': [pk.hex() for pk in self._active_set],
            'delegations': [d.to_dict() for d in self._delegations.values()],
            'unbonding': [u.to_dict() for u in self._unbonding],
            'current_height': self._current_height,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("HONEST Chain - Validator Management Test")
    print("=" * 50)

    # Create validator set
    vs = ValidatorSet(max_validators=10)
    vs.set_height(1000)

    # Register validator 1
    pk1 = bytes.fromhex("01" * 32)
    op1 = bytes.fromhex("a1" * 32)
    success, msg = vs.register_validator(
        pubkey=pk1,
        operator=op1,
        self_delegation=MIN_VALIDATOR_STAKE,
        commission=Commission(rate=1000, max_rate=3000, max_change_rate=100),
        description=ValidatorDescription(moniker="Validator One"),
    )
    print(f"\nRegister validator 1: {success} - {msg}")

    # Register validator 2
    pk2 = bytes.fromhex("02" * 32)
    op2 = bytes.fromhex("a2" * 32)
    success, msg = vs.register_validator(
        pubkey=pk2,
        operator=op2,
        self_delegation=MIN_VALIDATOR_STAKE * 2,
        commission=Commission(rate=500, max_rate=2000, max_change_rate=50),
        description=ValidatorDescription(moniker="Validator Two"),
    )
    print(f"Register validator 2: {success} - {msg}")

    # Check stats
    print(f"\nStats: {vs.stats()}")

    # Delegate to validator 1
    delegator = bytes.fromhex("d1" * 32)
    success, msg, shares = vs.delegate(delegator, pk1, 50_000_000_000)
    print(f"\nDelegate 50k to V1: {success}, shares={shares}")

    # Get validator info
    v1 = vs.get_validator(pk1)
    print(f"Validator 1 tokens: {v1.tokens}")
    print(f"Validator 1 voting power: {v1.voting_power}")

    # Check active set (V2 should be first due to higher stake)
    active = vs.active_validators
    print(f"\nActive validators: {len(active)}")
    for v in active:
        print(f"  - {v.description.moniker}: {v.tokens} tokens")

    # Undelegate
    success, msg, tokens = vs.undelegate(delegator, pk1, shares // 2)
    print(f"\nUndelegate half: {success}, tokens={tokens}")

    # Jail validator 2
    success, msg = vs.jail(pk2, JailReason.DOWNTIME, slash_fraction=0.01)
    print(f"\nJail V2 for downtime: {success}")

    v2 = vs.get_validator(pk2)
    print(f"V2 jailed: {v2.jailed}")
    print(f"V2 jail reason: {v2.jail_record.reason.name}")

    # Check active set (V2 should be removed)
    active = vs.active_validators
    print(f"\nActive after jail: {len(active)}")

    # Fast forward and unjail
    vs.set_height(1000 + JAIL_DURATION_MINOR)
    success, msg = vs.unjail(pk2)
    print(f"\nUnjail V2: {success}")

    # Process unbonding
    vs.set_height(1000 + UNBONDING_PERIOD + 1)
    mature = vs.process_unbonding()
    print(f"\nMature unbonding entries: {len(mature)}")

    print(f"\nFinal stats: {vs.stats()}")
    print("\nValidator management tests passed!")
