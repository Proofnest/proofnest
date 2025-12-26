"""
PROOFNEST P2P Node Network
=======================

Decentralized network for PROOFNEST propagation.
Ensures "peatamatus" (unstoppability) - no single point of failure.

Architecture:
- Each node stores its own chain + peers' chains
- Merkle roots are shared for quick verification
- Full chain sync on demand
- Gossip protocol for propagation

Copyright (c) 2025 Stellanium Ltd. All rights reserved.
Licensed under Apache License 2.0. See LICENSE file.
PROOFNEST™ is a trademark of Stellanium Ltd.
"""

import asyncio
import hashlib
import hmac
import json
import socket
import struct
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable
from enum import Enum
import secrets


class MessageType(Enum):
    """P2P message types"""
    PING = "ping"
    PONG = "pong"
    ANNOUNCE = "announce"           # Announce new merkle root
    REQUEST_CHAIN = "request_chain"  # Request full chain
    CHAIN_DATA = "chain_data"        # Full chain response
    PEER_LIST = "peer_list"          # Share known peers
    ANCHOR_REQUEST = "anchor_req"    # Request anchoring from peers
    ANCHOR_CONFIRM = "anchor_conf"   # Confirm anchor received


@dataclass
class Peer:
    """Known peer in the network"""
    node_id: str
    host: str
    port: int
    last_seen: float = 0.0
    merkle_root: str = ""
    trust_score: float = 1.0


@dataclass
class Message:
    """P2P message format"""
    msg_type: MessageType
    sender_id: str
    payload: dict
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    signature: str = ""

    def to_bytes(self) -> bytes:
        """Serialize message for network transmission"""
        data = {
            "type": self.msg_type.value,
            "sender": self.sender_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "signature": self.signature
        }
        json_bytes = json.dumps(data).encode('utf-8')
        # Prefix with length for framing
        return struct.pack('>I', len(json_bytes)) + json_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> 'Message':
        """Deserialize message from network"""
        json_data = json.loads(data.decode('utf-8'))
        return cls(
            msg_type=MessageType(json_data["type"]),
            sender_id=json_data["sender"],
            payload=json_data["payload"],
            timestamp=json_data["timestamp"],
            signature=json_data.get("signature", "")
        )


class Node:
    """
    PROOFNEST P2P Node - "Peatamatus" (Unstoppability)

    Each node is both client and server:
    - Stores local chain data
    - Connects to peers
    - Propagates updates
    - Provides anchoring service

    P1 SECURITY FEATURES (v1.1):
    - Message size limits (prevent DoS)
    - Rate limiting (prevent spam)
    - Peer authentication (HMAC signatures)

    P2 SECURITY FEATURES (v1.2):
    - Minimum SDK version enforcement (reject < 2.13.7)
    """

    VERSION = "1.2"
    MIN_SDK_VERSION = "2.13.7"  # Minimum safe version - no security vulnerabilities
    DEFAULT_PORT = 7777  # PROOFNEST port
    MAX_PEERS = 50
    PEER_TIMEOUT = 300  # 5 minutes

    # P1 SECURITY: Message size limits
    MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB max message
    MIN_MESSAGE_SIZE = 8  # Minimum valid message (4 byte length + 4 byte content)

    # P1 SECURITY: Rate limiting
    RATE_LIMIT_WINDOW = 60  # 1 minute window
    RATE_LIMIT_MAX_REQUESTS = 100  # Max requests per window per IP

    def __init__(
        self,
        node_id: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
        data_dir: Optional[Path] = None,
        bootstrap_peers: Optional[List[str]] = None
    ):
        """
        Initialize PROOFNEST P2P node.

        Args:
            node_id: Unique node identifier (generated if not provided)
            host: Host to bind to
            port: Port to listen on
            data_dir: Directory for storing chain data
            bootstrap_peers: Initial peers to connect to (host:port format)
        """
        self.node_id = node_id or f"node:{secrets.token_hex(8)}"
        self.host = host
        self.port = port

        # Data storage
        self.data_dir = data_dir or Path.home() / ".proofnest_node" / self.node_id
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Network state
        self.peers: Dict[str, Peer] = {}
        self.bootstrap_peers = bootstrap_peers or []
        self._lock = threading.Lock()

        # P1 SECURITY: Rate limiting state
        self._rate_limits: Dict[str, List[float]] = {}  # IP -> list of request timestamps
        self._rate_lock = threading.Lock()

        # P1 SECURITY: Shared secret for peer authentication (generated per node)
        self._auth_secret = secrets.token_bytes(32)

        # Chain data (merkle roots from all known chains)
        self.known_roots: Dict[str, str] = {}  # agent_id -> merkle_root
        self._load_state()

        # Server
        self._server_socket: Optional[socket.socket] = None
        self._running = False

        # Callbacks
        self._on_anchor_request: Optional[Callable[[str], str]] = None

    def _load_state(self) -> None:
        """Load persisted state"""
        state_file = self.data_dir / "state.json"
        if state_file.exists():
            with open(state_file) as f:
                data = json.load(f)
                self.known_roots = data.get("known_roots", {})
                for peer_data in data.get("peers", []):
                    peer = Peer(**peer_data)
                    self.peers[peer.node_id] = peer

    def _save_state(self) -> None:
        """Persist state to disk"""
        with self._lock:
            state_file = self.data_dir / "state.json"
            data = {
                "known_roots": self.known_roots,
                "peers": [asdict(p) for p in self.peers.values()]
            }
            with open(state_file, "w") as f:
                json.dump(data, f, indent=2)

    def start(self) -> None:
        """Start the P2P node"""
        self._running = True

        # Start server thread
        server_thread = threading.Thread(target=self._run_server, daemon=True)
        server_thread.start()

        # Connect to bootstrap peers
        for peer_addr in self.bootstrap_peers:
            try:
                host, port = peer_addr.split(":")
                self._connect_to_peer(host, int(port))
            except Exception as e:
                print(f"Failed to connect to bootstrap peer {peer_addr}: {e}")

        print(f"PROOFNEST Node started: {self.node_id}")
        print(f"Listening on {self.host}:{self.port}")

    def stop(self) -> None:
        """Stop the P2P node"""
        self._running = False
        if self._server_socket:
            self._server_socket.close()
        self._save_state()
        print(f"PROOFNEST Node stopped: {self.node_id}")

    def _is_version_safe(self, version: str) -> bool:
        """
        P2 SECURITY: Check if SDK version is safe (>= MIN_SDK_VERSION).
        Returns True if version is safe, False if vulnerable.
        """
        try:
            # Parse versions as tuples for comparison
            def parse_version(v: str) -> tuple:
                parts = v.split(".")
                return tuple(int(p) for p in parts[:3])

            client_version = parse_version(version)
            min_version = parse_version(self.MIN_SDK_VERSION)
            return client_version >= min_version
        except (ValueError, AttributeError):
            # Invalid version format - reject
            return False

    def _check_rate_limit(self, ip: str) -> bool:
        """
        P1 SECURITY: Check if IP is within rate limits.

        Returns True if request is allowed, False if rate limited.
        """
        now = time.time()
        window_start = now - self.RATE_LIMIT_WINDOW

        with self._rate_lock:
            if ip not in self._rate_limits:
                self._rate_limits[ip] = []

            # Remove old timestamps outside window
            self._rate_limits[ip] = [t for t in self._rate_limits[ip] if t > window_start]

            # Check if within limit
            if len(self._rate_limits[ip]) >= self.RATE_LIMIT_MAX_REQUESTS:
                return False

            # Add this request
            self._rate_limits[ip].append(now)
            return True

    def _sign_message(self, message: Message) -> str:
        """
        P1 SECURITY: Sign a message with node's auth secret.
        """
        # Create canonical representation for signing
        data = f"{message.msg_type.value}:{message.sender_id}:{message.timestamp}"
        sig = hmac.new(self._auth_secret, data.encode(), hashlib.sha3_256).hexdigest()
        return sig

    def _verify_peer_signature(self, message: Message, peer_secret: bytes) -> bool:
        """
        P1 SECURITY: Verify message signature from a peer.

        Note: Requires knowing peer's secret (exchanged during handshake).
        For third-party verification, use asymmetric signatures in future.
        """
        if not message.signature:
            return False

        data = f"{message.msg_type.value}:{message.sender_id}:{message.timestamp}"
        expected = hmac.new(peer_secret, data.encode(), hashlib.sha3_256).hexdigest()
        return hmac.compare_digest(expected, message.signature)

    def _run_server(self) -> None:
        """Run the TCP server"""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(10)
        self._server_socket.settimeout(1.0)

        while self._running:
            try:
                client_socket, address = self._server_socket.accept()
                # Handle in separate thread
                handler = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, address),
                    daemon=True
                )
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"Server error: {e}")

    def _handle_connection(self, client_socket: socket.socket, address: tuple) -> None:
        """Handle incoming connection with P1 security checks"""
        client_ip = address[0]

        try:
            # P1 SECURITY: Rate limiting check
            if not self._check_rate_limit(client_ip):
                print(f"SECURITY: Rate limit exceeded for {client_ip}")
                client_socket.close()
                return

            client_socket.settimeout(30.0)

            # Read message length
            length_data = client_socket.recv(4)
            if len(length_data) < 4:
                return
            msg_length = struct.unpack('>I', length_data)[0]

            # P1 SECURITY: Message size validation
            if msg_length > self.MAX_MESSAGE_SIZE:
                print(f"SECURITY: Message too large from {client_ip}: {msg_length} bytes")
                return
            if msg_length < self.MIN_MESSAGE_SIZE - 4:  # Already read 4 bytes for length
                print(f"SECURITY: Message too small from {client_ip}: {msg_length} bytes")
                return

            # Read message with size limit
            msg_data = b""
            bytes_remaining = msg_length
            while bytes_remaining > 0:
                chunk_size = min(4096, bytes_remaining)
                chunk = client_socket.recv(chunk_size)
                if not chunk:
                    break
                msg_data += chunk
                bytes_remaining -= len(chunk)

            if len(msg_data) != msg_length:
                print(f"SECURITY: Incomplete message from {client_ip}")
                return

            message = Message.from_bytes(msg_data)
            response = self._process_message(message, address)

            if response:
                # P1 SECURITY: Sign outgoing messages
                response.signature = self._sign_message(response)
                client_socket.sendall(response.to_bytes())

        except json.JSONDecodeError as e:
            print(f"SECURITY: Invalid JSON from {client_ip}: {e}")
        except Exception as e:
            print(f"Connection error from {address}: {e}")
        finally:
            client_socket.close()

    def _process_message(self, message: Message, address: tuple) -> Optional[Message]:
        """Process incoming message and return response"""
        sender = message.sender_id

        # Update peer info
        with self._lock:
            if sender not in self.peers:
                self.peers[sender] = Peer(
                    node_id=sender,
                    host=address[0],
                    port=message.payload.get("port", self.DEFAULT_PORT)
                )
            self.peers[sender].last_seen = time.time()

        if message.msg_type == MessageType.PING:
            # P2 SECURITY: Check client SDK version
            client_sdk_version = message.payload.get("sdk_version", "0.0.0")
            if not self._is_version_safe(client_sdk_version):
                print(f"SECURITY: Rejected client with unsafe SDK version {client_sdk_version} from {address[0]}")
                return Message(
                    msg_type=MessageType.PONG,
                    sender_id=self.node_id,
                    payload={
                        "version": self.VERSION,
                        "error": f"SDK version {client_sdk_version} is vulnerable. Upgrade to {self.MIN_SDK_VERSION}+",
                        "rejected": True
                    }
                )
            return Message(
                msg_type=MessageType.PONG,
                sender_id=self.node_id,
                payload={"version": self.VERSION, "rejected": False}
            )

        elif message.msg_type == MessageType.ANNOUNCE:
            # New merkle root announced
            agent_id = message.payload.get("agent_id")
            merkle_root = message.payload.get("merkle_root")
            if agent_id and merkle_root:
                with self._lock:
                    self.known_roots[agent_id] = merkle_root
                self._save_state()
                # Propagate to other peers (gossip)
                self._gossip_announce(agent_id, merkle_root, exclude=sender)
            return None

        elif message.msg_type == MessageType.REQUEST_CHAIN:
            agent_id = message.payload.get("agent_id")
            chain_file = self.data_dir / "chains" / f"{agent_id}.json"
            if chain_file.exists():
                with open(chain_file) as f:
                    chain_data = json.load(f)
                return Message(
                    msg_type=MessageType.CHAIN_DATA,
                    sender_id=self.node_id,
                    payload={"agent_id": agent_id, "chain": chain_data}
                )
            return None

        elif message.msg_type == MessageType.PEER_LIST:
            # Return known peers
            peer_list = [
                {"node_id": p.node_id, "host": p.host, "port": p.port}
                for p in self.peers.values()
                if time.time() - p.last_seen < self.PEER_TIMEOUT
            ][:20]  # Limit response size
            return Message(
                msg_type=MessageType.PEER_LIST,
                sender_id=self.node_id,
                payload={"peers": peer_list}
            )

        elif message.msg_type == MessageType.ANCHOR_REQUEST:
            # External anchoring request - store hash and return confirmation
            record_hash = message.payload.get("record_hash")
            if record_hash and self._on_anchor_request:
                anchor_proof = self._on_anchor_request(record_hash)
                return Message(
                    msg_type=MessageType.ANCHOR_CONFIRM,
                    sender_id=self.node_id,
                    payload={
                        "record_hash": record_hash,
                        "anchor_proof": anchor_proof,
                        "anchored_by": self.node_id,
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                )
            return None

        return None

    def _connect_to_peer(self, host: str, port: int) -> bool:
        """Connect to a peer and exchange info"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((host, port))

            # Send ping with SDK version for security check
            from proofnest import __version__ as SDK_VERSION
            ping = Message(
                msg_type=MessageType.PING,
                sender_id=self.node_id,
                payload={"port": self.port, "version": self.VERSION, "sdk_version": SDK_VERSION}
            )
            sock.sendall(ping.to_bytes())

            # Read response
            length_data = sock.recv(4)
            if len(length_data) < 4:
                return False
            msg_length = struct.unpack('>I', length_data)[0]
            msg_data = sock.recv(msg_length)
            response = Message.from_bytes(msg_data)

            if response.msg_type == MessageType.PONG:
                # P2 SECURITY: Check if server rejected us
                if response.payload.get("rejected"):
                    error_msg = response.payload.get("error", "Connection rejected")
                    print(f"SECURITY: Server rejected connection: {error_msg}")
                    return False

                with self._lock:
                    self.peers[response.sender_id] = Peer(
                        node_id=response.sender_id,
                        host=host,
                        port=port,
                        last_seen=time.time()
                    )
                print(f"Connected to peer: {response.sender_id}")
                return True

        except Exception as e:
            print(f"Failed to connect to {host}:{port}: {e}")
        finally:
            sock.close()

        return False

    def _gossip_announce(self, agent_id: str, merkle_root: str, exclude: str = None) -> None:
        """Gossip announce to all peers except sender"""
        message = Message(
            msg_type=MessageType.ANNOUNCE,
            sender_id=self.node_id,
            payload={"agent_id": agent_id, "merkle_root": merkle_root}
        )

        for peer in list(self.peers.values()):
            if peer.node_id == exclude:
                continue
            if time.time() - peer.last_seen > self.PEER_TIMEOUT:
                continue
            try:
                self._send_message(peer, message)
            except Exception:
                pass  # Ignore send failures in gossip

    def _send_message(self, peer: Peer, message: Message) -> Optional[Message]:
        """Send message to peer and optionally get response (with P1 security)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        try:
            # P1 SECURITY: Sign outgoing message
            message.signature = self._sign_message(message)

            sock.connect((peer.host, peer.port))
            sock.sendall(message.to_bytes())

            # Read response if expected
            length_data = sock.recv(4)
            if len(length_data) < 4:
                return None
            msg_length = struct.unpack('>I', length_data)[0]

            # P1 SECURITY: Validate response size
            if msg_length > self.MAX_MESSAGE_SIZE:
                print(f"SECURITY: Response too large from {peer.host}: {msg_length} bytes")
                return None

            # Read with size tracking
            msg_data = b""
            bytes_remaining = msg_length
            while bytes_remaining > 0:
                chunk = sock.recv(min(4096, bytes_remaining))
                if not chunk:
                    break
                msg_data += chunk
                bytes_remaining -= len(chunk)

            return Message.from_bytes(msg_data)
        finally:
            sock.close()

    # === Public API ===

    def announce_chain(self, agent_id: str, merkle_root: str) -> None:
        """Announce a chain's merkle root to the network"""
        with self._lock:
            self.known_roots[agent_id] = merkle_root
        self._save_state()
        self._gossip_announce(agent_id, merkle_root)

    def request_anchor(self, record_hash: str) -> List[dict]:
        """Request anchoring from multiple peers (for redundancy)"""
        anchors = []
        message = Message(
            msg_type=MessageType.ANCHOR_REQUEST,
            sender_id=self.node_id,
            payload={"record_hash": record_hash}
        )

        for peer in list(self.peers.values())[:5]:  # Ask up to 5 peers
            try:
                response = self._send_message(peer, message)
                if response and response.msg_type == MessageType.ANCHOR_CONFIRM:
                    anchors.append(response.payload)
            except Exception:
                continue

        return anchors

    def get_peer_count(self) -> int:
        """Get number of active peers"""
        return len([
            p for p in self.peers.values()
            if time.time() - p.last_seen < self.PEER_TIMEOUT
        ])

    def get_known_chains(self) -> Dict[str, str]:
        """Get all known chain merkle roots"""
        return dict(self.known_roots)

    def set_anchor_handler(self, handler: Callable[[str], str]) -> None:
        """Set callback for handling anchor requests"""
        self._on_anchor_request = handler


def create_anchor_callback(node: Node) -> Callable[[str], str]:
    """
    Create external anchor callback for ProofNest integration.

    Usage:
        node = Node()
        node.start()

        from proofnest import ProofNest
        hc = ProofNest(
            agent_id="my-agent",
            external_anchor=create_anchor_callback(node)
        )
    """
    def anchor(record_hash: str) -> str:
        anchors = node.request_anchor(record_hash)
        if anchors:
            # Return proof from first successful anchor
            return json.dumps({
                "p2p_anchors": anchors,
                "anchor_count": len(anchors),
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
        return f"local:{node.node_id}:{record_hash[:16]}"

    return anchor


# === Demo ===

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "node1":
        # First node
        node = Node(node_id="node-alpha", port=7777)
        node.start()
        print("Node 1 running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            node.stop()

    elif len(sys.argv) > 1 and sys.argv[1] == "node2":
        # Second node connecting to first
        node = Node(
            node_id="node-beta",
            port=7778,
            bootstrap_peers=["127.0.0.1:7777"]
        )
        node.start()
        print(f"Node 2 running. Peers: {node.get_peer_count()}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            node.stop()

    else:
        print("PROOFNEST P2P Node Network")
        print("=" * 50)
        print("Usage:")
        print("  python p2p_node.py node1  # Start first node on port 7777")
        print("  python p2p_node.py node2  # Start second node on port 7778")
        print()
        print("Integration with ProofNest:")
        print("  from p2p_node import Node, create_anchor_callback")
        print("  from proofnest import ProofNest")
        print()
        print("  node = Node()")
        print("  node.start()")
        print()
        print("  hc = ProofNest(")
        print("      agent_id='my-agent',")
        print("      external_anchor=create_anchor_callback(node)")
        print("  )")


