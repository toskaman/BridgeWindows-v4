#!/usr/bin/env python3
"""
BridgeWindows MCP Server v4.0.0
Provides seamless, native remote control of a secondary Windows 10 x86 PC
via reverse TCP connection with hot auto-update, telemetry, structured logs,
and bidirectional recursive file synchronization.

Architecture:
  Antigravity (Master PC) <--(stdio MCP)--> bridge_mcp.py <--(Reverse TCP)--> agent.exe (Target PC)
"""

import sys
import os
import re
import socket
import struct
import json
import base64
import hashlib
import hmac
import secrets
import threading
import time
import argparse
from contextvars import ContextVar
from typing import Dict, Any, Optional, List

DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 9876
PROTOCOL_VERSION = "4.0.0"
MAX_FRAME_SIZE = 32 * 1024 * 1024  # 32 MB max frame size for high-res screenshots
MAX_CHUNK_SIZE = 256 * 1024        # 256 KB chunk for file transfers
MAX_CHUNK_RETRIES = 3              # Retry attempts per chunk on SHA-256 mismatch
MAX_AGENTS_DEFAULT = 8             # simultaneous authenticated agents
HANDSHAKE_TIMEOUT = 10.0           # seconds to complete mutual auth, else drop
TAKEOVER_AFTER_S = 30.0             # silent seconds before a same-id handshake steals a ghost slot
MAX_PENDING_PER_AGENT = 64         # in-flight RPC cap per agent (fail-closed)
AGENT_ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$')

# Per-request agent routing. handle_tool_call() sets it; send_rpc() falls back
# to it when no explicit agent_id is given. Thread- and task-isolated.
_agent_ctx: ContextVar[Optional[str]] = ContextVar('bw_agent', default=None)


def _hmac_hex(key: bytes, *parts: str) -> str:
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p.encode('utf-8'))
    return m.hexdigest()


def _is_hex(value: Any, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def _valid_agent_id(value: Any) -> bool:
    return isinstance(value, str) and AGENT_ID_RE.match(value) is not None


def get_master_lan_ips() -> List[str]:
    """Detects local IPv4 addresses on Master PC (excluding loopback and APIPA)."""
    ips = []
    # 1. Preferred route via default gateway probe
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        primary = s.getsockname()[0]
        s.close()
        if primary and not primary.startswith("127.") and not primary.startswith("169.254."):
            ips.append(primary)
    except Exception:
        pass

    # 2. Hostname enumeration for additional Wi-Fi / Ethernet interfaces
    try:
        host = socket.gethostname()
        for ip in socket.gethostbyname_ex(host)[2]:
            if not ip.startswith("127.") and not ip.startswith("169.254.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    return ips if ips else ["127.0.0.1"]


def compute_sha256(filepath: str) -> str:
    """Computes SHA-256 of a local file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class _AgentSession:
    """One mutually-authenticated agent connection. All mutable per-agent state lives here."""

    def __init__(self, agent_id: str, sock: socket.socket, addr, info: Dict[str, Any], sesskey: bytes):
        self.agent_id = agent_id
        self.sock = sock
        self.addr = addr
        self.info = info
        self.sesskey = sesskey
        self.send_lock = threading.Lock()
        self.pending_requests: Dict[int, threading.Event] = {}
        self.pending_responses: Dict[int, Dict[str, Any]] = {}
        self.next_req_id = 1
        self.connected_at = time.time()
        self.last_seen = self.connected_at
        self.alive = True


class RemoteAgentBridge:
    def __init__(self, host: str = DEFAULT_LISTEN_HOST, port: int = DEFAULT_LISTEN_PORT,
                 token: Optional[str] = None, max_agents: int = MAX_AGENTS_DEFAULT,
                 handshake_timeout: float = HANDSHAKE_TIMEOUT):
        self.host = host
        self.port = port
        self.token = token
        self.max_agents = max_agents
        self.handshake_timeout = handshake_timeout
        self.server_sock: Optional[socket.socket] = None
        self.agents: Dict[str, _AgentSession] = {}
        self.lock = threading.Lock()
        self.running = True
        self.connected_event = threading.Event()

    @property
    def is_connected(self) -> bool:
        with self.lock:
            return any(s.alive for s in self.agents.values())

    def _sole_session(self) -> Optional[_AgentSession]:
        with self.lock:
            live = [s for s in self.agents.values() if s.alive]
            return live[0] if len(live) == 1 else None

    # Backward-compatible single-agent views (None unless exactly one agent live).
    @property
    def client_sock(self) -> Optional[socket.socket]:
        s = self._sole_session()
        return s.sock if s else None

    @property
    def client_addr(self):
        s = self._sole_session()
        return s.addr if s else None

    @property
    def agent_info(self) -> Dict[str, Any]:
        s = self._sole_session()
        return dict(s.info) if s else {}

    def start_server(self):
        if not self.token:
            raise RuntimeError('PSK required: pass token=... (CLI --token or OPENBRIDGE_PSK env). Refusing to listen unauthenticated.')
        if len(self.token) < 20:
            # Warn-only (not refuse): the live deployment's PSK length is unknown here and refusing
            # could break it. A short PSK falls to offline brute force from one captured handshake.
            sys.stderr.write('[BridgeServer] WARNING: PSK is short (<20 chars). Use a long random PSK '
                             '(e.g. python -c "import secrets; print(secrets.token_urlsafe(32))") on the bridge '
                             'and every agent.\n')
            sys.stderr.flush()
        t = threading.Thread(target=self._server_loop, daemon=True)
        t.start()

    def _server_loop(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.port))
        self.server_sock.listen(16)
        sys.stderr.write(f"[BridgeServer] v{PROTOCOL_VERSION} listening for agents on {self.host}:{self.port} (max {self.max_agents})...\n")
        sys.stderr.write("[BridgeServer] WARNING: v4 frames are authenticated (mutual HMAC), NOT encrypted. Keep this link on a trusted LAN: a passive observer sees RPC payloads (screenshots, files, commands).\n")
        sys.stderr.flush()

        while self.running:
            try:
                sock, addr = self.server_sock.accept()
            except OSError:
                break
            except Exception as e:
                if self.running:
                    sys.stderr.write(f"[BridgeServer] Error accepting client: {e}\n")
                    sys.stderr.flush()
                continue
            sys.stderr.write(f"[BridgeServer] Incoming connection from {addr}\n")
            sys.stderr.flush()
            t = threading.Thread(target=self._serve_connection, args=(sock, addr), daemon=True)
            t.start()

    @staticmethod
    def _set_keepalive(sock: socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
                sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 30000, 10000))
        except OSError:
            pass

    @staticmethod
    def _recv_exact(sock: socket.socket, num_bytes: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < num_bytes:
            chunk = sock.recv(num_bytes - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    @classmethod
    def _send_frame(cls, sock: socket.socket, obj: Dict[str, Any]):
        payload = json.dumps(obj).encode('utf-8')
        sock.sendall(struct.pack('!I', len(payload)) + payload)

    @classmethod
    def _recv_frame(cls, sock: socket.socket) -> Dict[str, Any]:
        header = cls._recv_exact(sock, 4)
        if not header:
            raise ConnectionError('closed during header')
        (length,) = struct.unpack('!I', header)
        if length == 0 or length > MAX_FRAME_SIZE:
            raise ValueError(f'bad frame length {length}')
        payload = cls._recv_exact(sock, length)
        if not payload:
            raise ConnectionError('closed during payload')
        data = json.loads(payload.decode('utf-8'))
        if not isinstance(data, dict):
            raise ValueError('frame is not a JSON object')
        return data

    @classmethod
    def _send_plain_error(cls, sock: socket.socket, message: str):
        try:
            cls._send_frame(sock, {'jsonrpc': '2.0', 'error': {'code': -32000, 'message': message}})
        except OSError:
            pass

    def _serve_connection(self, sock: socket.socket, addr):
        """Mutual-auth handshake, then the per-agent serve loop. Never blocks accept()."""
        self._set_keepalive(sock)
        psk = self.token.encode('utf-8')
        session = None
        try:
            sock.settimeout(self.handshake_timeout)
            try:
                hello = self._recv_frame(sock)
            except (socket.timeout, TimeoutError):
                self._send_plain_error(sock, 'handshake timeout')
                return
            params = hello.get('params') if isinstance(hello, dict) and hello.get('method') == 'agent.hello' else None
            agent_id = params.get('agent_id') if isinstance(params, dict) else None
            agent_nonce = params.get('agent_nonce') if isinstance(params, dict) else None
            if not isinstance(params, dict) or 'token' in params or not _valid_agent_id(agent_id) or not _is_hex(agent_nonce, 32):
                self._send_plain_error(sock, 'auth.required: v4 hello with agent_id + agent_nonce (no token on wire)')
                return
            with self.lock:
                if len(self.agents) >= self.max_agents:
                    full = True
                elif agent_id in self.agents and self.agents[agent_id].alive:
                    full = False
                    dup = True
                else:
                    full = False
                    dup = False
            if full:
                self._send_plain_error(sock, f'server full ({self.max_agents} agents max)')
                return
            if dup:
                if self._takeover_stale(agent_id):
                    dup = False
                else:
                    self._send_plain_error(sock, f"duplicate agent_id '{agent_id}' (already connected)")
                    return
            master_nonce = secrets.token_hex(16)
            self._send_frame(sock, {'jsonrpc': '2.0', 'method': 'auth.challenge',
                                    'params': {'master_nonce': master_nonce, 'agent_id': agent_id}})
            try:
                resp = self._recv_frame(sock)
            except (socket.timeout, TimeoutError):
                self._send_plain_error(sock, 'handshake timeout')
                return
            rparams = resp.get('params') if isinstance(resp, dict) and resp.get('method') == 'auth.response' else None
            peer_hmac = rparams.get('hmac') if isinstance(rparams, dict) else None
            expect = _hmac_hex(psk, agent_nonce, master_nonce, agent_id)
            if not isinstance(rparams, dict) or rparams.get('agent_id') != agent_id or not _is_hex(peer_hmac, 64) \
                    or not hmac.compare_digest(peer_hmac, expect):
                self._send_plain_error(sock, 'auth.failed')
                return
            self._send_frame(sock, {'jsonrpc': '2.0', 'method': 'auth.confirm',
                                    'params': {'hmac': _hmac_hex(psk, master_nonce, agent_nonce, agent_id)}})
            sesskey = hashlib.sha256(psk + agent_nonce.encode() + master_nonce.encode()).digest()
            info = {'version': params.get('version'), 'arch': params.get('arch'), 'os': params.get('os'),
                    'pid': params.get('pid')}
            session = _AgentSession(agent_id, sock, addr, info, sesskey)
            with self.lock:
                if len(self.agents) >= self.max_agents or (agent_id in self.agents and self.agents[agent_id].alive):
                    session = None
                    self._send_plain_error(sock, 'registration lost the race; retry')
                    return
                self.agents[agent_id] = session
                self.connected_event.set()
            sys.stderr.write(f"[BridgeServer] Agent '{agent_id}' authenticated from {addr}\n")
            sys.stderr.flush()
            sock.settimeout(None)
            while self.running and session.alive:
                try:
                    frame = self._recv_frame(sock)
                except (ConnectionError, ValueError, OSError):
                    break
                body_b64 = frame.get('body_b64') if isinstance(frame, dict) and frame.get('v') == 4 else None
                mac = frame.get('mac') if isinstance(frame, dict) else None
                if not isinstance(body_b64, str) or not _is_hex(mac, 64) or not hmac.compare_digest(
                        hmac.new(sesskey, body_b64.encode('ascii'), hashlib.sha256).hexdigest(), mac):
                    sys.stderr.write(f"[BridgeServer] Agent '{agent_id}': bad session MAC, dropping\n")
                    sys.stderr.flush()
                    break
                try:
                    data = json.loads(base64.b64decode(body_b64, validate=True).decode('utf-8'))
                except (ValueError, UnicodeDecodeError):
                    break
                if not isinstance(data, dict):
                    break
                session.last_seen = time.time()
                req_id = data.get('id')
                if req_id in session.pending_requests:
                    session.pending_responses[req_id] = data
                    session.pending_requests[req_id].set()
                # Unknown agent notifications are ignored (extensible, fail-closed).
        except (ConnectionError, ValueError, OSError, KeyError):
            pass
        except Exception as e:
            sys.stderr.write(f"[BridgeServer] Agent handler error: {e}\n")
            sys.stderr.flush()
        finally:
            if session is not None:
                self._unregister(session)
            try:
                sock.close()
            except OSError:
                pass

    def _takeover_stale(self, agent_id: str) -> bool:
        """Steal a ghost slot: same agent_id, silent for TAKEOVER_AFTER_S.

        A crashed agent can leave its TCP half-open (alive, frozen last_seen),
        rejecting the replacement handshake forever. Only a silent slot is
        stolen; a live duplicate is still rejected below.
        """
        with self.lock:
            old = self.agents.get(agent_id)
            if old is None or not old.alive:
                return False
            if time.time() - old.last_seen < TAKEOVER_AFTER_S:
                return False
            old.alive = False
            try:
                old.sock.close()
            except OSError:
                pass
            if self.agents.get(agent_id) is old:
                del self.agents[agent_id]
        sys.stderr.write(f"[BridgeServer] Agent '{agent_id}' took over a stale session\n")
        sys.stderr.flush()
        return True

    def _unregister(self, session: _AgentSession):
        session.alive = False
        with self.lock:
            if self.agents.get(session.agent_id) is session:
                del self.agents[session.agent_id]
            if not self.agents:
                self.connected_event.clear()
        for req_id, event in list(session.pending_requests.items()):
            session.pending_responses.setdefault(req_id, {'error': {'code': -32002, 'message': f"Agent '{session.agent_id}' disconnected"}})
            event.set()

    def _resolve(self, agent_id: Optional[str]) -> Any:
        """Returns the live session or an {"error": ...} dict. Never guesses across agents."""
        with self.lock:
            live = {k: s for k, s in self.agents.items() if s.alive}
        if agent_id is not None:
            sess = live.get(agent_id) if isinstance(agent_id, str) else None
            if sess is None:
                known = sorted(live)
                return {"error": {"code": -32003, "message": f"Unknown agent '{agent_id}'. Connected: {known if known else 'none'}"}}
            return sess
        if not live:
            return {"error": {"code": -32001, "message": "No remote agent currently connected. Please start agent.exe on the target machine."}}
        if len(live) > 1:
            return {"error": {"code": -32004, "message": f"Ambiguous: {len(live)} agents connected, specify one of {sorted(live)}"}}
        return next(iter(live.values()))

    def list_agents(self) -> List[Dict[str, Any]]:
        with self.lock:
            return [{'agent_id': s.agent_id, 'addr': f'{s.addr[0]}:{s.addr[1]}' if s.addr else 'unknown',
                     'version': s.info.get('version'), 'arch': s.info.get('arch'), 'os': s.info.get('os'),
                     'pid': s.info.get('pid'),
                     'connected_at': s.connected_at, 'last_seen': s.last_seen} for s in self.agents.values() if s.alive]

    def remove_agent(self, agent_id: str) -> bool:
        with self.lock:
            sess = self.agents.get(agent_id)
        if sess is None:
            return False
        sess.alive = False
        try:
            sess.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sess.sock.close()
        except OSError:
            pass
        return True

    def send_rpc(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: float = 60.0,
                 agent_id: Optional[str] = None) -> Dict[str, Any]:
        target = agent_id if agent_id is not None else _agent_ctx.get()
        sess = self._resolve(target)
        if isinstance(sess, dict):
            return sess
        if len(sess.pending_requests) >= MAX_PENDING_PER_AGENT:
            return {"error": {"code": -32005, "message": f"Too many in-flight requests on agent '{sess.agent_id}'"}}

        with sess.send_lock:
            req_id = sess.next_req_id
            sess.next_req_id += 1
            event = threading.Event()
            sess.pending_requests[req_id] = event

        req_obj = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method
        }
        if params is not None:
            for k, v in params.items():
                req_obj[k] = v
            req_obj["params"] = params

        inner = json.dumps(req_obj, sort_keys=True, separators=(',', ':')).encode('utf-8')
        body_b64 = base64.b64encode(inner).decode('ascii')
        envelope = {'v': 4, 'body_b64': body_b64,
                    'mac': hmac.new(sess.sesskey, body_b64.encode('ascii'), hashlib.sha256).hexdigest()}
        with sess.send_lock:
            try:
                self._send_frame(sess.sock, envelope)
            except Exception as e:
                sess.pending_requests.pop(req_id, None)
                return {"error": {"code": -32002, "message": f"Socket send error: {e}"}}

        signaled = event.wait(timeout)
        sess.pending_requests.pop(req_id, None)
        response = sess.pending_responses.pop(req_id, None)

        if not signaled or response is None:
            return {"error": {"code": -32008, "message": f"Operation timed out after {timeout}s"}}

        return response


# Initialize global bridge
bridge = RemoteAgentBridge()

# =========================================================================
# MCP PROTOCOL DEFINITIONS & SCHEMAS
# =========================================================================

MCP_TOOLS = [
    {
        "name": "remote_status",
        "description": "Check connection status to the remote Windows 10 machine, IP, uptime, RTT latency, and agent details. If disconnected, outputs local LAN IPs and deployment commands.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_network_helper",
        "description": "Get all detected local IPv4 addresses (Wi-Fi/Ethernet) and exact copy-paste command strings to launch agent.exe on the remote PC 2.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_telemetry",
        "description": "Query real-time hardware telemetry from PC 2: CPU load %, RAM available/total, Process Disk I/O bytes/sec, and network round-trip latency.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_telemetry_history",
        "description": "Retrieve 1-hour rolling telemetry history (60 samples, zero-disk-I/O in-memory ring buffer) from PC 2: CPU %, free RAM MB, GPU diode temp deg C.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_drift_status",
        "description": "Query Autonomous Drift Sentinel (SWARM-140) status on PC2: OLS linear regression slope, R2, monotonicity, memory leak state, and thermal guard state.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_kiosk_status",
        "description": "Query Autonomous Kiosk Sentinel (SWARM-150) status on PC2: detects if Supermium/MPV window is hung or crashed, restart counts, circuit breaker state, and current backoff.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_kiosk_restart",
        "description": "Force an immediate termination and relaunch of the kiosk presentation layer (Supermium / MPV) on PC2.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "force": {"type": "boolean", "default": True, "description": "Unconditionally terminate and relaunch kiosk"},
                "target": {"type": "string", "default": "", "description": "Optional target executable name"}
            },
            "required": []
        }
    },
    {
        "name": "remote_kiosk_configure",
        "description": "Configure Autonomous Kiosk Sentinel parameters on PC2 (enable/disable, auto-relaunch on crash, target executable name).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True, "description": "Enable or disable autonomous kiosk watchdog"},
                "auto_relaunch_on_crash": {"type": "boolean", "default": False, "description": "Automatically relaunch if process exits cleanly"},
                "target": {"type": "string", "default": "chrome.exe", "description": "Target executable name to monitor"}
            },
            "required": []
        }
    },
    {
        "name": "remote_get_logs",
        "description": "Retrieve recent structured execution logs from the circular log ring in agent memory on PC 2.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "since_seq": {"type": "integer", "default": 0, "description": "Only retrieve log entries with sequence ID strictly greater than this value"},
                "min_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARN", "ERROR"], "default": "INFO", "description": "Minimum log level to return"},
                "clear": {"type": "boolean", "default": False, "description": "Clear the log ring after retrieval"}
            },
            "required": []
        }
    },
    {
        "name": "remote_run_command",
        "description": "Execute a shell command or script on the remote machine (cmd, powershell, or direct executable). Captures separate stdout and stderr, exit code, and execution duration.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Command line to execute"},
                "shell": {"type": "string", "enum": ["cmd", "powershell", "direct"], "default": "cmd", "description": "Shell interpreter to use"},
                "cwd": {"type": "string", "description": "Working directory on the remote machine (optional)"},
                "timeout_ms": {"type": "integer", "default": 60000, "description": "Execution timeout in milliseconds"}
            },
            "required": ["command"]
        }
    },
    {
        "name": "remote_view_file",
        "description": "View the contents of a file on the remote machine (text or binary). Supports offset and length for chunked reading.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute remote file path (e.g. C:\\Users\\User\\file.txt)"},
                "offset": {"type": "integer", "default": 0, "description": "Byte offset to start reading"},
                "length": {"type": "integer", "default": 131072, "description": "Max bytes to read (default 128 KB)"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "remote_write_file",
        "description": "Write or overwrite content to a file on the remote machine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute remote file path"},
                "content": {"type": "string", "description": "Text content to write"},
                "append": {"type": "boolean", "default": False, "description": "Append to file instead of overwriting"}
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "remote_replace_file_content",
        "description": "Atomically search and replace a substring inside a remote file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute remote file path"},
                "target": {"type": "string", "description": "Exact text to search for"},
                "replacement": {"type": "string", "description": "Replacement text"},
                "replace_all": {"type": "boolean", "default": False, "description": "Replace all occurrences instead of only the first"}
            },
            "required": ["path", "target", "replacement"]
        }
    },
    {
        "name": "remote_list_directory",
        "description": "List files and subdirectories in a directory on the remote machine with sizes and directory flags.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory path on remote machine (e.g. C:\\)"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "remote_delete_file",
        "description": "Delete a file or recursively delete a directory on the remote machine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file or folder to delete"}
            },
            "required": ["path"]
        }
    },
    {
        "name": "remote_upload_file",
        "description": "Upload a file from the local master PC to the remote PC with block-level SHA-256 verification and remote integrity check.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "local_path": {"type": "string", "description": "Path to file on master PC"},
                "remote_path": {"type": "string", "description": "Target path on remote PC"}
            },
            "required": ["local_path", "remote_path"]
        }
    },
    {
        "name": "remote_download_file",
        "description": "Download a file from the remote PC to the local master PC with block-level and full SHA-256 integrity verification.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "remote_path": {"type": "string", "description": "Source path on remote PC"},
                "local_path": {"type": "string", "description": "Target path on master PC"}
            },
            "required": ["remote_path", "local_path"]
        }
    },
    {
        "name": "remote_sync_directory",
        "description": "Bidirectionally synchronize an entire directory between Master PC and Remote PC 2. Uses SHA-256 comparison and only transfers missing or modified files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "local_path": {"type": "string", "description": "Local directory path on Master PC"},
                "remote_path": {"type": "string", "description": "Remote directory path on PC 2"},
                "mode": {"type": "string", "enum": ["push", "pull"], "default": "push", "description": "'push' syncs Master -> PC 2; 'pull' syncs PC 2 -> Master"},
                "dry_run": {"type": "boolean", "default": False, "description": "If true, only report differences without transferring files"}
            },
            "required": ["local_path", "remote_path"]
        }
    },
    {
        "name": "remote_update_agent",
        "description": "Push a newly compiled agent.exe binary to the remote PC and hot-swap it atomically using side-by-side selftest validation, MoveFileExW rename, and watchdog rollback.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_binary_path": {"type": "string", "description": "Local path to the new agent binary (default: auto-picked from agents/ by target OS+arch)"},
                "timeout_seconds": {"type": "number", "default": 20.0, "description": "Seconds to wait for upgraded agent to reconnect"}
            },
            "required": []
        }
    },
    {
        "name": "remote_sysinfo",
        "description": "Get detailed hardware and OS diagnostic information from the remote machine (RAM, CPU cores, CPU load %, disks, agent memory consumption, uptime).",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_process_list",
        "description": "Get a list of all running processes on the remote PC with PID, Parent PID, and Working Set RAM.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_process_kill",
        "description": "Terminate a process (and optionally its process tree) on the remote machine by its PID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID to terminate"},
                "kill_tree": {"type": "boolean", "default": True, "description": "Recursively kill child processes"}
            },
            "required": ["pid"]
        }
    },
    {
        "name": "remote_process_priority",
        "description": "Change process CPU priority on the remote machine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID"},
                "priority": {"type": "string", "enum": ["idle", "below_normal", "normal", "above_normal", "high", "realtime"], "description": "Target priority class"}
            },
            "required": ["pid", "priority"]
        }
    },
    {
        "name": "remote_registry_read",
        "description": "Read a Windows registry key/value on the remote machine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hive": {"type": "string", "enum": ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"], "default": "HKLM"},
                "subkey": {"type": "string", "description": "Registry subkey path"},
                "value_name": {"type": "string", "description": "Value name (empty for default value)"}
            },
            "required": ["subkey"]
        }
    },
    {
        "name": "remote_registry_write",
        "description": "Create or write a registry key/value on the remote machine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hive": {"type": "string", "enum": ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"], "default": "HKLM"},
                "subkey": {"type": "string", "description": "Registry subkey path"},
                "value_name": {"type": "string", "description": "Value name"},
                "reg_type": {"type": "string", "enum": ["REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD"], "default": "REG_SZ"},
                "value_str": {"type": "string", "description": "String value content"},
                "value_int": {"type": "integer", "description": "Integer value (for REG_DWORD/REG_QWORD)"}
            },
            "required": ["subkey", "value_name", "reg_type"]
        }
    },
    {
        "name": "remote_registry_delete",
        "description": "Delete a registry value or an entire subkey on the remote machine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hive": {"type": "string", "enum": ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"], "default": "HKLM"},
                "subkey": {"type": "string", "description": "Registry subkey path"},
                "value_name": {"type": "string", "description": "Value name to delete"},
                "delete_key": {"type": "boolean", "default": False, "description": "Delete the whole subkey instead of just a value"}
            },
            "required": ["subkey"]
        }
    },
    {
        "name": "remote_service_control",
        "description": "Control a Windows Service on the remote machine (start, stop, set startup type).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {"type": "string", "description": "Service name (e.g. SysMain, WSearch, DiagTrack)"},
                "action": {"type": "string", "enum": ["start", "stop", "set_start_type"], "description": "Action to perform"},
                "start_type": {"type": "string", "enum": ["auto", "manual", "disabled"], "description": "Startup type (required if action is set_start_type)"}
            },
            "required": ["service_name", "action"]
        }
    },
    {
        "name": "remote_screenshot",
        "description": "Capture the primary screen of the remote machine, saves it locally as a BMP file, and returns width, height, and file path.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "save_path": {"type": "string", "description": "Local path to save the screenshot (defaults to ./remote_screenshot.bmp)"}
            },
            "required": []
        }
    },
    {
        "name": "remote_input",
        "description": "Inject keyboard or mouse events into the remote machine's active session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_type": {"type": "string", "enum": ["mouse_move", "mouse_click", "key_vk", "text"], "description": "Type of input event"},
                "x": {"type": "integer", "description": "Screen X coordinate for mouse"},
                "y": {"type": "integer", "description": "Screen Y coordinate for mouse"},
                "button": {"type": "string", "enum": ["left", "right"], "default": "left", "description": "Mouse button"},
                "vk": {"type": "integer", "description": "Virtual key code for key_vk"},
                "text": {"type": "string", "description": "Text to type for text input_type"}
            },
            "required": ["input_type"]
        }
    },
    {
        "name": "remote_optimize_apply",
        "description": "Apply selected Windows 10 x86 optimizations on the remote machine (disables telemetry, stops heavy background services, tunes visual effects for best performance, cleans temp files).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "disable_telemetry": {"type": "boolean", "default": True, "description": "Disable Windows Customer Experience & telemetry services"},
                "disable_unneeded_services": {"type": "boolean", "default": True, "description": "Disable non-essential heavy services (SysMain, WSearch, MapsBroker, Xbox services)"},
                "optimize_visual_effects": {"type": "boolean", "default": True, "description": "Tune Explorer visual effects for Best Performance"},
                "cleanup_disk": {"type": "boolean", "default": True, "description": "Clean %TEMP% directory"}
            },
            "required": []
        }
    },
    {
        "name": "remote_find_file",
        "description": "Ultra-fast native Win32 recursive file search across remote directories. Bypasses PowerShell and CMD; avoids timeouts and heavy disk churn on 5400 RPM HDDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "root": {"type": "string", "default": "C:\\", "description": "Root directory to start searching from"},
                "pattern": {"type": "string", "default": "*", "description": "File search pattern (e.g. mpv.exe, *jellyfin*, *.conf)"},
                "max_depth": {"type": "integer", "default": 6, "description": "Maximum directory recursion depth"},
                "max_results": {"type": "integer", "default": 50, "description": "Maximum number of matching file paths to return"}
            },
            "required": []
        }
    },
    {
        "name": "remote_sysinfo",
        "description": "Instant native Win32 hardware and OS diagnostic information (CPU brand/cores, total/available RAM, C: drive space, AC/battery status, system uptime). Zero subprocess overhead.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "remote_trim_memory",
        "description": "Force immediate working set memory compaction on the remote agent and query available system RAM.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]

# =========================================================================
# TOOL EXECUTION LOGIC
# =========================================================================

def handle_tool_call(tool_name: str, args: Dict[str, Any], agent_id: Optional[str] = None) -> str:
    # None inherits the outer context (nested tool calls keep their target);
    # an explicit agent always wins. Top level with 2+ agents and no agent
    # still resolves to ambiguity via _resolve(None) in send paths.
    token = _agent_ctx.set(agent_id if agent_id is not None else _agent_ctx.get())
    try:
        return _dispatch_tool_call(tool_name, args)
    finally:
        _agent_ctx.reset(token)


def _dispatch_tool_call(tool_name: str, args: Dict[str, Any]) -> str:
    if tool_name == "remote_status":
        lan_ips = get_master_lan_ips()
        primary_ip = lan_ips[0] if lan_ips else "127.0.0.1"
        agents = bridge.list_agents()
        target = _agent_ctx.get()

        if target is not None or len(agents) == 1:
            wanted = target or (agents[0]['agent_id'] if agents else None)
            known = [a['agent_id'] for a in agents]
            if wanted is None or wanted not in known:
                return json.dumps({
                    "status": "disconnected",
                    "message": f"No connected agent '{wanted}'." if wanted else "No remote agent currently connected.",
                    "connected_agents": known,
                    "master_listening_on": f"{bridge.host}:{bridge.port}"
                }, indent=2)
            info = next(a for a in agents if a['agent_id'] == wanted)
            # Measure RTT ping latency
            t0 = time.time()
            ping_res = bridge.send_rpc("sys.ping", timeout=3.0, agent_id=wanted)
            latency_ms = round((time.time() - t0) * 1000.0, 2)
            pong = ping_res.get("result", {})

            return json.dumps({
                "status": "connected",
                "agent_id": wanted,
                "remote_ip": info['addr'].rsplit(':', 1)[0] if ':' in info['addr'] else info['addr'],
                "agent_version": pong.get("version", info.get("version", "unknown")),
                "round_trip_latency_ms": latency_ms,
                "master_listening_on": f"{bridge.host}:{bridge.port}",
                "master_lan_ips": lan_ips,
                "agent_pid": info.get("pid"),
                "agent_uptime_ms": pong.get("uptime_ms", 0),
                "connected_agents": known
            }, indent=2)
        elif not agents:
            return json.dumps({
                "status": "disconnected",
                "message": "No remote agent currently connected.",
                "master_listening_on": f"{bridge.host}:{bridge.port}",
                "detected_master_lan_ips": lan_ips,
                "launch_command_powershell": f"Start-Process .\\agent.exe -ArgumentList '--host {primary_ip} --port {bridge.port} --token <YOUR_PSK> --agent-id <PC_NAME>'",
                "launch_command_cmd": f"agent.exe --host {primary_ip} --port {bridge.port} --token <YOUR_PSK> --agent-id <PC_NAME>",
                "psk_note": "Use the PSK configured on this master (--token / OPENBRIDGE_PSK). It is never printed."
            }, indent=2)
        else:
            return json.dumps({
                "status": "connected",
                "count": len(agents),
                "agents": agents,
                "master_listening_on": f"{bridge.host}:{bridge.port}",
                "master_lan_ips": lan_ips,
                "note": "Pass agent=<agent_id> to target one PC."
            }, indent=2)

    elif tool_name == "remote_network_helper":
        lan_ips = get_master_lan_ips()
        primary = lan_ips[0] if lan_ips else "127.0.0.1"
        return json.dumps({
            "detected_lan_ips": lan_ips,
            "primary_ip": primary,
            "port": bridge.port,
            "connected_agents": [a['agent_id'] for a in bridge.list_agents()],
            "agent_command_powershell": f"Start-Process .\\agent.exe -ArgumentList '--host {primary} --port {bridge.port} --token <YOUR_PSK> --agent-id <PC_NAME>'",
            "agent_command_cmd": f"agent.exe --host {primary} --port {bridge.port} --token <YOUR_PSK> --agent-id <PC_NAME>",
            "psk_note": "Replace <YOUR_PSK> with the PSK configured on this master (--token / OPENBRIDGE_PSK). It is never printed.",
            "instructions": "Run this command on each remote Windows PC in PowerShell or CMD inside the folder containing agent.exe. Give each PC a unique --agent-id."
        }, indent=2)

    elif tool_name == "remote_telemetry":
        t0 = time.time()
        res = bridge.send_rpc("sys.diag", {}, timeout=5.0)
        rtt_ms = round((time.time() - t0) * 1000.0, 2)
        if "result" in res:
            r = res["result"]
            r["round_trip_ms"] = rtt_ms
            # Format human-friendly memory
            total_ram = r.get("ram_total_bytes", 0)
            avail_ram = r.get("ram_avail_bytes", 0)
            if total_ram > 0:
                used_ram = total_ram - avail_ram
                r["ram_used_percent"] = round((used_ram * 100.0) / total_ram, 1)
                r["ram_avail_mb"] = round(avail_ram / (1024 * 1024), 1)
                r["ram_total_mb"] = round(total_ram / (1024 * 1024), 1)
            # Format working set
            ws = r.get("agent_working_set_bytes", 0)
            r["agent_working_set_mb"] = round(ws / (1024 * 1024), 2)
            # Format IO
            r["io_read_kb_sec"] = round(r.get("io_read_bytes_sec", 0) / 1024.0, 1)
            r["io_write_kb_sec"] = round(r.get("io_write_bytes_sec", 0) / 1024.0, 1)
            return json.dumps(r, indent=2)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_telemetry_history":
        res = bridge.send_rpc("sys.telemetry_history", {}, timeout=5.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_drift_status":
        res = bridge.send_rpc("sys.drift_status", {}, timeout=5.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_kiosk_status":
        res = bridge.send_rpc("kiosk.status", {}, timeout=5.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_kiosk_restart":
        res = bridge.send_rpc("kiosk.restart", {
            "force": args.get("force", True),
            "target": args.get("target", "")
        }, timeout=10.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_kiosk_configure":
        res = bridge.send_rpc("kiosk.configure", args, timeout=5.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_get_logs":
        res = bridge.send_rpc("log.get", {
            "since_seq": args.get("since_seq", 0),
            "min_level": args.get("min_level", "INFO"),
            "clear": args.get("clear", False)
        })
        if "result" in res:
            logs = res["result"].get("logs", [])
            return json.dumps({
                "count": len(logs),
                "logs": logs
            }, indent=2)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_run_command":
        t_sec = args.get("timeout_seconds", args.get("timeout_sec", 120))
        t_ms = args.get("timeout_ms", int(t_sec * 1000))
        args["timeout_ms"] = t_ms
        args["timeout_seconds"] = int(t_ms / 1000)
        res = bridge.send_rpc("exec.run", args, timeout=(t_ms / 1000.0 + 10))
        if "result" in res:
            r = res["result"]
            stdout_text = ""
            stderr_text = ""
            if r.get("stdout_b64"):
                try:
                    stdout_text = base64.b64decode(r["stdout_b64"]).decode("utf-8", errors="replace")
                except Exception:
                    pass
            if r.get("stderr_b64"):
                try:
                    stderr_text = base64.b64decode(r["stderr_b64"]).decode("utf-8", errors="replace")
                except Exception:
                    pass
            return json.dumps({
                "pid": r.get("pid"),
                "exit_code": r.get("exit_code"),
                "timed_out": r.get("timed_out"),
                "stdout": stdout_text,
                "stderr": stderr_text
            }, indent=2)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_view_file":
        res = bridge.send_rpc("fs.read", args)
        if "result" in res:
            r = res["result"]
            raw = base64.b64decode(r.get("data_b64", ""))
            text = raw.decode("utf-8", errors="replace")
            return json.dumps({
                "path": args.get("path"),
                "bytes_read": r.get("bytes_read"),
                "total_size": r.get("total_size"),
                "eof": r.get("eof"),
                "chunk_sha256": r.get("chunk_sha256"),
                "content": text
            }, indent=2)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_write_file":
        content_bytes = args.get("content", "").encode("utf-8")
        data_b64 = base64.b64encode(content_bytes).decode("ascii")
        rpc_args = {
            "path": args.get("path"),
            "data_b64": data_b64,
            "offset": 0,
            "truncate": not args.get("append", False),
            "finalize_hash": True
        }
        res = bridge.send_rpc("fs.write", rpc_args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_replace_file_content":
        path = args.get("path") or args.get("TargetFile") or args.get("file_path")
        target_str = args.get("target") or args.get("TargetContent") or args.get("search") or ""
        repl_str = args.get("replacement") or args.get("ReplacementContent") or args.get("replace") or ""
        search_bytes = target_str.encode("utf-8")
        repl_bytes = repl_str.encode("utf-8")
        rpc_args = {
            "path": path,
            "search_b64": base64.b64encode(search_bytes).decode("ascii"),
            "replace_b64": base64.b64encode(repl_bytes).decode("ascii"),
            "replace_all": args.get("replace_all") or args.get("AllowMultiple", False)
        }
        res = bridge.send_rpc("fs.patch", rpc_args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_list_directory":
        res = bridge.send_rpc("fs.list", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_find_file":
        rpc_args = {
            "root": args.get("root", "C:\\"),
            "pattern": args.get("pattern", "*"),
            "max_depth": args.get("max_depth", 6),
            "max_results": args.get("max_results", 50)
        }
        res = bridge.send_rpc("fs.find", rpc_args, timeout=30.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_delete_file":
        res = bridge.send_rpc("fs.delete", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_upload_file":
        local_p = args.get("local_path")
        remote_p = args.get("remote_path")
        if not local_p or not os.path.isfile(local_p):
            return json.dumps({"error": f"Local file not found: {local_p}"})

        file_size = os.path.getsize(local_p)
        full_sha = hashlib.sha256()
        offset = 0

        with open(local_p, "rb") as f:
            while offset < file_size:
                chunk = f.read(MAX_CHUNK_SIZE)
                if not chunk:
                    break
                full_sha.update(chunk)
                chunk_expected_sha = hashlib.sha256(chunk).hexdigest()
                b64 = base64.b64encode(chunk).decode("ascii")
                is_last = (offset + len(chunk) >= file_size)

                # Retry loop per chunk
                chunk_ok = False
                for attempt in range(MAX_CHUNK_RETRIES):
                    res = bridge.send_rpc("fs.write", {
                        "path": remote_p,
                        "data_b64": b64,
                        "offset": offset,
                        "truncate": (offset == 0),
                        "finalize_hash": is_last
                    })
                    if "error" not in res:
                        returned_sha = res.get("result", {}).get("chunk_sha256", "")
                        if returned_sha.lower() == chunk_expected_sha.lower():
                            chunk_ok = True
                            break
                        sys.stderr.write(f"[Upload] Chunk SHA mismatch at offset {offset}, retrying ({attempt+1}/{MAX_CHUNK_RETRIES})...\n")
                    time.sleep(0.1)

                if not chunk_ok:
                    return json.dumps({"error": f"Chunk upload failed at offset {offset} after {MAX_CHUNK_RETRIES} attempts."})

                offset += len(chunk)

        # Final end-to-end verification via remote fs.hash
        hash_res = bridge.send_rpc("fs.hash", {"path": remote_p})
        if "error" in hash_res:
            return json.dumps({"error": f"Remote hash verification failed: {hash_res['error']}"})

        remote_sha = hash_res.get("result", {}).get("sha256", "")
        expected_sha = full_sha.hexdigest()
        if remote_sha.lower() != expected_sha.lower():
            return json.dumps({
                "error": f"File integrity check failed! Local SHA={expected_sha}, Remote SHA={remote_sha}"
            })

        return json.dumps({
            "uploaded": True,
            "local_path": local_p,
            "remote_path": remote_p,
            "bytes_uploaded": file_size,
            "sha256": expected_sha,
            "integrity_verified": True
        }, indent=2)

    elif tool_name == "remote_download_file":
        remote_p = args.get("remote_path")
        local_p = args.get("local_path")
        if not remote_p or not local_p:
            return json.dumps({"error": "Missing remote_path or local_path"})

        # First query remote file size and sha256
        hash_res = bridge.send_rpc("fs.hash", {"path": remote_p})
        if "error" in hash_res:
            return json.dumps({"error": f"Remote file not found or inaccessible: {hash_res['error']}"})
        remote_expected_sha = hash_res.get("result", {}).get("sha256", "")
        total_size = hash_res.get("result", {}).get("size", 0)

        offset = 0
        local_sha = hashlib.sha256()

        os.makedirs(os.path.dirname(os.path.abspath(local_p)), exist_ok=True)
        with open(local_p, "wb") as f:
            while offset < total_size or total_size == 0:
                res = bridge.send_rpc("fs.read", {
                    "path": remote_p,
                    "offset": offset,
                    "length": MAX_CHUNK_SIZE
                })
                if "error" in res:
                    return json.dumps({"error": f"Download failed at offset {offset}: {res['error']}"})
                r = res.get("result", {})
                b64 = r.get("data_b64", "")
                chunk = base64.b64decode(b64)
                if not chunk and total_size > 0:
                    break
                f.write(chunk)
                local_sha.update(chunk)
                offset += len(chunk)
                if r.get("eof", False) or len(chunk) == 0:
                    break

        actual_local_sha = local_sha.hexdigest()
        if actual_local_sha.lower() != remote_expected_sha.lower():
            return json.dumps({
                "error": f"Download SHA-256 verification mismatch! Expected {remote_expected_sha}, Got {actual_local_sha}"
            })

        return json.dumps({
            "downloaded": True,
            "remote_path": remote_p,
            "local_path": local_p,
            "bytes_downloaded": offset,
            "sha256": actual_local_sha,
            "integrity_verified": True
        }, indent=2)

    elif tool_name == "remote_sync_directory":
        local_p = os.path.abspath(args.get("local_path", ""))
        remote_p = args.get("remote_path", "")
        mode = args.get("mode", "push")
        dry_run = args.get("dry_run", False)

        if not os.path.isdir(local_p) and mode == "push":
            return json.dumps({"error": f"Local directory not found: {local_p}"})

        files_checked = 0
        files_transferred = 0
        bytes_transferred = 0
        synced_items = []

        t_start = time.time()

        if mode == "push":
            for root, _, files in os.walk(local_p):
                rel_dir = os.path.relpath(root, local_p)
                target_remote_dir = remote_p if rel_dir == "." else os.path.join(remote_p, rel_dir).replace("/", "\\")
                # Ensure remote dir exists
                bridge.send_rpc("fs.mkdir", {"path": target_remote_dir})

                for fname in files:
                    files_checked += 1
                    loc_f = os.path.join(root, fname)
                    rem_f = os.path.join(target_remote_dir, fname).replace("/", "\\")

                    loc_size = os.path.getsize(loc_f)
                    loc_sha = compute_sha256(loc_f)

                    # Check remote file
                    r_hash = bridge.send_rpc("fs.hash", {"path": rem_f})
                    rem_sha = r_hash.get("result", {}).get("sha256", "") if "result" in r_hash else ""

                    if rem_sha.lower() != loc_sha.lower():
                        if not dry_run:
                            up_res = handle_tool_call("remote_upload_file", {"local_path": loc_f, "remote_path": rem_f})
                            up_data = json.loads(up_res)
                            if "error" in up_data:
                                return json.dumps({"error": f"Failed syncing {loc_f}: {up_data['error']}"})
                        files_transferred += 1
                        bytes_transferred += loc_size
                        synced_items.append({"file": rel_dir + "\\" + fname, "size": loc_size, "action": "pushed"})

        elif mode == "pull":
            # List remote files recursively
            dirs_to_visit = [remote_p]
            while dirs_to_visit:
                curr_rem_dir = dirs_to_visit.pop(0)
                rel_dir = os.path.relpath(curr_rem_dir, remote_p)
                target_loc_dir = local_p if rel_dir == "." else os.path.join(local_p, rel_dir)
                os.makedirs(target_loc_dir, exist_ok=True)

                lres = bridge.send_rpc("fs.list", {"path": curr_rem_dir})
                entries = lres.get("result", {}).get("entries", [])
                for ent in entries:
                    ename = ent.get("name")
                    is_dir = ent.get("is_dir", False)
                    sub_rem = os.path.join(curr_rem_dir, ename).replace("/", "\\")
                    sub_loc = os.path.join(target_loc_dir, ename)

                    if is_dir:
                        dirs_to_visit.append(sub_rem)
                    else:
                        files_checked += 1
                        r_sha = bridge.send_rpc("fs.hash", {"path": sub_rem}).get("result", {}).get("sha256", "")
                        l_sha = compute_sha256(sub_loc) if os.path.isfile(sub_loc) else ""

                        if r_sha.lower() != l_sha.lower():
                            if not dry_run:
                                dn_res = handle_tool_call("remote_download_file", {"remote_path": sub_rem, "local_path": sub_loc})
                                dn_data = json.loads(dn_res)
                                if "error" in dn_data:
                                    return json.dumps({"error": f"Failed downloading {sub_rem}: {dn_data['error']}"})
                            files_transferred += 1
                            bytes_transferred += ent.get("size", 0)
                            synced_items.append({"file": ename, "size": ent.get("size", 0), "action": "pulled"})

        duration_sec = round(time.time() - t_start, 2)
        return json.dumps({
            "mode": mode,
            "dry_run": dry_run,
            "files_checked": files_checked,
            "files_transferred": files_transferred,
            "bytes_transferred": bytes_transferred,
            "duration_seconds": duration_sec,
            "items": synced_items
        }, indent=2)

    elif tool_name == "remote_update_agent":
        # Resolve the target first: explicit agent, or single connected agent.
        # Ambiguous multi-agent calls fail here (explicit routing, never broadcast).
        _upd_sess = bridge._resolve(_agent_ctx.get())
        if isinstance(_upd_sess, dict):
            return json.dumps({"error": f"remote_update_agent: no target ({_upd_sess.get('error')})"})
        _here = os.path.dirname(os.path.abspath(__file__))
        _t_os = (_upd_sess.info.get('os') or 'windows').lower()
        _t_arch = (_upd_sess.info.get('arch') or ('x64' if _t_os == 'linux' else 'x86')).lower()
        _AGENT_FILES = {
            ('windows', 'x86'): 'agent-win-x86.exe',
            ('windows', 'x64'): 'agent-win-x64.exe',
            ('windows', 'arm64'): 'agent-win-arm64.exe',
            ('linux', 'x64'): 'agent-linux-x64',
            ('linux', 'arm64'): 'agent-linux-arm64',
        }
        binary_p = args.get("agent_binary_path")
        if not binary_p:
            _fname = _AGENT_FILES.get((_t_os, _t_arch))
            if _fname is None:
                return json.dumps({"error": (
                    f"No agent build for os={_t_os} arch={_t_arch} "
                    f"(target '{_upd_sess.agent_id}'); pass agent_binary_path explicitly")})
            binary_p = os.path.join(_here, 'agents', _fname)
        timeout_sec = float(args.get("timeout_seconds", 20.0))

        if not os.path.isfile(binary_p):
            return json.dumps({"error": f"Agent binary not found: {binary_p}"})
        sys.stderr.write(f"[Update] Target '{_upd_sess.agent_id}' ({_t_os}/{_t_arch}) <- {binary_p}\n")

        # Calculate binary SHA-256
        binary_sha = compute_sha256(binary_p)

        # 1. Upload new binary to staging path
        remote_staging = "agent_new.exe"
        sys.stderr.write(f"[Update] Staging new agent binary to {remote_staging} (SHA: {binary_sha})...\n")
        up_res = handle_tool_call("remote_upload_file", {
            "local_path": binary_p,
            "remote_path": remote_staging
        })
        up_data = json.loads(up_res)
        if "error" in up_data:
            return json.dumps({"error": f"Failed uploading staging binary: {up_data['error']}"})

        # 2. Trigger RPC agent.update
        sys.stderr.write("[Update] Calling agent.update RPC...\n")
        bridge.connected_event.clear()
        res = bridge.send_rpc("agent.update", {
            "staging_path": remote_staging,
            "expected_sha256": binary_sha
        }, timeout=8.0)

        if "error" in res:
            return json.dumps({"error": f"Agent update rejected by remote host: {res['error']}"})

        update_info = res.get("result", {})
        old_pid = bridge.agent_info.get("pid")
        new_pid = update_info.get("new_pid")

        # 3. Wait for new agent to reconnect via reverse TCP
        sys.stderr.write(f"[Update] Waiting up to {timeout_sec}s for upgraded agent to reconnect...\n")
        reconnected = bridge.connected_event.wait(timeout_sec)

        if not reconnected:
            return json.dumps({
                "updated": True,
                "reconnected": False,
                "message": "Update triggered successfully, but upgraded agent has not reconnected yet within timeout window.",
                "old_pid": old_pid,
                "new_pid": new_pid,
                "sha256": binary_sha
            }, indent=2)

        # 4. Verify new connection with ping
        ping = bridge.send_rpc("sys.ping", timeout=3.0)
        pong = ping.get("result", {})

        return json.dumps({
            "updated": True,
            "reconnected": True,
            "old_pid": old_pid,
            "new_pid": new_pid,
            "sha256": binary_sha,
            "agent_version": pong.get("version"),
            "agent_uptime_ms": pong.get("uptime_ms"),
            "message": "Agent upgraded and seamlessly reconnected!"
        }, indent=2)

    elif tool_name == "remote_sysinfo":
        res = bridge.send_rpc("sys.diag", {})
        return json.dumps(res, indent=2)

    elif tool_name == "remote_process_list":
        res = bridge.send_rpc("proc.list", {})
        return json.dumps(res, indent=2)

    elif tool_name == "remote_process_kill":
        res = bridge.send_rpc("proc.kill", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_process_priority":
        res = bridge.send_rpc("proc.priority", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_registry_read":
        res = bridge.send_rpc("reg.read", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_registry_write":
        res = bridge.send_rpc("reg.write", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_registry_delete":
        res = bridge.send_rpc("reg.delete", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_service_control":
        res = bridge.send_rpc("svc.op", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_screenshot":
        res = bridge.send_rpc("gui.screenshot", {}, timeout=15.0)
        if "result" in res:
            r = res["result"]
            b64 = r.get("image_b64", "")
            raw = base64.b64decode(b64)
            save_path = args.get("save_path") or os.path.abspath("remote_screenshot.bmp")
            with open(save_path, "wb") as f:
                f.write(raw)
            return json.dumps({
                "captured": True,
                "width": r.get("width"),
                "height": r.get("height"),
                "file_path": save_path,
                "file_size_bytes": len(raw)
            }, indent=2)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_input":
        res = bridge.send_rpc("gui.input", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_optimize_apply":
        res = bridge.send_rpc("opt.run", args)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_sysinfo":
        res = bridge.send_rpc("sys.hardware", {}, timeout=5.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_trim_memory":
        res = bridge.send_rpc("sys.trim", {}, timeout=5.0)
        return json.dumps(res, indent=2)

    elif tool_name == "remote_find_file":
        res = bridge.send_rpc("fs.find", args, timeout=30.0)
        return json.dumps(res, indent=2)

    else:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})


def main():
    parser = argparse.ArgumentParser(description="BridgeWindows MCP Server")
    parser.add_argument("--host", default=DEFAULT_LISTEN_HOST, help="TCP listen host for agent connection")
    parser.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help="TCP listen port for agent connection")
    parser.add_argument("--token", default=None, help="Pre-shared key (or OPENBRIDGE_PSK env). Required; never printed.")
    parser.add_argument("--max-agents", type=int, default=MAX_AGENTS_DEFAULT, help="Max simultaneous agents")
    args = parser.parse_args()

    token = args.token or os.environ.get("OPENBRIDGE_PSK")
    if not token:
        parser.error("PSK required: pass --token <psk> or set OPENBRIDGE_PSK. The same PSK goes on every agent.exe command line.")
    bridge.host = args.host
    bridge.port = args.port
    bridge.token = token
    bridge.max_agents = max(1, args.max_agents)
    bridge.start_server()

    # Read MCP JSON-RPC requests from stdin line by line
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        method = req.get("method")
        msg_id = req.get("id")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "bridge-windows",
                        "version": "4.0.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "notifications/initialized":
            pass

        elif method == "ping":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {}
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": MCP_TOOLS
                }
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            params = req.get("params", {})
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            agent_id = params.get("agent")
            if agent_id is not None and not _valid_agent_id(agent_id):
                agent_id = None
            try:
                text_result = handle_tool_call(tool_name, tool_args, agent_id=agent_id)
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": text_result
                            }
                        ]
                    }
                }
            except Exception as e:
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "isError": True,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Tool execution failed: {str(e)}"
                            }
                        ]
                    }
                }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        else:
            if msg_id is not None:
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    main()
