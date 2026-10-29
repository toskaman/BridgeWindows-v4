#!/usr/bin/env python3
"""Multi-agent v4 tests: registry, routing, mutual auth, no secret on wire.

Self-contained: fake agents over loopback, no agent.exe needed. Run:
  python -m unittest test_multiagent -v   (from BridgeWindows-v4/)
"""
import base64
import hashlib
import hmac
import json
import secrets
import socket
import struct
import threading
import time
import unittest

import bridge_mcp

PSK = 'TestPSK-Only-For-Loopback-99'
PORT_BASE = 19900


def send_frame(sock, obj):
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack('!I', len(payload)) + payload)


def recv_frame(sock, timeout=5.0):
    sock.settimeout(timeout)
    header = b''
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError('closed during header')
        header += chunk
    (length,) = struct.unpack('!I', header)
    if length == 0 or length > 2 * 1024 * 1024:
        raise ValueError(f'bad length {length}')
    payload = b''
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise ConnectionError('closed during payload')
        payload += chunk
    return json.loads(payload.decode())


def hmac_hex(key: bytes, *parts: str) -> str:
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p.encode())
    return m.hexdigest()


class FakeAgent:
    """Minimal v4 agent: hello -> challenge -> response -> confirm -> session MACs."""

    def __init__(self, agent_id, port, psk=PSK, proto='v4'):
        self.agent_id = agent_id
        self.port = port
        self.psk = psk.encode()
        self.proto = proto
        self.sock = None
        self.sesskey = None
        self.received = []
        self.agent_nonce = secrets.token_hex(16)

    def connect(self):
        self.sock = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        if self.proto == 'v3':
            send_frame(self.sock, {'jsonrpc': '2.0', 'method': 'agent.hello',
                                   'params': {'version': '3.7.1', 'arch': 'x64', 'pid': 1, 'token': PSK}})
            return
        send_frame(self.sock, {'jsonrpc': '2.0', 'method': 'agent.hello',
                               'params': {'version': '4.0.0', 'arch': 'x64', 'pid': 1,
                                          'agent_id': self.agent_id, 'agent_nonce': self.agent_nonce}})
        chal = recv_frame(self.sock)
        assert chal.get('method') == 'auth.challenge', chal
        master_nonce = chal['params']['master_nonce']
        send_frame(self.sock, {'jsonrpc': '2.0', 'method': 'auth.response',
                               'params': {'agent_id': self.agent_id,
                                          'hmac': hmac_hex(self.psk, self.agent_nonce, master_nonce, self.agent_id)}})
        conf = recv_frame(self.sock)
        assert conf.get('method') == 'auth.confirm', conf
        expect = hmac_hex(self.psk, master_nonce, self.agent_nonce, self.agent_id)
        if not hmac.compare_digest(conf['params']['hmac'], expect):
            raise ConnectionError('master auth failed')
        self.sesskey = hashlib.sha256(self.psk + self.agent_nonce.encode() + master_nonce.encode()).digest()

    def _wrap(self, obj):
        body_b64 = base64.b64encode(json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()).decode('ascii')
        mac = hmac.new(self.sesskey, body_b64.encode('ascii'), hashlib.sha256).hexdigest()
        return {'v': 4, 'body_b64': body_b64, 'mac': mac}

    def _unwrap(self, frame):
        assert frame.get('v') == 4, frame
        body_b64 = frame['body_b64']
        expect = hmac.new(self.sesskey, body_b64.encode('ascii'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(frame['mac'], expect):
            raise ConnectionError('bad session mac')
        return json.loads(base64.b64decode(body_b64).decode())

    def serve_once(self, timeout=5.0):
        """Answer one request with an echo result. Returns the method seen."""
        req = self._unwrap(recv_frame(self.sock, timeout))
        self.received.append(req.get('method'))
        send_frame(self.sock, self._wrap({'jsonrpc': '2.0', 'id': req.get('id'),
                                          'result': {'echo': self.agent_id, 'method': req.get('method')}}))
        return req.get('method')

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class MultiAgentTests(unittest.TestCase):
    def setUp(self):
        MultiAgentTests._port = getattr(MultiAgentTests, '_port', PORT_BASE) + 1
        self.bridge = bridge_mcp.RemoteAgentBridge(host='127.0.0.1', port=MultiAgentTests._port, token=PSK)
        self.bridge.start_server()
        time.sleep(0.2)
        self.agents = []

    def tearDown(self):
        for a in self.agents:
            a.close()
        self.bridge.running = False
        try:
            self.bridge.server_sock.close()
        except OSError:
            pass
        time.sleep(0.2)

    def make_agent(self, agent_id, **kw):
        a = FakeAgent(agent_id, MultiAgentTests._port, **kw)
        a.connect()
        self.agents.append(a)
        return a

    def test_two_agents_concurrently_visible(self):
        self.make_agent('PC1')
        self.make_agent('PC2')
        time.sleep(0.3)
        self.assertEqual(sorted(self.bridge.agents.keys()), ['PC1', 'PC2'])

    def test_remote_status_lists_all_agents(self):
        self.make_agent('PC1')
        self.make_agent('PC2')
        time.sleep(0.3)
        old, bridge_mcp.bridge = bridge_mcp.bridge, self.bridge
        try:
            st = json.loads(bridge_mcp.handle_tool_call('remote_status', {}))
        finally:
            bridge_mcp.bridge = old
        self.assertIn('PC1', json.dumps(st))
        self.assertIn('PC2', json.dumps(st))
        self.assertNotIn(PSK, json.dumps(st))

    def test_routed_rpc_reaches_correct_agent(self):
        a1 = self.make_agent('PC1')
        a2 = self.make_agent('PC2')
        time.sleep(0.3)
        t = threading.Thread(target=a2.serve_once, daemon=True)
        t.start()
        res = self.bridge.send_rpc('sys.ping', {}, timeout=5.0, agent_id='PC2')
        t.join(timeout=6)
        self.assertEqual(res.get('result', {}).get('echo'), 'PC2')
        self.assertEqual(a1.received, [])

    def test_unselected_multi_is_ambiguity_error(self):
        self.make_agent('PC1')
        self.make_agent('PC2')
        time.sleep(0.3)
        res = self.bridge.send_rpc('sys.ping', {}, timeout=2.0)
        self.assertIn('error', res)
        self.assertIn('PC1', res['error']['message'])
        self.assertIn('PC2', res['error']['message'])

    def test_unknown_agent_rejected_before_registry(self):
        bad = FakeAgent('EVIL', MultiAgentTests._port, psk='Wrong-PS8K-0000000000000000')
        with self.assertRaises((ConnectionError, AssertionError)):
            bad.connect()
        bad.close()
        time.sleep(0.3)
        self.assertNotIn('EVIL', self.bridge.agents)

    def test_duplicate_live_id_rejected_old_session_intact(self):
        a1 = self.make_agent('PC1')
        time.sleep(0.3)
        dup = FakeAgent('PC1', MultiAgentTests._port)
        with self.assertRaises((ConnectionError, AssertionError)):
            dup.connect()
        dup.close()
        time.sleep(0.3)
        t = threading.Thread(target=a1.serve_once, daemon=True)
        t.start()
        res = self.bridge.send_rpc('sys.ping', {}, timeout=5.0, agent_id='PC1')
        t.join(timeout=6)
        self.assertEqual(res.get('result', {}).get('echo'), 'PC1')

    def test_reconnect_after_drop_ok(self):
        a1 = self.make_agent('PC1')
        time.sleep(0.3)
        a1.close()
        for _ in range(50):
            if 'PC1' not in self.bridge.agents:
                break
            time.sleep(0.1)
        self.assertNotIn('PC1', self.bridge.agents)
        a1b = self.make_agent('PC1')
        time.sleep(0.3)
        self.assertIn('PC1', self.bridge.agents)
        t = threading.Thread(target=a1b.serve_once, daemon=True)
        t.start()
        res = self.bridge.send_rpc('sys.ping', {}, timeout=5.0, agent_id='PC1')
        t.join(timeout=6)
        self.assertEqual(res.get('result', {}).get('echo'), 'PC1')

    def test_no_secret_on_wire(self):
        captured = []
        orig_send, orig_recv = send_frame, recv_frame

        def send_cap(sock, obj):
            payload = json.dumps(obj).encode()
            captured.append(payload)
            sock.sendall(struct.pack('!I', len(payload)) + payload)

        def recv_cap(sock, timeout=5.0):
            msg = orig_recv(sock, timeout)
            captured.append(json.dumps(msg).encode())
            return msg

        globals()['send_frame'], globals()['recv_frame'] = send_cap, recv_cap
        try:
            a = self.make_agent('PC1')
            time.sleep(0.3)
            t = threading.Thread(target=a.serve_once, daemon=True)
            t.start()
            self.bridge.send_rpc('sys.ping', {}, timeout=5.0, agent_id='PC1')
            t.join(timeout=6)
        finally:
            globals()['send_frame'], globals()['recv_frame'] = orig_send, orig_recv
        blob = b''.join(captured)
        self.assertTrue(len(blob) > 100)
        self.assertNotIn(PSK.encode(), blob)

    def test_stale_v3_hello_rejected(self):
        v3 = FakeAgent('OLD', MultiAgentTests._port, proto='v3')
        v3.connect()  # sends legacy hello; server must close without registering
        time.sleep(0.5)
        v3.close()
        self.assertNotIn('OLD', self.bridge.agents)

    def test_server_refuses_to_listen_without_psk(self):
        b = bridge_mcp.RemoteAgentBridge(host='127.0.0.1', port=MultiAgentTests._port + 500, token=None)
        with self.assertRaises(RuntimeError):
            b.start_server()

    def test_nested_tool_call_inherits_outer_agent_target(self):
        # Regression: nested handle_tool_call(agent_id=None) inside an outer
        # targeted call must keep the target (update/sync broke with 2 agents).
        seen = []
        orig = bridge_mcp._dispatch_tool_call

        def spy(tool, args):
            seen.append(bridge_mcp._agent_ctx.get())
            return '{"ok": true}'

        bridge_mcp._dispatch_tool_call = spy
        try:
            tok = bridge_mcp._agent_ctx.set('PC2')  # outer targeted call
            try:
                bridge_mcp.handle_tool_call('anything', {})
            finally:
                bridge_mcp._agent_ctx.reset(tok)
        finally:
            bridge_mcp._dispatch_tool_call = orig
        self.assertEqual(seen, ['PC2'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
