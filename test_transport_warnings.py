#!/usr/bin/env python3
"""§3.1: the bridge loudly reports its transport reality (plaintext LAN, short PSK).

No agent needed: start the listener on loopback, capture stderr, stop it. Run:
  python -m unittest test_transport_warnings -v   (from BridgeWindows-v4/)
"""
import contextlib
import io
import time
import unittest

import bridge_mcp

PORT = 19950


def stop(bridge):
    bridge.running = False
    try:
        if bridge.server_sock is not None:
            bridge.server_sock.close()
    except OSError:
        pass
    time.sleep(0.2)


def wait_bound(bridge, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if bridge.server_sock is not None:
            return bridge.server_sock.getsockname()
        time.sleep(0.05)
    raise AssertionError('bridge did not bind in time')


class TransportWarnings(unittest.TestCase):
    def test_listen_banner_warns_frames_are_not_encrypted(self):
        buf = io.StringIO()
        b = bridge_mcp.RemoteAgentBridge(host='127.0.0.1', port=PORT, token='TestPSK-Only-For-Loopback-99')
        try:
            with contextlib.redirect_stderr(buf):
                b.start_server()
                for _ in range(100):
                    if 'NOT encrypted' in buf.getvalue():
                        break
                    time.sleep(0.05)
            out = buf.getvalue()
            self.assertIn('NOT encrypted', out)
            self.assertIn('trusted LAN', out)
        finally:
            stop(b)

    def test_short_psk_warns_but_still_listens(self):
        # Warn-only: refusing could break the live deployment whose PSK length is unknown here.
        buf = io.StringIO()
        b = bridge_mcp.RemoteAgentBridge(host='127.0.0.1', port=PORT + 1, token='short')
        try:
            with contextlib.redirect_stderr(buf):
                b.start_server()
            self.assertIn('<20 chars', buf.getvalue())
            self.assertEqual(wait_bound(b)[1], PORT + 1)
        finally:
            stop(b)

    def test_long_psk_does_not_warn_about_length(self):
        buf = io.StringIO()
        b = bridge_mcp.RemoteAgentBridge(host='127.0.0.1', port=PORT + 2, token='TestPSK-Only-For-Loopback-99')
        try:
            with contextlib.redirect_stderr(buf):
                b.start_server()
                time.sleep(0.3)
            self.assertNotIn('<20 chars', buf.getvalue())
        finally:
            stop(b)


if __name__ == '__main__':
    unittest.main()
