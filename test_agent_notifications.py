#!/usr/bin/env python3
"""Agent-initiated notifications: Playdate-class agents report button/crank
events upstream; the bridge queues (bounded) and logs them instead of
dropping them. Loopback only, no agent binary needed.

Run from BridgeWindows-v4/:
  python -m pytest test_agent_notifications.py -q
"""
import time
import unittest

import bridge_mcp
from test_multiagent import FakeAgent, PSK, send_frame

PORT = 19961


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.bridge = bridge_mcp.RemoteAgentBridge(host="127.0.0.1", port=PORT, token=PSK)
        self.bridge.start_server()
        time.sleep(0.2)
        self.agent = FakeAgent("PD-NOTIF", PORT)
        self.agent.connect()

    def tearDown(self):
        self.agent.close()
        self.bridge.running = False
        try:
            self.bridge.server_sock.close()
        except OSError:
            pass
        time.sleep(0.2)

    def _wait_queue(self, agent_id, count=1, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.bridge.lock:
                session = self.bridge.agents.get(agent_id)
                n = len(session.notifications) if session else 0
            if n >= count:
                return True
            time.sleep(0.05)
        return False

    def test_button_notification_is_queued_and_drained(self):
        send_frame(self.agent.sock, self.agent._wrap(
            {"jsonrpc": "2.0", "method": "pd.button", "params": {"button": "a", "pressed": True}}))
        self.assertTrue(self._wait_queue("PD-NOTIF"))
        notes = self.bridge.drain_notifications("PD-NOTIF")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["method"], "pd.button")
        self.assertEqual(notes[0]["params"], {"button": "a", "pressed": True})
        self.assertIn("ts", notes[0])
        self.assertEqual(self.bridge.drain_notifications("PD-NOTIF"), [])

    def test_malformed_notifications_are_dropped_silently(self):
        send_frame(self.agent.sock, self.agent._wrap(
            {"jsonrpc": "2.0", "method": "x" * 65, "params": {}}))
        send_frame(self.agent.sock, self.agent._wrap(
            {"jsonrpc": "2.0", "method": "pd.ok", "params": [1, 2]}))
        send_frame(self.agent.sock, self.agent._wrap({"jsonrpc": "2.0", "id": 999}))
        time.sleep(0.5)
        self.assertEqual(self.bridge.drain_notifications("PD-NOTIF"), [])

    def test_drain_unknown_agent_is_empty(self):
        self.assertEqual(self.bridge.drain_notifications("NOPE"), [])


if __name__ == "__main__":
    unittest.main()
