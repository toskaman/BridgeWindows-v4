#!/usr/bin/env python3
"""Playdate agent protocol tests: the SAME C core, compiled for host, talks v4.

The agent core (agents/playdate-ob/proto/, dependency-free C99) is compiled
with the host C compiler and driven over loopback TCP against the real
bridge server (bridge_mcp.RemoteAgentBridge) — genuine agent code, plus the
agent->bridge notification path the Playdate buttons use.

Run from BridgeWindows-v4/:
  python -m pytest test_playdate_proto.py -q
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import bridge_mcp

PSK = "TestPSK-Only-For-Loopback-99"
PORT = 19991
HERE = os.path.dirname(os.path.abspath(__file__))
PROTO = os.path.join(HERE, "agents", "playdate-ob", "proto")


def build_harness(out_dir):
    srcs = [os.path.join(PROTO, f) for f in
            ("obsha256.c", "obminijson.c", "obproto.c", "host_main.c")]
    for s in srcs:
        if not os.path.exists(s):
            raise FileNotFoundError("missing Playdate proto source: " + s)
    exe = os.path.join(out_dir, "ob_pd_host.exe" if sys.platform == "win32"
                       else "ob_pd_host")
    cc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
    assert cc, "no host C compiler"
    cmd = [cc, "-O1", "-std=c99", "-Wall", "-o", exe] + srcs
    if sys.platform == "win32":
        cmd += ["-lws2_32"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, "harness build failed:\n" + r.stderr[-2000:]
    return exe


HMAC_SHA256_CASE2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
LONGMAC_200 = "ecdeacc81888988217e30741c69908c6a109f2ee96df0b5eab8a53694675a32c"


class PlaydateProtoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ob_pd_")
        cls.exe = build_harness(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_selftest_vectors(self):
        r = subprocess.run([self.exe, "--selftest"], capture_output=True,
                           text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("SHA256_OK " + SHA256_ABC, r.stdout)
        self.assertIn("HMAC_OK " + HMAC_SHA256_CASE2, r.stdout)
        self.assertIn("LONGMAC_OK " + LONGMAC_200, r.stdout)
        self.assertIn("JSON_OK", r.stdout)
        self.assertIn("FRAMING_OK", r.stdout)

    def _bridge(self):
        b = bridge_mcp.RemoteAgentBridge(host="127.0.0.1", port=PORT,
                                         token=PSK)
        b.start_server()
        time.sleep(0.2)
        return b

    def _stop(self, b):
        b.running = False
        try:
            b.server_sock.close()
        except OSError:
            pass

    def _run_agent(self, agent_id, *extra):
        return subprocess.Popen(
            [self.exe, "--host", "127.0.0.1", "--port", str(PORT),
             "--token", PSK, "--agent-id", agent_id] + list(extra),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def _wait_agent(self, b, agent_id, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline and agent_id not in b.agents:
            time.sleep(0.1)
        self.assertIn(agent_id, b.agents)

    def test_handshake_and_ping_vs_real_bridge(self):
        b = self._bridge()
        try:
            p = self._run_agent("PD-TEST", "--once", "4")
            try:
                self._wait_agent(b, "PD-TEST")
                pong = b.send_rpc("sys.ping", {}, agent_id="PD-TEST",
                                  timeout=10)
                self.assertTrue(pong.get("result", {}).get("pong"), pong)
                diag = b.send_rpc("sys.diag", {}, agent_id="PD-TEST",
                                  timeout=10)
                self.assertIn("hostname", diag.get("result", {}), diag)
                out, _ = p.communicate(timeout=20)
                self.assertIn("AUTH_OK", out)
            finally:
                if p.poll() is None:
                    p.kill()
        finally:
            self._stop(b)

    def test_exec_allowlist(self):
        b = self._bridge()
        try:
            p = self._run_agent("PD-EXEC", "--once", "6")
            try:
                self._wait_agent(b, "PD-EXEC")
                ok = b.send_rpc("exec.run", {"command": "screen.text HelloPD"},
                                agent_id="PD-EXEC", timeout=10)
                self.assertEqual(ok.get("result", {}).get("exit_code"), 0, ok)
                beep = b.send_rpc("exec.run", {"command": "beep"},
                                  agent_id="PD-EXEC", timeout=10)
                self.assertEqual(beep.get("result", {}).get("exit_code"), 0, beep)
                bad = b.send_rpc("exec.run", {"command": "rm -rf /"},
                                 agent_id="PD-EXEC", timeout=10)
                res = bad.get("result", bad)
                self.assertNotEqual(res.get("exit_code"), 0, bad)
                out, _ = p.communicate(timeout=20)
                self.assertIn("AUTH_OK", out)
            finally:
                if p.poll() is None:
                    p.kill()
        finally:
            self._stop(b)

    def test_button_notification_reaches_bridge(self):
        b = self._bridge()
        try:
            p = self._run_agent("PD-BTN", "--once", "1", "--notify",
                                'pd.button,{"button":"a","pressed":true}')
            try:
                self._wait_agent(b, "PD-BTN")
                # Drain WHILE connected: the bridge deletes the session (and
                # its queued notifications) on agent disconnect, so draining
                # after communicate() would always see []. The agent exits by
                # itself on serve-loop idle timeout (< communicate timeout).
                deadline = time.time() + 10
                notes = []
                while time.time() < deadline and not notes:
                    notes = b.drain_notifications("PD-BTN")
                    if not notes:
                        time.sleep(0.1)
                self.assertEqual(len(notes), 1)
                self.assertEqual(notes[0]["method"], "pd.button")
                self.assertEqual(notes[0]["params"],
                                 {"button": "a", "pressed": True})
                out, _ = p.communicate(timeout=20)
                self.assertIn("NOTIFY_OK pd.button", out)
            finally:
                if p.poll() is None:
                    p.kill()
        finally:
            self._stop(b)


if __name__ == "__main__":
    unittest.main()
