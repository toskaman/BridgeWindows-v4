#!/usr/bin/env python3
"""ESP32 agent protocol tests: the SAME firmware core, compiled for host, talks v4.

The firmware core (agents/esp32-ob/proto/, dependency-free C++) is compiled
with the host C++ compiler and driven over loopback TCP against the real
bridge server (bridge_mcp.RemoteAgentBridge), exactly like test_multiagent
does with FakeAgent — but with genuine firmware code.

Run from BridgeWindows-v4/:
  python -m pytest test_esp32_proto.py -q
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

import bridge_mcp

PSK = "TestPSK-Only-For-Loopback-99"
PORT = 19990
HERE = os.path.dirname(os.path.abspath(__file__))
PROTO = os.path.join(HERE, "agents", "esp32-ob", "proto")


def build_harness(out_dir):
    srcs = [os.path.join(PROTO, f) for f in
            ("sha256.cpp", "obproto.cpp", "host_main.cpp")]
    for s in srcs:
        if not os.path.exists(s):
            raise FileNotFoundError("missing ESP32 proto source: " + s)
    exe = os.path.join(out_dir, "ob_esp32_host.exe" if sys.platform == "win32"
                       else "ob_esp32_host")
    cxx = shutil.which("g++") or shutil.which("c++") or shutil.which("zig")
    assert cxx, "no host C++ compiler"
    if os.path.basename(cxx).startswith("zig"):
        cmd = [cxx, "c++", "-O1", "-o", exe] + srcs
        if sys.platform == "win32":
            cmd += ["-lws2_32"]
    else:
        cmd = [cxx, "-O1", "-std=c++03", "-o", exe] + srcs
        if sys.platform == "win32":
            cmd += ["-lws2_32"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert r.returncode == 0, "harness build failed:\n" + r.stderr[-2000:]
    return exe


# RFC 4231 case 2 + FIPS 180-4 SHA-256("abc"), also asserted on-device.
HMAC_SHA256_CASE2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


class Esp32ProtoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ob_esp32_")
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
        self.assertIn("LONGMAC_OK b86f60810b32c7b3d804680554b863d3a6d7d8a6e50574ae4651e6b15072799e",
                      r.stdout)
        self.assertIn("FRAMING_OK", r.stdout)

    def _bridge(self):
        b = bridge_mcp.RemoteAgentBridge(host="127.0.0.1", port=PORT,
                                         token=PSK)
        b.start_server()
        time.sleep(0.2)
        return b

    def test_handshake_and_ping_vs_real_bridge(self):
        b = self._bridge()
        try:
            p = subprocess.Popen(
                [self.exe, "--host", "127.0.0.1", "--port", str(PORT),
                 "--token", PSK, "--agent-id", "ESP32-TEST", "--once", "4"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                deadline = time.time() + 10
                while time.time() < deadline and "ESP32-TEST" not in b.agents:
                    time.sleep(0.1)
                self.assertIn("ESP32-TEST", b.agents)
                pong = b.send_rpc("sys.ping", {}, agent_id="ESP32-TEST",
                                  timeout=10)
                self.assertTrue(pong.get("result", {}).get("pong"), pong)
                diag = b.send_rpc("sys.diag", {}, agent_id="ESP32-TEST",
                                  timeout=10)
                self.assertIn("hostname", diag.get("result", {}), diag)
                out, _ = p.communicate(timeout=20)
                self.assertIn("AUTH_OK", out)
            finally:
                if p.poll() is None:
                    p.kill()
        finally:
            b.running = False
            try:
                b.server_sock.close()
            except OSError:
                pass

    def test_exec_allowlist(self):
        b = self._bridge()
        try:
            p = subprocess.Popen(
                [self.exe, "--host", "127.0.0.1", "--port", str(PORT),
                 "--token", PSK, "--agent-id", "ESP32-EXEC", "--once", "4"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                deadline = time.time() + 10
                while time.time() < deadline and "ESP32-EXEC" not in b.agents:
                    time.sleep(0.1)
                self.assertIn("ESP32-EXEC", b.agents)
                ok = b.send_rpc("exec.run", {"command": "screen.text HelloESP32"},
                                agent_id="ESP32-EXEC", timeout=10)
                self.assertEqual(ok.get("result", {}).get("exit_code"), 0, ok)
                led = b.send_rpc("exec.run", {"command": "led on"},
                                 agent_id="ESP32-EXEC", timeout=10)
                self.assertEqual(led.get("result", {}).get("exit_code"), 0, led)
                bad = b.send_rpc("exec.run", {"command": "rm -rf /"},
                                 agent_id="ESP32-EXEC", timeout=10)
                res = bad.get("result", bad)
                self.assertNotEqual(res.get("exit_code"), 0, bad)
                out, _ = p.communicate(timeout=20)
                self.assertIn("AUTH_OK", out)
            finally:
                if p.poll() is None:
                    p.kill()
        finally:
            b.running = False
            try:
                b.server_sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()
