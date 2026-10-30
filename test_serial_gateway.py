#!/usr/bin/env python3
"""Serial gateway tests: marker sync + untouched bidirectional piping."""
import socket
import threading
import time
import unittest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents", "esp32-ob"))
import serial_gateway


def listen():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    return s


class GatewayTests(unittest.TestCase):
    def test_marker_sync_and_pipe(self):
        ser_listener, br_listener = listen(), listen()
        got_bridge, got_serial = [], []
        gw_stats = {}

        def fake_serial():
            c, _ = ser_listener.accept()
            with c:
                c.sendall(b"ets Jul 29 2019\r\nrst:0x1 BOOT\r\n")  # ROM chatter
                time.sleep(0.1)
                c.sendall(b"OB-SER-SYNC\r\nFRAME-HELLO")  # println(): \r\n line end
                c.settimeout(5)
                try:
                    while True:
                        d = c.recv(4096)
                        if not d:
                            break
                        got_serial.append(d)
                except socket.timeout:
                    pass

        def fake_bridge():
            c, _ = br_listener.accept()
            with c:
                c.settimeout(5)
                try:
                    while True:
                        d = c.recv(4096)
                        if not d:
                            break
                        got_bridge.append(d)
                        if b"FRAME-HELLO" in b"".join(got_bridge):
                            c.sendall(b"FRAME-REPLY")
                except socket.timeout:
                    pass

        ts = threading.Thread(target=fake_serial, daemon=True)
        tb = threading.Thread(target=fake_bridge, daemon=True)
        ts.start()
        tb.start()
        gw_stats["s"] = serial_gateway.run(
            ("127.0.0.1", ser_listener.getsockname()[1]),
            ("127.0.0.1", br_listener.getsockname()[1]),
            log=lambda *a: None)
        ts.join(6)
        tb.join(6)
        ser_listener.close()
        br_listener.close()
        s = gw_stats["s"]
        self.assertTrue(s.synced)
        self.assertEqual(b"".join(got_bridge), b"FRAME-HELLO")  # chatter dropped
        self.assertEqual(b"".join(got_serial), b"FRAME-REPLY")  # bridge bytes pass
        self.assertGreater(s.dropped, 0)

    def test_split_marker_across_chunks(self):
        ser_listener, br_listener = listen(), listen()
        got_bridge = []

        def fake_serial():
            c, _ = ser_listener.accept()
            with c:
                for byte in (b"OB-SER", b"-SY", b"NC\nPAYLOAD"):
                    c.sendall(byte)
                    time.sleep(0.05)
                time.sleep(0.5)

        def fake_bridge():
            c, _ = br_listener.accept()
            with c:
                c.settimeout(5)
                try:
                    while True:
                        d = c.recv(4096)
                        if not d:
                            break
                        got_bridge.append(d)
                except socket.timeout:
                    pass

        ts = threading.Thread(target=fake_serial, daemon=True)
        tb = threading.Thread(target=fake_bridge, daemon=True)
        ts.start()
        tb.start()
        s = serial_gateway.run(
            ("127.0.0.1", ser_listener.getsockname()[1]),
            ("127.0.0.1", br_listener.getsockname()[1]),
            log=lambda *a: None)
        ts.join(6)
        tb.join(6)
        ser_listener.close()
        br_listener.close()
        self.assertTrue(s.synced)
        self.assertEqual(b"".join(got_bridge), b"PAYLOAD")

    def test_open_serial_wraps_pyserial_contract(self):
        import sys as _sys
        import types
        fake = types.ModuleType("serial")
        opened = {}

        class FakeInner:
            def __init__(self):
                self.to_read = b"OB-SER-SYNC\r\nHI"

            def read(self, n):
                out, self.to_read = self.to_read[:n], self.to_read[n:]
                return out

            def write(self, d):
                opened.setdefault("written", b"")
                opened["written"] += bytes(d)
                return len(d)

            def close(self):
                opened["closed"] = True

        def serial_for_url(port, baudrate=115200, timeout=30):
            opened["port"], opened["baud"] = port, baudrate
            return FakeInner()

        fake.serial_for_url = serial_for_url
        _sys.modules["serial"] = fake
        try:
            p = serial_gateway.open_serial("COM9")
            self.assertEqual(p.recv(64), b"OB-SER-SYNC\r\nHI")
            p.sendall(b"YO")
            with self.assertRaises(TimeoutError):
                p.recv(64)
            p.close()
        finally:
            del _sys.modules["serial"]
        self.assertEqual((opened["port"], opened["baud"], opened["written"]), ("COM9", 115200, b"YO"))
        self.assertTrue(opened.get("closed"))


if __name__ == "__main__":
    unittest.main()
