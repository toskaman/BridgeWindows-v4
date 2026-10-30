#!/usr/bin/env python3
"""Serial gateway: pipe ESP32 serial-mode v4 frames to the master over TCP.

The firmware (OB_NO_WIFI build) emits one OB-SER-SYNC marker line, then pure
v4 bytes. Everything before the marker (ROM bootloader chatter, reboot loops)
is dropped and logged; after it, bytes flow both ways untouched. The gateway
never interprets frames: authentication and MACs terminate at the bridge.

Use: QEMU `-serial tcp:127.0.0.1:5555,server` (QEMU waits for us, so the
marker is never missed), or a physical board over USB serial via
--serial-port (needs pyserial: pip install pyserial).
"""
import socket
import sys
import threading
import time


def open_serial(port, baud=115200, timeout=30):
    """Open a local serial port (COMx, /dev/ttyUSB0) or pyserial URL
    (socket://...). Returns a socket-like object (recv/sendall/close)."""
    import serial

    class Port:
        def __init__(self, inner):
            self._s = inner

        def recv(self, n):
            chunk = self._s.read(n if n > 0 else 1)
            if chunk:
                return bytes(chunk)
            raise TimeoutError("serial read timeout")

        def sendall(self, data):
            self._s.write(bytes(data))

        def close(self):
            self._s.close()

    return Port(serial.serial_for_url(port, baudrate=baud, timeout=timeout))

MARKER = b"OB-SER-SYNC"  # line end consumed through \n (firmware prints \r\n)
CHUNK = 4096


class PipeStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.dropped = 0
        self.synced = False
        self.ser_to_bridge = 0
        self.bridge_to_ser = 0
        self.t_sync = None


def _pump(src, dst, stats, direction, stop, log):
    buf = b""
    try:
        while not stop.is_set():
            try:
                data = src.recv(CHUNK)
            except TimeoutError:
                continue  # serial idle poll; the session stays up
            except (ConnectionError, OSError):
                break
            if not data:
                break
            if direction == "S2B":
                with stats.lock:
                    if not stats.synced:
                        buf += data
                        i = buf.find(MARKER)
                        if i < 0:
                            # Keep a marker-length tail: the marker may straddle chunks.
                            keep = buf[-(len(MARKER) - 1):] if len(MARKER) > 1 else b""
                            stats.dropped += len(buf) - len(keep)
                            buf = keep
                            continue
                        eol = buf.find(b"\n", i)
                        if eol < 0:
                            buf = buf[i:]  # marker seen, line end split across chunks
                            stats.dropped += i
                            continue
                        stats.dropped += eol + 1
                        head = (buf[:i])[-300:]
                        log("pre-marker bytes: %r" % head)
                        data = buf[eol + 1:]
                        buf = b""
                        stats.synced = True
                        stats.t_sync = time.time()
                        log("SYNC after %d dropped bytes" % stats.dropped)
                        if not data:
                            continue
                    stats.ser_to_bridge += len(data)
            else:
                with stats.lock:
                    stats.bridge_to_ser += len(data)
            try:
                dst.sendall(data)
            except (ConnectionError, OSError):
                break
    finally:
        stop.set()


def run(serial_addr, bridge_addr, log=print, ready=None, serial_port=None):
    """Connect both sides and pipe until either drops. Returns PipeStats.
    serial_port: local port/URL via pyserial instead of the serial_addr TCP."""
    stats, stop = PipeStats(), threading.Event()
    ser = open_serial(serial_port) if serial_port else socket.create_connection(serial_addr, timeout=30)
    try:
        br = socket.create_connection(bridge_addr, timeout=30)
    except OSError:
        ser.close()
        raise
    log("serial %s <-> bridge %s" % (serial_addr, bridge_addr))
    if ready is not None:
        ready()
    t1 = threading.Thread(target=_pump, args=(ser, br, stats, "S2B", stop, log), daemon=True)
    t2 = threading.Thread(target=_pump, args=(br, ser, stats, "B2S", stop, log), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    ser.close()
    br.close()
    return stats


def main(argv):
    serial_port = None
    args = list(argv[1:])
    if "--serial-port" in args:
        i = args.index("--serial-port")
        try:
            serial_port = args[i + 1]
        except IndexError:
            print("usage: serial_gateway.py [--serial-port PORT] <serial-host:port|-> <bridge-host:port>")
            return 2
        del args[i:i + 2]
    if len(args) != 2:
        print("usage: serial_gateway.py [--serial-port PORT] <serial-host:port|-> <bridge-host:port>")
        return 2
    def addr(s):
        h, p = s.rsplit(":", 1)
        return h, int(p)
    stats = run(addr(args[0]) if args[0] != "-" else (None, None), addr(args[1]),
                serial_port=serial_port)
    print("done synced=%s dropped=%d s2b=%d b2s=%d" % (
        stats.synced, stats.dropped, stats.ser_to_bridge, stats.bridge_to_ser))
    return 0 if stats.synced else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
