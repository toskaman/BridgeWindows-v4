#!/usr/bin/env python3
"""OpenBridge reference agent (pure stdlib Python 3.9+).

Runs on anything CPython runs on (Windows/macOS/Linux/*BSD, Raspberry Pi, NAS):
reverse-connects to the bridge (default 127.0.0.1:9876), performs the mutual
PSK handshake, then serves the core RPC surface: sys.ping, exec.run,
fs.read/write/hash/list/mkdir/delete, proc.list/kill, sys.diag, log.get and
agent.update. Windows-only methods (reg.*, svc.op, kiosk.*) answer
"unsupported on this platform" instead of hanging the caller.

Config (CLI > env > agent.provision sidecar next to this file, then cwd):
  --host H --port P --token PSK --agent-id ID
  env: BRIDGE_PSK
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import platform
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

PROTOCOL_VERSION = "4.0.0"
MAX_FRAME = 8 * 1024 * 1024
RECONNECT_START, RECONNECT_MAX = 1.0, 30.0

LOGS, LOG_LOCK, LOG_SEQ = [], threading.Lock(), [0]


def log(level, msg):
    with LOG_LOCK:
        LOG_SEQ[0] += 1
        LOGS.append({"seq": LOG_SEQ[0], "level": level, "msg": msg[:500]})
        del LOGS[:-200]
    sys.stderr.write("[agent-py][%s] %s\n" % (level, msg[:300]))
    sys.stderr.flush()


def load_sidecar(path):
    cfg = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip().replace("-", "_")] = v.strip()
    except OSError:
        pass
    return cfg


def resolve_config(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    cfg = load_sidecar(os.path.join(here, "agent.provision"))
    cfg.update({k: v for k, v in load_sidecar("agent.provision").items() if v})
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=cfg.get("host", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(cfg.get("port", 9876)))
    ap.add_argument("--token", default=os.environ.get("BRIDGE_PSK", cfg.get("token", "")))
    ap.add_argument("--agent-id", default=cfg.get("agent_id", ""))
    a = ap.parse_args(argv)
    if not a.agent_id:
        a.agent_id = "".join(c if c.isalnum() or c in "-_" else "-" for c in platform.node())[:32] or "PY-AGENT"
        if not a.agent_id[0].isalnum():
            a.agent_id = "A" + a.agent_id[1:]
    if not a.token:
        sys.stderr.write("agent: PSK required (--token, BRIDGE_PSK env or agent.provision sidecar).\n")
        return None
    return a


def send_frame(sock, obj):
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def recv_frame(sock):
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length == 0 or length > MAX_FRAME:
        raise ValueError("bad frame length %d" % length)
    data = json.loads(recv_exact(sock, length).decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("frame is not an object")
    return data


def hmac_hex(key, *parts):
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p.encode("utf-8"))
    return m.hexdigest()


def mem_info():
    """(total, avail) bytes; stdlib-only on Linux/Windows/macOS."""
    try:
        if sys.platform.startswith("linux"):
            kv = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    k, _, v = line.partition(":")
                    kv[k] = int(v.split()[0]) * 1024
            return kv.get("MemTotal", 0), kv.get("MemAvailable", kv.get("MemFree", 0))
        if sys.platform == "win32":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong)] + \
                           [("x%d" % i, ctypes.c_ulonglong) for i in range(4)]

            ms = MS()
            ms.dwLength = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
            return ms.ullTotalPhys, ms.ullAvailPhys
        if sys.platform == "darwin":
            total = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True,
                                       text=True, timeout=5).stdout.strip())
            vm = subprocess.run(["vm_stat"], capture_output=True, text=True, timeout=5).stdout
            page = 16384
            free = weird = 0
            for line in vm.splitlines():
                if line.startswith("Pages free:"):
                    free = int(line.split(":")[1].strip().rstrip("."))
                elif line.startswith("Pages speculative:"):
                    weird = int(line.split(":")[1].strip().rstrip("."))
            return total, (free + weird) * page
    except Exception:
        pass
    return 0, 0


def proc_snapshot():
    """[(pid, ppid, name, rss)] without third-party deps."""
    out = []
    try:
        if sys.platform.startswith("linux"):
            import glob
            for stat in glob.glob("/proc/[0-9]*/stat"):
                try:
                    pid = int(stat.split("/")[2])
                    parts = open(stat).read().rsplit(")", 1)
                    rest = parts[1].split()
                    ppid, rss_pages = int(rest[1]), int(rest[21])
                    name = parts[0].split("(", 1)[1]
                    out.append((pid, ppid, name, rss_pages * 4096))
                except (ValueError, IndexError, OSError):
                    continue
            return out
        if sys.platform == "win32":
            ps = subprocess.run(["powershell", "-NoProfile", "-Command",
                                 "Get-Process | Select-Object Id,Name,WorkingSet64 | ConvertTo-Json -Compress"],
                                capture_output=True, text=True, timeout=15).stdout.strip()
            rows = json.loads(ps or "[]")
            if isinstance(rows, dict):
                rows = [rows]
            return [(int(r.get("Id", 0)), 0, str(r.get("Name", "")), int(r.get("WorkingSet64", 0))) for r in rows]
        ps = subprocess.run(["ps", "-ax", "-o", "pid=,ppid=,rss=,comm="], capture_output=True,
                            text=True, timeout=15).stdout
        for line in ps.splitlines():
            p = line.split(None, 3)
            if len(p) == 4:
                out.append((int(p[0]), int(p[1]), p[3].strip(), int(p[2]) * 1024))
    except Exception:
        pass
    return out


START = time.time()


def handle(method, params):
    if method == "sys.ping":
        return {"pong": True, "version": PROTOCOL_VERSION, "uptime_ms": int((time.time() - START) * 1000)}
    if method == "exec.run":
        cmd = params.get("command") or params.get("cmd")
        if params.get("cmd_b64"):
            cmd = base64.b64decode(params["cmd_b64"]).decode("utf-8", errors="replace")
        if not cmd:
            raise ValueError("Missing command or cmd_b64")
        shell = (params.get("shell") or "").lower()
        if shell == "powershell" and sys.platform == "win32":
            full = ["powershell.exe", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", cmd]
            use_shell = False
        elif shell == "direct":
            full, use_shell = cmd, False
        elif sys.platform == "win32":
            full, use_shell = "cmd.exe /c " + cmd, False
        else:
            full, use_shell = cmd, True
        tmo = params.get("timeout_ms", 0) or params.get("timeout_seconds", 0) * 1000 or 120000
        try:
            p = subprocess.run(full, shell=use_shell, capture_output=True,
                               cwd=params.get("cwd") or None, timeout=tmo / 1000.0)
            return {"pid": p.args if isinstance(p.args, int) else 0, "exit_code": p.returncode,
                    "timed_out": False, "stdout_b64": base64.b64encode(p.stdout).decode("ascii"),
                    "stderr_b64": base64.b64encode(p.stderr).decode("ascii")}
        except subprocess.TimeoutExpired as e:
            return {"pid": 0, "exit_code": -1, "timed_out": True,
                    "stdout_b64": base64.b64encode(e.stdout or b"").decode("ascii"),
                    "stderr_b64": base64.b64encode(e.stderr or b"").decode("ascii")}
    if method == "fs.read":
        off = int(params.get("offset", 0))
        ln = params.get("length", 1 << 20)
        with open(params["path"], "rb") as f:
            f.seek(off)
            data = f.read(ln if ln is not None else 1 << 20)
            f.seek(0, 2)
            total = f.tell()
        return {"data_b64": base64.b64encode(data).decode("ascii"), "bytes_read": len(data),
                "total_size": total, "eof": off + len(data) >= total,
                "chunk_sha256": hashlib.sha256(data).hexdigest()}
    if method == "fs.write":
        data = base64.b64decode(params.get("data_b64", ""))
        mode = "ab" if params.get("append") else "r+b" if params.get("offset") else "wb"
        off = int(params.get("offset", 0))
        if mode == "r+b" and not os.path.exists(params["path"]):
            mode = "wb"
        with open(params["path"], mode) as f:
            if off and mode == "r+b":
                f.seek(off)
            f.write(data)
        return {"bytes_written": len(data),
                "file_sha256": hashlib.sha256(open(params["path"], "rb").read()).hexdigest()}
    if method == "fs.hash":
        return {"sha256": hashlib.sha256(open(params["path"], "rb").read()).hexdigest(),
                "size": os.path.getsize(params["path"])}
    if method == "fs.list":
        entries = [{"name": e, "is_dir": os.path.isdir(os.path.join(params["path"], e)),
                    "size": os.path.getsize(os.path.join(params["path"], e))}
                   for e in sorted(os.listdir(params["path"]))]
        return {"entries": entries}
    if method == "fs.mkdir":
        os.makedirs(params["path"], exist_ok=True)
        return {"created": True}
    if method == "fs.delete":
        p = params["path"]
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)
        return {"deleted": True}
    if method == "proc.list":
        return {"processes": [{"pid": pid, "ppid": ppid, "name": name, "working_set_bytes": rss}
                              for pid, ppid, name, rss in proc_snapshot()]}
    if method == "proc.kill":
        pid = int(params["pid"])
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, timeout=15)
        else:
            os.kill(pid, 9)
        return {"killed": True}
    if method in ("sys.diag", "sys.telemetry"):
        total, avail = mem_info()
        disks = []
        for mp in (["C:\\"] if sys.platform == "win32" else ["/"]):
            try:
                u = shutil.disk_usage(mp)
                disks.append({"mount": mp, "total_bytes": u.total, "free_bytes": u.free})
            except OSError:
                pass
        return {"hostname": platform.node(), "version": PROTOCOL_VERSION,
                "architecture": platform.machine(), "cpu_cores": os.cpu_count() or 0,
                "cpu_load_percent": (os.getloadavg()[0] / (os.cpu_count() or 1) * 100)
                if hasattr(os, "getloadavg") else 0.0,
                "ram_total_bytes": total, "ram_avail_bytes": avail,
                "agent_working_set_bytes": 0, "io_read_bytes_sec": 0, "io_write_bytes_sec": 0,
                "io_total_read_bytes": 0, "io_total_write_bytes": 0,
                "agent_pid": os.getpid(), "disks": disks,
                "uptime_seconds": int(time.time() - START)}
    if method == "log.get":
        with LOG_LOCK:
            logs = [l for l in LOGS if l["seq"] > int(params.get("since_seq", 0))]
        return {"logs": logs[-100:]}
    if method == "agent.update":
        staged = params.get("path") or params.get("staged_path")
        if not staged or not os.path.exists(staged):
            raise ValueError("Missing staged update file")
        me = os.path.abspath(__file__)
        os.replace(me, me + ".old")
        shutil.copyfile(staged, me)
        log("INFO", "updated from %s; relaunching" % staged)
        threading.Thread(target=lambda: (time.sleep(1), os.execv(sys.executable, [sys.executable, me] + sys.argv[1:])),
                         daemon=True).start()
        return {"updated": True, "relaunching": True}
    if method.split(".")[0] in ("reg", "svc", "kiosk"):
        raise ValueError("unsupported on this platform: " + method)
    raise ValueError("unknown method: " + method)


def serve(sock, sesskey, agent_id):
    send_lock = threading.Lock()

    def reply(obj):
        body = base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")
        mac = hmac.new(sesskey, body.encode("ascii"), hashlib.sha256).hexdigest()
        with send_lock:
            send_frame(sock, {"v": 4, "body_b64": body, "mac": mac})

    log("INFO", "Connected to master as '%s'" % agent_id)
    while True:
        frame = recv_frame(sock)
        if frame.get("v") != 4 or not hmac.compare_digest(
                hmac.new(sesskey, frame.get("body_b64", "").encode("ascii"),
                         hashlib.sha256).hexdigest(), frame.get("mac", "")):
            raise ConnectionError("bad session MAC")
        req = json.loads(base64.b64decode(frame["body_b64"]).decode("utf-8"))
        method = req.get("method", "")
        rid = req.get("id")
        try:
            reply({"jsonrpc": "2.0", "id": rid, "result": handle(method, req.get("params", {}) or {})})
        except Exception as e:
            reply({"jsonrpc": "2.0", "id": rid,
                   "error": {"code": -32001, "message": "%s: %s" % (type(e).__name__, str(e)[:200])}})


def connect_once(host, port, psk, agent_id):
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(15)
    try:
        agent_nonce = secrets.token_hex(16)
        send_frame(sock, {"jsonrpc": "2.0", "method": "agent.hello",
                          "params": {"version": PROTOCOL_VERSION,
                                     "arch": platform.machine() or "unknown",
                                     "os": {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux"),
                                     "pid": os.getpid(), "agent_id": agent_id,
                                     "agent_nonce": agent_nonce}})
        ch = recv_frame(sock)
        params = ch.get("params") if isinstance(ch.get("params"), dict) else {}
        master_nonce = params.get("master_nonce") or ch.get("master_nonce", "")
        if ch.get("method") != "auth.challenge" or len(master_nonce) != 32:
            raise ConnectionError("handshake rejected: %s" % json.dumps(ch)[:160])
        send_frame(sock, {"jsonrpc": "2.0", "method": "auth.response",
                          "params": {"agent_id": agent_id,
                                     "hmac": hmac_hex(psk, agent_nonce, master_nonce, agent_id)}})
        cf = recv_frame(sock)
        if cf.get("method") != "auth.confirm" or not hmac.compare_digest(
                cf.get("params", {}).get("hmac", ""),
                hmac_hex(psk, master_nonce, agent_nonce, agent_id)):
            raise ConnectionError("master authentication failed")
        sesskey = hashlib.sha256(psk + agent_nonce.encode() + master_nonce.encode()).digest()
        sock.settimeout(None)
        serve(sock, sesskey, agent_id)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main(argv):
    cfg = resolve_config(argv)
    if cfg is None:
        return 2
    psk = cfg.token.encode("utf-8")
    backoff = RECONNECT_START
    while True:
        try:
            connect_once(cfg.host, cfg.port, psk, cfg.agent_id)
            backoff = RECONNECT_START
        except (ConnectionError, OSError, ValueError) as e:
            log("WARN", "link down (%s); retry in %.0fs" % (str(e)[:120], backoff))
        time.sleep(backoff)
        backoff = min(backoff * 2, RECONNECT_MAX)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

