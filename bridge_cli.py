#!/usr/bin/env python3
"""
BridgeWindows CLI Client v3.1.0
Fast command-line tool to query BridgeWindows Daemon on 127.0.0.1:9877.
Supports base64 transport, script execution, registry queries, and telemetry.
"""

import sys
import os
import json
import base64
import http.client
import socket
import threading

DAEMON_HOST = "127.0.0.1"
DAEMON_PORT = 9877

class DaemonClient:
    """Thread-safe persistent HTTP/1.1 connection pool with automatic reconnect."""
    def __init__(self, host: str = DAEMON_HOST, port: int = DAEMON_PORT):
        self.host = host
        self.port = port
        self._conn = None
        self._lock = threading.Lock()

    def _reset(self):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def request(self, method: str, path: str, body: bytes = None, headers: dict = None, timeout: float = 120.0) -> bytes:
        if headers is None:
            headers = {}
        headers.setdefault("Connection", "keep-alive")
        if body:
            headers.setdefault("Content-Length", str(len(body)))

        with self._lock:
            for attempt in range(2):
                try:
                    if self._conn is None:
                        self._conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
                    self._conn.timeout = timeout
                    self._conn.request(method, path, body=body, headers=headers)
                    resp = self._conn.getresponse()
                    data = resp.read()
                    if resp.getheader("Connection", "").lower() == "close":
                        self._reset()
                    return data
                except (http.client.HTTPException, socket.error, ConnectionError):
                    self._reset()
                    if attempt == 1:
                        raise

_client = DaemonClient()

WANT_AGENT = os.environ.get("BRIDGE_AGENT")


def post_tool(tool_name: str, args: dict = None) -> dict:
    if args is None:
        args = {}
    payload_obj = {"tool": tool_name, "args": args}
    if WANT_AGENT:
        payload_obj["agent"] = WANT_AGENT
    payload = json.dumps(payload_obj).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    try:
        data = _client.request("POST", "/tool", body=payload, headers=headers, timeout=120.0)
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        return {"success": False, "error": f"Failed to connect to daemon: {e}"}

def get_health() -> dict:
    try:
        data = _client.request("GET", "/health", timeout=5.0)
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        return {"status": "error", "error": str(e), "connected": False}

def main():
    global WANT_AGENT
    if "--agent" in sys.argv:
        i = sys.argv.index("--agent")
        if i + 1 >= len(sys.argv):
            print("Error: --agent needs an agent id.", file=sys.stderr)
            sys.exit(1)
        WANT_AGENT = sys.argv[i + 1]
        del sys.argv[i:i + 2]
    if len(sys.argv) < 2:
        print("Usage: bridge_cli.py [--agent <id>] <command> [args...]")
        print("Commands:")
        print("  health                     Check daemon & agent health")
        print("  status                     Detailed remote status")
        print("  exec <cmd> [timeout] [sh]  Run remote command")
        print("  script <file.ps1> [timeout] Run a local script file on remote PC2")
        print("  logs [min_level]           Fetch remote agent logs")
        print("  sysinfo                    Fetch remote OS & hardware info")
        print("  telemetry                  Fetch live CPU/RAM telemetry")
        print("  find <root> <pat> [m] [d]  Native fast file search")
        print("  trim                       Trim process working sets")
        print("  reg_read <h> <p> <n>       Read registry value")
        print("  reg_write <h> <p> <n> <t> <v> Write registry value")
        print("  call <tool_name> <json>    Generic MCP tool call")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "health":
        h = get_health()
        print(json.dumps(h, indent=2))

    elif cmd == "status":
        res = post_tool("remote_status", {})
        print(res.get("result", res.get("error", "")))

    elif cmd == "exec":
        if len(sys.argv) < 3:
            print("Error: command string required.")
            sys.exit(1)
        command_str = sys.argv[2]
        timeout_sec = int(sys.argv[3]) if len(sys.argv) > 3 else 120
        shell = sys.argv[4] if len(sys.argv) > 4 else "powershell"
        # Always use cmd_b64 for zero escaping issues
        b64 = base64.b64encode(command_str.encode("utf-8")).decode("ascii")
        res = post_tool("remote_run_command", {"cmd_b64": b64, "command_b64": b64, "command": command_str, "timeout_seconds": timeout_sec, "timeout_ms": timeout_sec * 1000, "shell": shell})
        if res.get("success"):
            r = res["result"]
            if isinstance(r, str):
                try:
                    r = json.loads(r)
                except Exception:
                    pass
            if isinstance(r, dict):
                if r.get("stdout"):
                    print(r["stdout"].strip())
                if r.get("exit_code", 0) != 0 and r.get("stderr"):
                    print(f"[STDERR]\n{r['stderr'].strip()}", file=sys.stderr)
            else:
                print(r)
        else:
            print(f"ERROR: {res.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "script":
        if len(sys.argv) < 3:
            print("Usage: bridge_cli.py script <path_to_script> [timeout_seconds]")
            sys.exit(1)
        script_path = sys.argv[2]
        timeout_sec = int(sys.argv[3]) if len(sys.argv) > 3 else 120
        with open(script_path, "r", encoding="utf-8") as f:
            script_content = f.read()

        # If script is larger than 8 KB, upload to temporary file on PC2 to avoid 32 KB CreateProcess limit
        if len(script_content) > 8192:
            remote_tmp = "C:\\Users\\Sea\\AppData\\Local\\Temp\\_bridge_script.ps1"
            up_res = post_tool("remote_upload_file", {"local_path": script_path, "remote_path": remote_tmp})
            if not up_res.get("success"):
                print(f"ERROR: Failed to stage script to remote PC2: {up_res.get('error')}", file=sys.stderr)
                sys.exit(1)
            direct_cmd = f'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{remote_tmp}"'
        else:
            enc_b64 = base64.b64encode(script_content.encode("utf-16le")).decode("ascii")
            direct_cmd = f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc_b64}"

        b64 = base64.b64encode(direct_cmd.encode("utf-8")).decode("ascii")
        res = post_tool("remote_run_command", {"cmd_b64": b64, "command_b64": b64, "command": direct_cmd, "timeout_seconds": timeout_sec, "shell": "direct"})
        if res.get("success"):
            r = res["result"]
            if isinstance(r, str):
                try:
                    r = json.loads(r)
                except Exception:
                    pass
            if isinstance(r, dict):
                if r.get("stdout"):
                    print(r["stdout"].strip())
                if r.get("exit_code", 0) != 0 and r.get("stderr"):
                    print(f"[STDERR]\n{r['stderr'].strip()}", file=sys.stderr)
            else:
                print(r)
        else:
            print(f"ERROR: {res.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "logs":
        lvl = sys.argv[2] if len(sys.argv) > 2 else "INFO"
        res = post_tool("remote_get_logs", {"min_level": lvl})
        print(res.get("result", res.get("error", "")))

    elif cmd == "sysinfo":
        res = post_tool("remote_sysinfo", {})
        print(res.get("result", res.get("error", "")))

    elif cmd == "telemetry":
        res = post_tool("remote_telemetry", {})
        print(res.get("result", res.get("error", "")))

    elif cmd in ("telemetry-history", "history"):
        res = post_tool("remote_telemetry_history", {})
        print(res.get("result", res.get("error", "")))

    elif cmd in ("drift-status", "drift"):
        res = post_tool("remote_drift_status", {})
        print(res.get("result", res.get("error", "")))

    elif cmd in ("kiosk-status", "kiosk"):
        res = post_tool("remote_kiosk_status", {})
        print(res.get("result", res.get("error", "")))

    elif cmd == "kiosk-restart":
        force = True
        target = sys.argv[2] if len(sys.argv) > 2 else ""
        res = post_tool("remote_kiosk_restart", {"force": force, "target": target})
        print(res.get("result", res.get("error", "")))

    elif cmd == "kiosk-config":
        enabled = sys.argv[2].lower() in ("true", "1", "yes") if len(sys.argv) > 2 else True
        auto_relaunch = sys.argv[3].lower() in ("true", "1", "yes") if len(sys.argv) > 3 else False
        target = sys.argv[4] if len(sys.argv) > 4 else "chrome.exe"
        res = post_tool("remote_kiosk_configure", {"enabled": enabled, "auto_relaunch_on_crash": auto_relaunch, "target": target})
        print(res.get("result", res.get("error", "")))

    elif cmd in ("update-agent", "upgrade"):
        bin_path = sys.argv[2] if len(sys.argv) > 2 else os.path.abspath("e:\\PROJECT PET RIFT\\BridgeWindows\\agent.exe")
        res = post_tool("remote_update_agent", {"agent_binary_path": bin_path})
        print(res.get("result", res.get("error", "")))

    elif cmd == "find":
        if len(sys.argv) < 4:
            print("Usage: bridge_cli.py find <root_dir> <pattern> [max_results] [max_depth]")
            sys.exit(1)
        root = sys.argv[2]
        pattern = sys.argv[3]
        max_res = int(sys.argv[4]) if len(sys.argv) > 4 else 100
        max_depth = int(sys.argv[5]) if len(sys.argv) > 5 else 6
        res = post_tool("remote_find_file", {"root": root, "pattern": pattern, "max_results": max_res, "max_depth": max_depth})
        print(res.get("result", res.get("error", "")))

    elif cmd == "trim":
        res = post_tool("remote_trim_memory", {})
        print(res.get("result", res.get("error", "")))

    elif cmd == "reg_read":
        if len(sys.argv) < 5:
            print("Usage: bridge_cli.py reg_read <hive> <path> <name>")
            sys.exit(1)
        hive = sys.argv[2]
        path = sys.argv[3]
        name = sys.argv[4]
        res = post_tool("remote_registry_read", {"hive": hive, "subkey": path, "path": path, "value_name": name, "name": name})
        print(res.get("result", res.get("error", "")))

    elif cmd == "reg_write":
        if len(sys.argv) < 7:
            print("Usage: bridge_cli.py reg_write <hive> <path> <name> <type> <value>")
            sys.exit(1)
        hive = sys.argv[2]
        path = sys.argv[3]
        name = sys.argv[4]
        v_type = sys.argv[5]
        v_val = sys.argv[6]
        res = post_tool("remote_registry_write", {
            "hive": hive, "subkey": path, "path": path,
            "value_name": name, "name": name,
            "reg_type": v_type, "value_type": v_type,
            "value_str": str(v_val), "value_int": int(v_val) if v_val.isdigit() else 0
        })
    elif cmd == "upload":
        if len(sys.argv) < 4:
            print("Usage: bridge_cli.py upload <local_path> <remote_path>")
            sys.exit(1)
        local_p = sys.argv[2]
        remote_p = sys.argv[3]
        res = post_tool("remote_upload_file", {"local_path": local_p, "remote_path": remote_p})
        print(res.get("result", res.get("error", "")))

    elif cmd == "download":
        if len(sys.argv) < 4:
            print("Usage: bridge_cli.py download <remote_path> <local_path>")
            sys.exit(1)
        remote_p = sys.argv[2]
        local_p = sys.argv[3]
        res = post_tool("remote_download_file", {"remote_path": remote_p, "local_path": local_p})
        print(res.get("result", res.get("error", "")))

    elif cmd == "call":
        if len(sys.argv) < 3:
            print("Usage: bridge_cli.py call <tool_name> [json_args]")
            sys.exit(1)
        tool_name = sys.argv[2]
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        res = post_tool(tool_name, args)
        print(json.dumps(res, indent=2, ensure_ascii=False))

    elif cmd in ("live", "monitor"):
        import time
        last_seq = 0
        print("\033[96m[LIVE MONITOR START]\033[0m Streaming real-time telemetry and logs from PC2 (Press Ctrl+C to stop)...")
        try:
            while True:
                # 1. Ping / Telemetry
                t_res = post_tool("remote_telemetry", {})
                if t_res.get("success"):
                    tr = json.loads(t_res.get("result", "{}"))
                    cpu = tr.get("cpu_load_pct", 0)
                    ram_mb = int(tr.get("ram_avail_bytes", 0) / (1024 * 1024))
                    gpu_t = tr.get("gpu_temp_c", "N/A")
                    gpu_clk = tr.get("gpu_engine_clock_mhz", "N/A")
                    gpu_act = tr.get("gpu_activity_pct", "N/A")
                    now_str = time.strftime("%H:%M:%S")
                    print(f"\r\033[1;92m[{now_str}]\033[0m CPU: \033[1;93m{cpu:4.1f}%\033[0m | RAM Free: \033[1;96m{ram_mb} MB\033[0m | GPU: \033[1;95m{gpu_t}°C\033[0m (SCLK: {gpu_clk} MHz, Load: {gpu_act}%)", end="", flush=True)

                # 2. Check logs for new entries
                l_res = post_tool("remote_get_logs", {"min_level": "DEBUG"})
                if l_res.get("success"):
                    lr = json.loads(l_res.get("result", "{}"))
                    logs = lr.get("logs", [])
                    new_logs = [entry for entry in logs if entry.get("seq", 0) > last_seq]
                    if new_logs:
                        print()
                        for entry in new_logs:
                            last_seq = max(last_seq, entry.get("seq", 0))
                            lvl = entry.get("level", "INFO")
                            clr = "\033[92m" if lvl == "INFO" else ("\033[93m" if lvl == "WARN" else ("\033[91m" if lvl == "ERROR" else "\033[90m"))
                            print(f"  {clr}[{lvl:<5}]\033[0m #{entry.get('seq')}: {entry.get('message')}")
                    elif not last_seq and logs:
                        last_seq = max(entry.get("seq", 0) for entry in logs)
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n[LIVE MONITOR STOPPED]")

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
