#!/usr/bin/env python3
"""Live test: Python reference agent <-> bridge (stdlib only, loopback).

Spawns agents/agent_reference.py against an in-process bridge on port 9891
and exercises ping, telemetry, run_command, file write/read/hash/list.
"""
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def run_tests():
    from bridge_mcp import bridge, handle_tool_call
    passes = 0
    total = 0

    def check(name, ok, details=""):
        nonlocal passes, total
        total += 1
        passes += 1 if ok else 0
        print(("PASS " if ok else "FAIL ") + name + (" " + details if details else ""))

    bridge.port = 9891
    bridge.token = "RefAgentTest2026!"
    bridge.start_server()
    tmp = tempfile.mkdtemp(prefix="refagent-")
    with open(os.path.join(tmp, "agent.provision"), "w") as f:
        f.write("host=127.0.0.1\nport=9891\ntoken=RefAgentTest2026!\nagent-id=PY-REF-TEST\n")
    agent = subprocess.Popen([sys.executable, os.path.join(HERE, "agents", "agent_reference.py")],
                             cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ok = False
        for _ in range(60):
            if bridge.list_agents():
                ok = True
                break
            time.sleep(0.5)
        check("reference agent connects with sidecar (zero CLI args)", ok)
        if not ok:
            return False
        ping = bridge.send_rpc("sys.ping", {}, agent_id="PY-REF-TEST")
        check("sys.ping answers", ping.get("result", {}).get("pong") is True, json.dumps(ping)[:100])
        tele = json.loads(handle_tool_call("remote_telemetry", {}, agent_id="PY-REF-TEST"))
        check("telemetry reports this box", tele.get("hostname", "") != "", json.dumps(tele)[:80])
        out = json.loads(handle_tool_call("remote_run_command", {"command": "echo ref-ok"},
                                          agent_id="PY-REF-TEST"))
        check("run_command executes", out.get("exit_code") == 0 and "ref-ok" in out.get("stdout", ""),
              json.dumps(out)[:100])
        probe = os.path.join(tmp, "probe.txt")
        w = json.loads(handle_tool_call("remote_write_file", {"path": probe, "content": "hello-ref"},
                                        agent_id="PY-REF-TEST"))
        check("write file", "file_sha256" in w.get("result", {}), json.dumps(w)[:100])
        v = json.loads(handle_tool_call("remote_view_file", {"path": probe}, agent_id="PY-REF-TEST"))
        check("read file round-trips", v.get("content") == "hello-ref", json.dumps(v)[:80])
        h = bridge.send_rpc("fs.hash", {"path": probe}, agent_id="PY-REF-TEST")
        check("hash matches", h.get("result", {}).get("sha256") == w["result"]["file_sha256"])
        ures = agent.poll() is None
        check("agent stays connected", ures)
    finally:
        agent.terminate()
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill()
    print("====================================================")
    print("  ReferenceAgent: %d/%d Passed" % (passes, total))
    print("====================================================")
    return passes == total


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
