#!/usr/bin/env python3
"""
Automated End-to-End Test Suite for BridgeWindows v4.0.0
Tests local agent.exe <---> bridge_mcp.py interaction across all features:
RPC, telemetry, structured logs, bidirectional file sync, hot self-update,
and v4 multi-agent routing (second PC visible + addressable, ambiguity rejected).
"""

import sys
import os
import subprocess
import time
import json
import hashlib
import shutil

def run_tests():
    print("====================================================")
    print("  BridgeWindows Automated End-to-End Test Suite v4.0")
    print("====================================================")

    # 1. Compile agent.exe if not present
    print("[TEST] Compiling agent.exe...")
    subprocess.run(["cmd.exe", "/c", "build_all.bat"], check=True)

    # 2. Start bridge server in background
    from bridge_mcp import RemoteAgentBridge, handle_tool_call, bridge, get_master_lan_ips

    test_port = 9889
    bridge.port = test_port
    bridge.token = "BridgeSecret2026!"
    bridge.start_server()
    print(f"[TEST] Bridge server listening on port {test_port}")

    # 3. Spawn agent.exe pointing to test_port
    print("[TEST] Launching initial agent.exe...")
    # NOTE: DEVNULL, never PIPE — agent_log() printf+fflush's every RPC and an
    # undrained pipe fills up mid-suite, blocking the agent's main loop (wedge).
    agent_proc = subprocess.Popen([
        os.path.abspath("agent.exe"),
        "--host", "127.0.0.1",
        "--port", str(test_port),
        "--token", "BridgeSecret2026!",
        "--agent-id", "TESTE2E",
        "--headless"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for connection
    connected = False
    for _ in range(30):
        time.sleep(0.2)
        if bridge.is_connected:
            connected = True
            break

    if not connected:
        agent_proc.terminate()
        print("[FAIL] Agent failed to connect within 6 seconds!")
        return False

    print("[PASS] Agent connected successfully!")

    passes = 0
    total = 0

    def check(test_name, success, details=""):
        nonlocal passes, total
        total += 1
        if success:
            passes += 1
            print(f"  [PASS] {test_name} {details}")
        else:
            print(f"  [FAIL] {test_name} {details}")

    # Test 1: remote_status
    res = json.loads(handle_tool_call("remote_status", {}))
    check("remote_status", res.get("status") == "connected", f"(version={res.get('agent_version')}, latency={res.get('round_trip_latency_ms')}ms)")

    # Test 2: remote_network_helper
    res = json.loads(handle_tool_call("remote_network_helper", {}))
    check("remote_network_helper", len(res.get("detected_lan_ips", [])) > 0, f"(primary={res.get('primary_ip')}, IPs={res.get('detected_lan_ips')})")

    # Test 3: remote_telemetry
    res = json.loads(handle_tool_call("remote_telemetry", {}))
    check("remote_telemetry", res.get("ram_total_bytes", 0) > 0,
          f"(CPU={res.get('cpu_load_percent')}%, RAM={res.get('ram_avail_mb')}MB avail / {res.get('ram_total_mb')}MB, IO={res.get('io_read_kb_sec')} KB/s read, RTT={res.get('round_trip_ms')}ms)")

    # Test 4: remote_get_logs
    res = json.loads(handle_tool_call("remote_get_logs", {"min_level": "DEBUG"}))
    logs = res.get("logs", [])
    check("remote_get_logs", len(logs) > 0, f"({len(logs)} entries in circular log ring)")

    # Test 5: remote_run_command (cmd)
    res = json.loads(handle_tool_call("remote_run_command", {"command": "echo BridgeWindowsTestOK", "shell": "cmd"}))
    check("remote_run_command (cmd)", res.get("exit_code") == 0 and "BridgeWindowsTestOK" in res.get("stdout", ""), f"(exit_code={res.get('exit_code')})")

    # Test 6: remote_run_command (powershell)
    res = json.loads(handle_tool_call("remote_run_command", {"command": "Write-Output 'PSTest42'", "shell": "powershell"}))
    check("remote_run_command (powershell)", res.get("exit_code") == 0 and "PSTest42" in res.get("stdout", ""))

    # Test 7: remote_write_file & remote_view_file
    test_file = os.path.abspath("test_dummy.txt")
    write_res = json.loads(handle_tool_call("remote_write_file", {"path": test_file, "content": "Hello Remote Windows 10!"}))
    check("remote_write_file", write_res.get("result", {}).get("bytes_written", 0) > 0, f"(chunk_sha={write_res.get('result', {}).get('chunk_sha256')[:10]}...)")

    read_res = json.loads(handle_tool_call("remote_view_file", {"path": test_file}))
    check("remote_view_file", read_res.get("content") == "Hello Remote Windows 10!")

    # Test 8: remote_replace_file_content
    patch_res = json.loads(handle_tool_call("remote_replace_file_content", {
        "path": test_file,
        "target": "Windows 10",
        "replacement": "Windows 10 x86 Super Fast"
    }))
    check("remote_replace_file_content", patch_res.get("result", {}).get("replacements", 0) > 0)

    read_res2 = json.loads(handle_tool_call("remote_view_file", {"path": test_file}))
    check("verify patched content", read_res2.get("content") == "Hello Remote Windows 10 x86 Super Fast!")

    # Test 9: remote_list_directory
    list_res = json.loads(handle_tool_call("remote_list_directory", {"path": os.path.abspath(".")}))
    entries = list_res.get("result", {}).get("entries", [])
    has_agent = any(e.get("name") == "agent.exe" for e in entries)
    check("remote_list_directory", has_agent, f"({len(entries)} entries found)")

    # Test 10: remote_upload_file with CNG SHA-256 verification
    upload_src = os.path.abspath("test_upload_source.bin")
    upload_dst = os.path.abspath("test_upload_dest.bin")
    test_bytes = os.urandom(300 * 1024)  # 300 KB to test multi-chunk transfer
    with open(upload_src, "wb") as f:
        f.write(test_bytes)

    up_res = json.loads(handle_tool_call("remote_upload_file", {
        "local_path": upload_src,
        "remote_path": upload_dst
    }))
    check("remote_upload_file (multi-chunk with CNG hash)", up_res.get("integrity_verified") is True, f"(bytes={up_res.get('bytes_uploaded')})")

    # Test 11: remote_download_file with SHA-256 verification
    dn_dst = os.path.abspath("test_download_received.bin")
    dn_res = json.loads(handle_tool_call("remote_download_file", {
        "remote_path": upload_dst,
        "local_path": dn_dst
    }))
    dn_ok = dn_res.get("integrity_verified") is True and os.path.getsize(dn_dst) == len(test_bytes)
    check("remote_download_file (multi-chunk with CNG hash)", dn_ok, f"(bytes={dn_res.get('bytes_downloaded')})")

    # Clean temporary files
    for p in [upload_src, upload_dst, dn_dst]:
        if os.path.exists(p): os.remove(p)

    # Test 12: remote_sync_directory (push mode)
    sync_src_dir = os.path.abspath("test_sync_src")
    sync_dst_dir = os.path.abspath("test_sync_dst")
    os.makedirs(os.path.join(sync_src_dir, "sub"), exist_ok=True)
    with open(os.path.join(sync_src_dir, "file1.txt"), "w") as f: f.write("Sync File 1 Content")
    with open(os.path.join(sync_src_dir, "sub", "file2.txt"), "w") as f: f.write("Sync File 2 Subdir Content")

    sync_res = json.loads(handle_tool_call("remote_sync_directory", {
        "local_path": sync_src_dir,
        "remote_path": sync_dst_dir,
        "mode": "push"
    }))
    check("remote_sync_directory (recursive push)", sync_res.get("files_transferred") == 2, f"({sync_res.get('files_transferred')} files synced)")

    # Clean sync dirs
    shutil.rmtree(sync_src_dir, ignore_errors=True)
    shutil.rmtree(sync_dst_dir, ignore_errors=True)

    # Test 13: remote_process_list
    proc_res = json.loads(handle_tool_call("remote_process_list", {}))
    procs = proc_res.get("result", {}).get("processes", [])
    has_my_agent = any(p.get("pid") == agent_proc.pid for p in procs)
    check("remote_process_list", has_my_agent, f"({len(procs)} processes, found agent.exe PID={agent_proc.pid})")

    # Test 14: remote_process_priority
    prio_res = json.loads(handle_tool_call("remote_process_priority", {"pid": agent_proc.pid, "priority": "above_normal"}))
    check("remote_process_priority", prio_res.get("result", {}).get("updated") is True)

    # Test 15: remote_screenshot
    shot_path = os.path.abspath("test_screen.bmp")
    shot_res = json.loads(handle_tool_call("remote_screenshot", {"save_path": shot_path}))
    shot_ok = os.path.isfile(shot_path) and os.path.getsize(shot_path) > 1000
    check("remote_screenshot", shot_ok, f"({shot_res.get('width')}x{shot_res.get('height')}, size={os.path.getsize(shot_path) if shot_ok else 0} bytes)")
    if os.path.isfile(shot_path):
        os.remove(shot_path)

    # Test 16: remote_delete_file
    del_res = json.loads(handle_tool_call("remote_delete_file", {"path": test_file}))
    check("remote_delete_file", del_res.get("result", {}).get("deleted") is True and not os.path.exists(test_file))

    # Test 17: multi-agent routing (v4) — second PC visible, addressable, ambiguity rejected
    print("[TEST] Spawning second agent.exe (second-PC simulation)...")
    agent2_proc = subprocess.Popen([
        os.path.abspath("agent.exe"),
        "--host", "127.0.0.1",
        "--port", str(test_port),
        "--token", "BridgeSecret2026!",
        "--agent-id", "TESTE2E-B",
        "--headless"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    two = False
    for _ in range(30):
        time.sleep(0.2)
        if len(bridge.list_agents()) == 2:
            two = True
            break
    check("second agent registered (2 PCs visible)", two)
    st2 = json.loads(handle_tool_call("remote_status", {}))
    check("remote_status lists both agents", st2.get("count") == 2,
          f"(agents={[a.get('agent_id') for a in st2.get('agents', [])]})")
    amb = json.loads(handle_tool_call("remote_telemetry", {}))
    check("ambiguous call without agent rejected", "Ambiguous" in json.dumps(amb))
    p1 = bridge.send_rpc("sys.ping", timeout=5.0, agent_id="TESTE2E")
    p2 = bridge.send_rpc("sys.ping", timeout=5.0, agent_id="TESTE2E-B")
    check("routed sys.ping reaches each PC",
          "error" not in p1 and "error" not in p2
          and "version" in p1.get("result", {}) and "version" in p2.get("result", {}))
    agent2_proc.terminate()
    try:
        agent2_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        agent2_proc.kill()

    # Test 18: Hot Atomic Self-Update (remote_update_agent) with OS/arch auto-select:
    # no agent_binary_path -> master must pick agents/agent-win-x86.exe itself.
    print("[TEST] Testing hot atomic self-update via remote_update_agent (auto-select)...")
    with open(os.path.abspath(os.path.join("agents", "agent-win-x86.exe")), "rb") as f:
        expected_sha = hashlib.sha256(f.read()).hexdigest()
    update_res = json.loads(handle_tool_call("remote_update_agent", {
        "timeout_seconds": 15.0
    }))
    update_ok = (update_res.get("updated") is True and update_res.get("reconnected") is True
                 and update_res.get("sha256") == expected_sha)
    check("remote_update_agent (auto-select + selftest + MoveFileExW + watchdog + reconnect)", update_ok,
          f"(old_pid={update_res.get('old_pid')}, new_pid={update_res.get('new_pid')}, version={update_res.get('agent_version')}, auto_sha_match={update_res.get('sha256') == expected_sha})")

    # Clean shutdown of newly spawned agent
    print("[TEST] Terminating upgraded agent.exe...")
    new_pid = update_res.get("new_pid")
    if new_pid:
        subprocess.run(["taskkill", "/F", "/PID", str(new_pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        agent_proc.terminate()
    except Exception:
        pass

    print("====================================================")
    print(f"  Test Results: {passes}/{total} Passed ({int(passes/total*100)}%)")
    print("====================================================")
    return passes == total

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
