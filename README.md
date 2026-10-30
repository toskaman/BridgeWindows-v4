# BridgeWindows v4.0.0 (multi-PC)

Remote operation bridge: the **master PC** administers **up to 8 Windows PCs simultaneously** over the LAN through authenticated reverse-TCP agents (protocol v4: mutual auth + session MACs).

## Topology

```
+---------------------------------------------+
| PC MAITRE                                   |
| - bridge_mcp.py (MCP stdio + TCP :9876)     |
| - bridge_daemon.py (HTTP /tool + /health)   |
| - bridge_cli.py --agent <id>                |
+---------------------------------------------+
        ^                        ^
        | reverse TCP v4         | reverse TCP v4
        v                        v
+---------------+        +---------------+
| PC-1          |        | PC-2 .. PC-8  |
| agent.exe     |  ...   | agent.exe     |
| --agent-id    |        | --agent-id    |
|   PC-1        |        |   PC-N        |
+---------------+        +---------------+
```

## v4 authentication (mutual, no secret on wire)

1. Agent dials master, sends `agent.hello` with `agent_id` + `agent_nonce` (never the PSK).
2. Master replies `auth.challenge` with `master_nonce`.
3. Agent proves PSK knowledge: `HMAC(psk, agent_nonce || master_nonce || agent_id)`.
4. Master confirms with the mirrored HMAC (agent verifies the master too).
5. Session key `SHA256(psk || agent_nonce || master_nonce)`; every frame after that is a `{"v":4,"body_b64":...,"mac":...}` envelope with a per-frame session MAC.

Routing is explicit: with 2+ agents connected, any call without `agent=<id>` is rejected as ambiguous — never broadcast, never guessed. Single agent auto-routes.

## Deploy an agent (each remote PC)

Pick the binary for the PC from `agents/` (see matrix below), copy it over, then
(prefer the env var: `--token` shows the PSK in the process list):

```cmd
set BRIDGE_PSK=<YOUR_PSK>
agent.exe --host <MASTER_LAN_IP> --port 9876 --agent-id <PC_NAME>
```

```sh
BRIDGE_PSK=<YOUR_PSK> ./agent-linux-x64 --host <MASTER_IP> --port 9876 --agent-id <NAME>
```

PSK and `--agent-id` are both required; the agent refuses to run without them (exit 2).
`--selftest` checks SHA-256/HMAC against RFC 4231 vectors (identical output on all OSes).
`--headless` disables the status window (Linux is always headless).

## Status window (Windows agent) + terminal orb (Linux)

The agent shows a **voice-style presence orb**: a 3D particle sphere with a glowing
core and Siri-style ribbons (shared renderer in `orb_core.h`). It breathes when idle
(cyan/violet), swirls violet with orbiting arcs while connecting, and flares
magenta on each RPC; it pulses on every state change and rides network traffic.
Under it: a connection chip, live tiles (uptime, session, RPC count, network,
CPU/RAM, reconnects), the colour-coded activity feed, and Reconnect / Quit.

- **Windows** (`gui.c`, GDI, same window on x86 / x64 / arm64): orb drawn into a 32-bit
  DIB and blitted each frame; no desktop (service/session 0) or `--headless` → console mode.
- **Linux** (`orb_hud.h`): the same orb drawn in the terminal with unicode half-blocks and
  24-bit colour, in a fixed box above the scrolling log region (TTY only; `--headless`/no TTY → plain logs).

See `agent_gui.png`.

## Build matrix (`build_all.bat` → `agents/` + `SHA256SUMS`)

| file | target | toolchain | verified |
|---|---|---|---|
| `agent-win-x86.exe` | Windows 32-bit | MinGW i686 | selftest + e2e 23/23 |
| `agent-win-x64.exe` | Windows 64-bit | MinGW x86_64 | selftest |
| `agent-win-arm64.exe` | Windows ARM64 | zig | compiles (no ARM64 HW here) |
| `agent-linux-x64` | Linux x86_64 (static musl) | zig | selftest + live v4 session under WSL kernel |
| `agent-linux-arm64` | Linux ARM64 (static musl) | zig | compiles (no ARM64 HW here) |

`remote_update_agent` with no `agent_binary_path` auto-picks from `agents/` by the
target's reported OS/arch (explicit path still wins; ambiguous multi-agent calls
are rejected).

## Master

```cmd
set OPENBRIDGE_PSK=<YOUR_PSK>
python bridge_mcp.py --host 0.0.0.0 --port 9876 --max-agents 8
```

`remote_status` with no args lists all connected PCs; pass `agent=<id>` to target one. `bridge_cli.py --agent <id> <tool> ...` for CLI use.

## Tests (27 Oct 2026, all green)

- `python -m unittest test_multiagent -v` → **10/10** (fake agents, loopback: registry, mutual auth, routing, ambiguity, no-PSK-on-wire).
- `python -u test_bridge.py` → **23/23 (100%)** with 2 real `agent.exe`: RPC, telemetry, logs, exec cmd/powershell, file R/W/patch/delete, SHA-256 chunk transfers up+down, recursive sync, process list/priority, screenshot, **2-PC routing (Test 17)**, **hot self-update + reconnect (Test 18)**.
- OpenBridge `WindowsBridge` speaks v4 too (single-agent + read-only allowlist): `tests/runtime/test_windows_bridge.py` 7/7, full OpenBridge suite 376/376, real agent.exe interop verified.

Note: the e2e spawns agents with pipes to DEVNULL — the agent `printf`-logs every RPC and an undrained pipe wedges it mid-suite (harness flaw, fixed in test).

## Known limits (honest)

- 2-PC LAN proof done 27 Oct 2026 (~23:00): DESKTOP-8AQOOHB (.9) + WIN-EEIP61A9AP8 (.33) both on v4 agent.exe, both served by one daemon, routed RPCs verified.
- No-PSK-on-wire proof 28 Oct 2026: `evidence_2026-10-28_nopsk.pcap` (opens in Wireshark) — 2 real agents through a logging proxy: handshake + routed ping/diag/file-write, 4002 payload bytes, PSK and `token` key absent, nonces + `body_b64`/`mac` envelopes present. Scratch ports 9878/9879, documented as-is.
- `secure_v4.inc` (X25519 pairing design) deprecated, not shipped — see note in file.
- Self-update reconnect is a retry storm (~350 incoming connections); works but noisy.
- Screenshot BMP is ~15 MB per capture on ultrawide; file chunks are 256 KB.

Fix (28 Oct ~00:30): nested tool calls (update/sync staging) now inherit the outer agent target instead of resetting to ambiguous with 2+ agents connected (handle_tool_call ctx inheritance + regression test 	est_nested_tool_call_inherits_outer_agent_target, 11/11). Both physical PCs updated over the air to the GUI agent (auto-select by OS/arch, hash-verified before swap).
