# OpenBridge Agent Wire Protocol (v4)

Source of truth: `agents/agent_reference.py` (PROTOCOL_VERSION `4.0.0`,
pure-stdlib Python 3.9+) with the master side in `bridge_mcp.py` (and mirrored
by `src/adapters/windows_bridge.py` in the
[OpenBridge](https://github.com/toskaman/openbridge) repo). This document
describes the wire format only; it changes no code.

> Dialect note: `auth.challenge` carries `master_nonce` **nested** in
> `params` (`params.master_nonce`). Agents must read the nested field (a
> top-level fallback is tolerated). The C agents match via whole-document key
> search; the reference agent reads `params` explicitly.

## 1. Overview

- Transport: plain TCP. The **agent dials out** (reverse-connect) to the bridge
  listener (default `127.0.0.1:9876`; bridge binds one LAN address, never
  `0.0.0.0`, one agent at a time).
- Layering: length-prefixed JSON frames. The 4-message handshake runs as
  plaintext JSON-RPC inside frames; everything after it runs as
  MAC-authenticated envelopes (`v: 4`) carrying base64 JSON-RPC.
- Direction: after the handshake the bridge sends RPC **requests** and the
  agent sends RPC **replies**. The agent never initiates calls.
- Reference agent serves the core surface (`sys.*`, `exec.run`, `fs.*`,
  `proc.*`, `log.get`, `agent.update`); `reg.*` / `svc.*` / `kiosk.*` answer
  "unsupported on this platform" (Windows agents implement them; the bridge
  allowlists `reg.read` for 5 exact values).
- Reconnect: on any link failure the agent sleeps and retries with backoff
  1 s doubling to 30 s max.

## 2. Framing

```
+------------+----------------------+
| len (4 B)  | JSON payload (len B) |
+------------+----------------------+
```

- `len`: unsigned 32-bit big-endian (`struct.pack("!I", ...)`), JSON UTF-8.
- Every frame body must be a JSON **object**; anything else drops the link.
- Caps differ per side: agent accepts `1 .. 8 MiB` (`MAX_FRAME`, reference
  agent); bridge accepts `<= 1 MiB` and rejects larger with "frame too large".
  Keep requests + replies under 1 MiB.
- Timeouts: TCP connect 10 s; handshake messages 10–15 s; idle session socket
  has no timeout; bridge calls time out after 10 s (`CALL_TIMEOUT`; jobs use
  `timeout_s + 15`).

## 3. Auth / handshake (mutual PSK challenge-response)

PSK provisioning (agent): `--token` CLI flag, else `BRIDGE_PSK` env var, else
`agent.provision` sidecar (`key=value` lines, `-` normalized to `_`) next to
the agent file, then `./agent.provision`. The PSK is never sent, logged, or
returned. `agent_id`: `--agent-id`, else sanitized hostname (`[A-Za-z0-9_-]`,
max 32 chars, first char alnum).

Nonces: `secrets.token_hex(16)` → 32 lowercase hex chars each side.
`hmac_hex(key, *parts)` = hex(HMAC-SHA256(key, utf-8 concat of parts)).

```
Agent -> Bridge  {"jsonrpc":"2.0","method":"agent.hello","params":{
                   "version":"4.0.0","arch":str,"os":"windows"|"macos"|"linux",
                   "pid":int,"agent_id":str,"agent_nonce":str}}
Bridge -> Agent  {"jsonrpc":"2.0","method":"auth.challenge",
                  "params":{"master_nonce":str,"agent_id":str}}
Agent -> Bridge  {"jsonrpc":"2.0","method":"auth.response",
                  "params":{"agent_id":str,
                    "hmac":hmac_hex(psk, agent_nonce, master_nonce, agent_id)}}
Bridge -> Agent  {"jsonrpc":"2.0","method":"auth.confirm",
                  "params":{"hmac":hmac_hex(psk, master_nonce, agent_nonce, agent_id)}}
```

Checks: bridge requires `agent.hello` with valid `agent_id` + 32-hex nonce,
no `token` field, and `version` starting with `4.`; agent requires a 32-char
`master_nonce` and verifies `auth.confirm` with constant-time compare.
Session key (both sides):

```
sesskey = SHA256(psk_bytes + agent_nonce_bytes + master_nonce_bytes)  (32 B)
```

Post-handshake envelope (both directions):

```json
{"v": 4, "body_b64": "<base64 of JSON-RPC object>", "mac": "<hex HMAC-SHA256(sesskey, body_b64-ascii)>"}
```

Any envelope with `v != 4`, missing/invalid MAC, or undecodable body drops
the link ("bad session MAC" / "bad envelope body"). MACs are compared with
`hmac.compare_digest`.

## 4. RPC table (exact method names / params)

Requests: `{"jsonrpc":"2.0","id":rid,"method":str,"params":{...}}`.
Success: `{"jsonrpc":"2.0","id":rid,"result":{...}}`.
Failure: `{"jsonrpc":"2.0","id":rid,"error":{"code":-32001,"message":"<ExcType>: <msg>"}}`
(message truncated to 200 chars).

| Method | Params (exact keys) | Result |
|---|---|---|
| `sys.ping` | `{}` | `{pong:true, version:str, uptime_ms:int}` |
| `sys.diag`, alias `sys.telemetry` | `{}` | `{hostname, version, architecture, cpu_cores, cpu_load_percent, ram_total_bytes, ram_avail_bytes, agent_working_set_bytes:0, io_read_bytes_sec:0, io_write_bytes_sec:0, io_total_read_bytes:0, io_total_write_bytes:0, agent_pid, disks:[{mount,total_bytes,free_bytes}], uptime_seconds}` |
| `exec.run` | `command` (or `cmd`, or `cmd_b64`), `shell`: `"powershell"` (win32 only) \| `"direct"` (no shell) \| default (`cmd.exe /c` on win32, `/bin/sh` elsewhere), `timeout_ms` (or `timeout_seconds`), `cwd` | `{pid, exit_code (-1 on timeout), timed_out:bool, stdout_b64, stderr_b64}`. Default timeout 120 s |
| `fs.read` | `path`, `offset`=0, `length`=1 MiB | `{data_b64, bytes_read, total_size, eof:bool, chunk_sha256}` |
| `fs.write` | `path`, `data_b64`, `append`?, `offset`? (`offset` without `append` opens `r+b`, falls back to `wb`) | `{bytes_written, file_sha256}` |
| `fs.hash` | `path` | `{sha256, size}` |
| `fs.list` | `path` | `{entries:[{name, is_dir, size}]}` sorted by name |
| `fs.mkdir` | `path` | `{created:true}` (`exist_ok=True`) |
| `fs.delete` | `path` | `{deleted:true}` (dir → `rmtree`, else `os.remove`) |
| `proc.list` | `{}` | `{processes:[{pid, ppid, name, working_set_bytes}]}` (`ppid`=0 on Windows) |
| `proc.kill` | `pid:int` | `{killed:true}` (`taskkill /F` on win32, `SIGKILL` elsewhere) |
| `log.get` | `since_seq`=0 | `{logs:[{seq, level, msg}]}` last ≤100 entries above `since_seq`; ring keeps 200, `msg` ≤500 chars |
| `agent.update` | `path` (or `staged_path`) | `{updated:true, relaunching:true}`; current file moved to `*.old`, staged file copied over, `os.execv` relaunch after 1 s |
| `reg.*`, `svc.*`, `kiosk.*` | — | **Error** `ValueError: unsupported on this platform: <method>` on the reference agent |
| anything else | — | **Error** `ValueError: unknown method: <method>` |

Bridge-side policy (`WindowsBridge.call`, `run_job`): only
`sys.ping`, `sys.diag`, `proc.list`, `reg.read` (5 exact allowlisted values:
`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`,
`HKLM\...\Windows NT\CurrentVersion\{ProductName,DisplayVersion,CurrentBuild}`,
`HKLM\SYSTEM\...\0001\HwProfileGuid`) are callable; `exec.run` is reachable
only via the consent-gated `pc_job` primitive as
`{command (1..2000 chars), shell: "cmd"|"powershell", timeout_ms}` with
`timeout_s` 1..600. All other agent methods are never sent by the bridge.

## 5. Error codes

Wire-level (agent RPC replies): single JSON-RPC code **`-32001`** with
`"<ExcType>: <message>"`; common payloads: `ValueError: Missing command or
cmd_b64`, `ValueError: Missing staged update file`,
`ValueError: unsupported on this platform: <method>`,
`ValueError: unknown method: <method>`, plus `OSError`/`FileNotFoundError`
from `fs.*` passthrough.

Link-level (no JSON-RPC reply; the connection drops and the agent backs
off): `handshake rejected`, `master authentication failed`, `bad frame
length`, `frame is not an object`, `bad session MAC` (agent side);
`auth.required: v4 hello with agent_id + agent_nonce`, `incompatible
protocol`, `agent failed authentication`, `frame too large`, `bad envelope
body`, `agent disconnected` (bridge side, kept in `last_error`).

Not wire errors: `PrimitiveError` codes (`NOT_LINKED`, `BLOCKED`,
`NOTHING_TO_UNDO`, `DEVICE_UNAVAILABLE`, …) live one layer up in
`src/runtime/primitives.py` and never appear on the agent socket.

## 6. Minimal client example (stdlib only)

```python
import base64, hashlib, hmac, json, secrets, socket, struct

def frame(sock, obj):
    b = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(b)) + b)

def read_frame(sock):
    (n,) = struct.unpack("!I", sock.recv(4))
    buf = b""
    while len(buf) < n:
        buf += sock.recv(n - len(buf))
    return json.loads(buf)

def hh(key, *parts):
    m = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        m.update(p.encode())
    return m.hexdigest()

psk = b"<shared secret>"
s = socket.create_connection(("127.0.0.1", 9876), timeout=10)
an, aid = secrets.token_hex(16), "PY-AGENT"
frame(s, {"jsonrpc": "2.0", "method": "agent.hello",
          "params": {"version": "4.0.0", "arch": "x86_64", "os": "linux",
                     "pid": 1234, "agent_id": aid, "agent_nonce": an}})
mn = read_frame(s)["params"]["master_nonce"]          # auth.challenge
frame(s, {"jsonrpc": "2.0", "method": "auth.response",
          "params": {"agent_id": aid, "hmac": hh(psk, an, mn, aid)}})
cf = read_frame(s)                                     # auth.confirm
assert hmac.compare_digest(cf["params"]["hmac"], hh(psk, mn, an, aid))
sess = hashlib.sha256(psk + an.encode() + mn.encode()).digest()

def call(method, params=None, rid=1):
    body = base64.b64encode(json.dumps(
        {"jsonrpc": "2.0", "id": rid, "method": method,
         "params": params or {}}).encode()).decode()
    frame(s, {"v": 4, "body_b64": body,
              "mac": hmac.new(sess, body.encode(), hashlib.sha256).hexdigest()})
    env = read_frame(s)
    assert hmac.compare_digest(
        hmac.new(sess, env["body_b64"].encode(), hashlib.sha256).hexdigest(),
        env["mac"])
    return json.loads(base64.b64decode(env["body_b64"]))

print(call("sys.ping"))
```
