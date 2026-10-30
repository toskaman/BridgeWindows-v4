# Sealed transport design (v5) — DESIGN ONLY, not implemented

STATUS (30 Oct 2026): design document. The v4 wire protocol (mutual-HMAC
challenge-response + per-frame session MAC, NO payload encryption) is what
ships. This design is the agreed follow-up; implementing it before the
4 Nov hackathon deadline was judged too risky (C agent incl. the XP legacy
build + Python bridge + migration + QEMU re-verification, with no live
hardware available to test against). Until it ships: trusted home LAN only,
long random PSK (the bridge warns on both at startup).

## Threat model

Protect against a passive LAN observer (reads screenshots, files, commands
today) and an active LAN attacker without the PSK (cannot forge today, must
never be able to decrypt, inject, replay, downgrade or MITM after the change).
The PSK remains the enrollment secret: whoever holds it can already command
the PCs, so PSK compromise is out of scope (rotation procedure below bounds
its lifetime). Endpoint compromise is out of scope.

## Construction (standard pieces only, no custom crypto)

- Handshake: keep the existing mutual-HMAC hello (authentication, agent_id
  binding), then an ephemeral X25519 exchange in both directions. Each side
  MACs the transcript (both ephemeral public keys + both handshake nonces)
  under a PSK-derived confirmation key. The session keys are
  HKDF-SHA256(salt = transcript hash, ikm = X25519 shared secret,
  info = "ob-v5" + direction). An attacker without the PSK learns nothing
  and cannot MITM (confirmation MACs fail closed).
- Record layer: XChaCha20-Poly1305 frames. Nonce = 4-byte direction prefix +
  8-byte per-direction counter (rekey before 2^32 frames; a session never
  lives that long, and re-handshake is cheap). Associated data binds
  agent_id, frame counter and the session id. Replies use the opposite
  direction key. Any MAC failure drops the connection (fail closed, loud log,
  agent backs off and re-handshakes).
- Session binding: the session id = first 16 bytes of the transcript hash;
  RPC receipts quote it, so a response can never be transplanted across
  sessions or agents.
- Rotation: re-handshake every 24 h or 1 GiB, whichever comes first; either
  side may initiate. Revocation = PSK change + bridge restart + agent
  restart; old sessions die with the process (keys are memory-only, wiped
  on free where the platform allows).
- Downgrade prevention: the hello carries `enc-required: true`; a v5 bridge
  refuses v4-plain hellos after the migration window (below), and a v5 agent
  refuses a bridge that answers plain. No silent fallback, ever.

## Primitives (audited, XP-compatible)

- C (all agent builds incl. AGENT_LEGACY_XP): Monocypher (public domain,
  audited) for X25519 + HKDF-SHA256 + XChaCha20-Poly1305. One implementation
  everywhere: no CNG/CryptoAPI dependency for crypto, identical vectors on
  every build. `agent.exe --selftest` asserts the RFC 7748 X25519 vectors,
  RFC 5869 HKDF vectors and RFC 8439 / draft-arciszewski-xchacha vectors.
- Python (bridge): the `cryptography` package if it exposes XChaCha20-Poly1305
  and X25519 at implementation time (verify then; do not assume), else PyNaCl
  (libsodium, same algorithms). The bridge test-suite asserts the same RFC
  vectors plus a cross-implementation handshake against the C agent in CI.

## Migration (no flag day, no silent downgrade)

1. Bridge ships dual-stack: accepts v4-plain AND v5-sealed, with a
   per-agent `channel: plain|sealed` visible in `remote_status` and the logs.
2. Agents upgrade one PC at a time (existing hot self-update path); each
   upgraded agent negotiates v5.
3. Owner flips `--require-sealed` on the bridge once every agent shows
   `sealed`; the bridge then refuses plain hellos loudly.
4. v4-plain code is deleted in the release after the hackathon; the
   plaintext warning (shipped 30 Oct) is deleted with it.

## Test plan (before the design is declared done)

- RFC vectors (C + Python + cross).
- Tamper/replay/reorder/drop/duplication battery on sealed frames.
- MITM proxy without PSK: handshake must fail, nothing decryptable.
- Downgrade battery: v5-vs-plain in both directions refused loudly.
- Rekey + rotation + PSK-change revocation, incl. mid-transfer rotation.
- Full legacy re-proof: XP SP3 + Win7 x86 QEMU guests (fleet rebuild, E:),
  mutual-auth + RPC + screenshots, same bar as the v4 legacy proof.
- Long-run soak: 24 h agent↔bridge with rotation forced every 5 min.

## Non-goals

- Hiding traffic shape/timing (no padding scheme yet).
- Post-quantum key exchange (note for later; X25519 is the pragmatic now).
- Internet-safe exposure: even sealed, the bridge stays LAN-only by default.
