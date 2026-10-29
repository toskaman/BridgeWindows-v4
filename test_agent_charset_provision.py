#!/usr/bin/env python3
"""Focused regression: agent special characters + zero-config sidecar.

1. No raw non-ASCII bytes in agent sources (all glyphs are \\xNN escapes,
   so the build does not depend on the editor/compiler codepage).
2. gui.c draws text wide (DrawTextW) and never uses the U+25CF glyph
   (missing from Tahoma/XP era); the status dot is drawn.
3. Console titles with UTF-8 glyphs go through set_title_utf8.
4. agent.provision sidecar: host/port/token/agent-id with zero CLI args.
"""
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = ["agent.c", "agent_linux.c", "gui.c", "gui.h", "orb_core.h",
           "orb_hud.h", "protocol.h"]


def run_tests():
    passes = 0
    total = 0

    def check(name, ok, details=""):
        nonlocal passes, total
        total += 1
        passes += 1 if ok else 0
        print(("PASS " if ok else "FAIL ") + name + (" " + details if details else ""))

    src = {}
    for f in SOURCES:
        with open(os.path.join(HERE, f), "rb") as fh:
            src[f] = fh.read()

    raw = [(f, i) for f, b in src.items() for i, x in enumerate(b) if x >= 0x80]
    check("no raw non-ASCII bytes in agent sources", not raw,
          "" if not raw else "(first: %s offset %d)" % (raw[0][0], raw[0][1]))

    gui = src["gui.c"].decode("ascii", errors="replace")
    check("gui.c draws text wide (DrawTextW)", "DrawTextW" in gui)
    check("gui.c keeps no U+25CF glyph escape", "\\xE2\\x97\\x8F" not in gui)
    check("status dot is drawn (Ellipse)", "Ellipse(" in gui)

    agent = src["agent.c"].decode("ascii", errors="replace")
    ansi_titles = [ln.strip()[:80] for ln in agent.splitlines()
                   if "SetConsoleTitleA(" in ln and "set_title_utf8" not in ln]
    non_ascii_calls = [ln for ln in ansi_titles if any(ord(c) > 127 for c in ln)]
    check("SetConsoleTitleA call sites are ASCII-only", not non_ascii_calls,
          "" if not non_ascii_calls else "(%s)" % non_ascii_calls[0])
    check("set_title_utf8 helper exists", "static void set_title_utf8" in agent)

    with open(os.path.join(HERE, "agent.manifest"), "rb") as fh:
        manifest = fh.read().decode("utf-8")
    check("manifest demands admin (requireAdministrator)",
          'level="requireAdministrator"' in manifest)
    with open(os.path.join(HERE, "agent_x64.exe"), "rb") as fh:
        check("x64 binary embeds requireAdministrator",
              b"requireAdministrator" in fh.read())
    check("runtime self-elevation covers manifest-less builds",
          "ensure_elevated(argc, argv)" in agent and '"runas"' in agent)

    linux = src["agent_linux.c"].decode("ascii", errors="replace")
    for name, body in (("agent.c", agent), ("agent_linux.c", linux)):
        check("%s loads agent.provision sidecar" % name,
              "provision_load()" in body and "agent.provision" in body)
        check("%s error message mentions sidecar" % name,
              "agent.provision sidecar" in body)

    # Functional: zero-config sidecar on the 64-bit Windows agent.
    exe = os.path.join(HERE, "agent_x64.exe")
    if not os.path.exists(exe):
        check("agent_x64.exe present (run build_all.bat first)", False)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            # Negative: no sidecar, no token -> exit 2 naming the sidecar.
            r = subprocess.run([exe, "--headless"], capture_output=True,
                               text=True, cwd=tmp, timeout=30)
            check("no-config run exits 2 and names the sidecar",
                  r.returncode == 2 and "agent.provision sidecar" in r.stderr,
                  "(exit=%s)" % r.returncode)
            # Positive: sidecar with token + unroutable host -> passes the
            # auth gate (no exit 2, stays alive retrying) with zero CLI args.
            with open(os.path.join(tmp, "agent.provision"), "w") as fh:
                fh.write("# zero-config bundle\n"
                         "host = 192.0.2.1\nport=9876\n"
                         "token=SidecarProbeToken\nagent-id=SIDECAR-PROBE\n")
            p = subprocess.Popen([exe, "--headless"], cwd=tmp,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            time.sleep(8)
            alive = p.poll() is None
            check("sidecar run passes the auth gate (alive, no instant exit)",
                  alive, "(exit=%s)" % p.poll())
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

    print("====================================================")
    print("  Charset+Sidecar: %d/%d Passed" % (passes, total))
    print("====================================================")
    return passes == total


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
