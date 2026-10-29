#!/usr/bin/env python3
"""Focused: ghost-slot takeover on duplicate handshake (no sockets).

A crashed agent can leave TCP half-open (alive, frozen last_seen), rejecting
its replacement forever -> the client spams reconnects. A same-id handshake
may steal the slot only after TAKEOVER_AFTER_S of silence.
"""
import os
import sys
import time
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from bridge_mcp import RemoteAgentBridge, TAKEOVER_AFTER_S


def run_tests():
    passes = 0
    total = 0

    def check(name, ok, details=""):
        nonlocal passes, total
        total += 1
        passes += 1 if ok else 0
        print(("PASS " if ok else "FAIL ") + name + (" " + details if details else ""))

    def ghost(last_seen_ago):
        closed = []
        sock = SimpleNamespace(close=lambda: closed.append(True))
        return SimpleNamespace(agent_id="GHOST", alive=True,
                               last_seen=time.time() - last_seen_ago,
                               sock=sock), closed

    b = RemoteAgentBridge()
    g, closed = ghost(TAKEOVER_AFTER_S + 30)
    b.agents["GHOST"] = g
    check("stale ghost slot is stolen", b._takeover_stale("GHOST") is True)
    check("ghost slot freed", "GHOST" not in b.agents)
    check("ghost marked dead and socket closed", g.alive is False and closed == [True])

    b2 = RemoteAgentBridge()
    live, _ = ghost(2)
    b2.agents["LIVE"] = live
    check("live duplicate is kept (no steal)", b2._takeover_stale("LIVE") is False)
    check("live slot untouched", b2.agents.get("LIVE") is live and live.alive is True)

    check("unknown id steals nothing", b2._takeover_stale("NOPE") is False)

    print("====================================================")
    print("  Takeover: %d/%d Passed" % (passes, total))
    print("====================================================")
    return passes == total


if __name__ == "__main__":
    sys.exit(0 if run_tests() else 1)
