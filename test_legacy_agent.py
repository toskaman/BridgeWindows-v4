"""Legacy (XP/Win7-x86) agent build: wire-compatible, XP-loadable.

RED first: fails until agents/agent-win-x86-legacy.exe is built from agent.c
with AGENT_LEGACY_XP (embedded software SHA-256/HMAC instead of CNG --
XP SP3 has no usable SHA-256 provider -- and no Vista+ imports).
"""
import hashlib
import hmac
import os
import re
import struct
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.abspath(__file__))
LEGACY_BIN = os.path.join(REPO, "agents", "agent-win-x86-legacy.exe")

RFC4231_HMAC_SHA256_TC1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
SHA256_SELFTEST = hashlib.sha256(b"selftest").hexdigest()

# DLLs that do not exist (or not inbox) on XP SP3 / stock Win7 SP1.
BANNED_DLLS = ("bcrypt.dll", "api-ms-win-crt", "api-ms-win-core")
# A sample of Vista+ entry points that must never be imported.
BANNED_FNS = (
    "GetTickCount64", "InitializeConditionVariable", "SleepConditionVariableCS",
    "InitOnceExecuteOnce", "FlsAlloc", "GetFinalPathNameByHandle",
    "SetThreadErrorMode", "RegDeleteTree", "RegSetKeyValue", "RegDeleteKeyEx",
    "TaskDialogIndirect", "TaskDialog", "ChangeWindowMessageFilter",
    "BCryptOpenAlgorithmProvider", "BCryptGenRandom", "InetNtop", "inet_ntop",
    "GetAddrInfoEx", "IdnToAscii",
    # Not used by the legacy build (manual TokenGroups walk instead);
    # kept out to minimize API dependencies on XP.
    "CheckTokenMembership",
)


def read_imports(path):
    """Minimal PE32 import-table + subsystem reader (stdlib only)."""
    with open(path, "rb") as f:
        img = f.read()
    assert img[:2] == b"MZ", "not a PE image"
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    assert img[pe:pe + 4] == b"PE\0\0", "bad PE signature"
    machine = struct.unpack_from("<H", img, pe + 4)[0]
    assert machine == 0x14C, "legacy agent must be i386 (x86), got %#x" % machine
    nsec = struct.unpack_from("<H", img, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", img, opt)[0]
    assert magic == 0x10B, "legacy agent must be PE32 (x86)"
    major_sub, minor_sub = struct.unpack_from("<HH", img, opt + 48)
    imp_rva, imp_size = struct.unpack_from("<II", img, opt + 104)
    sections = []
    sh = opt + 224
    for _ in range(nsec):
        vs, vaddr, rawsz, rawptr = struct.unpack_from("<IIII", img, sh + 8)
        sections.append((vaddr, vs, rawptr, rawsz))
        sh += 40

    def rva2off(rva):
        for vaddr, vs, rawptr, rawsz in sections:
            if vaddr <= rva < vaddr + max(vs, rawsz):
                return rawptr + (rva - vaddr)
        raise AssertionError("RVA %08x not in any section" % rva)

    dlls, fns = [], []
    off = rva2off(imp_rva)
    while True:
        ilt, _ts, _fw, name_rva, _iat = struct.unpack_from("<IIIII", img, off)
        if ilt == 0 and name_rva == 0:
            break
        end = img.index(b"\0", rva2off(name_rva))
        dlls.append(img[rva2off(name_rva):end].decode("ascii"))
        thunk = rva2off(ilt)
        while True:
            entry = struct.unpack_from("<I", img, thunk)[0]
            if entry == 0:
                break
            if not entry & 0x80000000:
                nm = rva2off(entry & 0x7FFFFFFF) + 2
                fns.append(img[nm:img.index(b"\0", nm)].decode("ascii"))
            thunk += 4
        off += 20
        if off - rva2off(imp_rva) > imp_size + 20:
            break
    return (major_sub, minor_sub), dlls, fns


def test_legacy_binary_exists():
    assert os.path.isfile(LEGACY_BIN), "build agents/agent-win-x86-legacy.exe first"


def test_selftest_vectors_match():
    p = subprocess.run([LEGACY_BIN, "--selftest"], capture_output=True,
                       text=True, timeout=60)
    assert p.returncode == 0, "selftest failed: %s%s" % (p.stdout, p.stderr)
    m = re.search(r"\[SELFTEST\] OK - SHA256=([0-9a-f]{64}) HMAC=([0-9a-f]{64})", p.stdout)
    assert m, "unexpected selftest output: %r" % p.stdout
    assert m.group(1) == SHA256_SELFTEST, "SHA256 differs from hashlib"
    assert m.group(2) == RFC4231_HMAC_SHA256_TC1, "HMAC differs from RFC 4231 TC1"


def test_imports_have_no_xp_blockers():
    (major, minor), dlls, fns = read_imports(LEGACY_BIN)
    assert (major, minor) == (5, 1), "subsystem must be 5.01, got %d.%02d" % (major, minor)
    for d in dlls:
        low = d.lower()
        assert not any(b in low for b in BANNED_DLLS), "banned import: %s" % d
    bad = [f for f in fns if f in BANNED_FNS]
    assert not bad, "Vista+ imports present: %s" % bad
    assert any(d.lower() == "advapi32.dll" for d in dlls), "CryptoAPI (advapi32) expected"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
