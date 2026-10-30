/*
 * BridgeWindows - Win32 x86 Remote Agent v3.4.0
 * Target: Windows 10 32-bit (x86) & 64-bit
 * Footprint: < 3.5 MB RAM, Single Portable .exe, Native Win32 + CNG (bcrypt.dll)
 */

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT /* zig predefines 0x0A00; we choose per-target below */
#endif
#ifdef AGENT_LEGACY_XP
#define _WIN32_WINNT 0x0501 /* XP/2003: no CNG, no TokenElevation, no GetTickCount64 */
#else
#define _WIN32_WINNT 0x0601
#endif
#define PSAPI_VERSION 1

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#ifdef AGENT_LEGACY_XP
#include <wincrypt.h> /* CryptoAPI: same SHA-256/HMAC digests as CNG */
#else
#include <bcrypt.h>
#endif
#include <tlhelp32.h>
#include <psapi.h>
#include <wingdi.h>
#include <winreg.h>
#include <winsvc.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <io.h>      /* _open_osfhandle/_dup2: ANSI bridge for pre-Win10 consoles */
#include <fcntl.h>

#include "protocol.h"
#include "gui.h"
#if defined(_M_ARM64) || defined(__aarch64__)
#define AGENT_ARCH "arm64"
#elif defined(_WIN64)
#define AGENT_ARCH "x64"
#else
#define AGENT_ARCH "x86"
#endif
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
#ifndef STACK_SIZE_PARAM_IS_A_RESERVATION
#define STACK_SIZE_PARAM_IS_A_RESERVATION 0x00010000
#endif

#define CLR_RESET   "[0m"
#define CLR_BOLD    "[1m"
#define CLR_DIM     "[90m"
#define CLR_RED     "[91m"
#define CLR_GREEN   "[92m"
#define CLR_YELLOW  "[93m"
#define CLR_BLUE    "[94m"
#define CLR_MAGENTA "[95m"
#define CLR_CYAN    "[96m"
#define CLR_WHITE   "[97m"


#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifdef AGENT_LEGACY_XP
/* XP compatibility shims. Same wire digests/timestamps as the CNG path. */
static uint64_t legacy_tick64(void) {
    static DWORD last = 0;
    static uint64_t base = 0;
    DWORD now = GetTickCount();
    if (now < last) base += (uint64_t)1 << 32; /* 49.7-day wrap */
    last = now;
    return base + now;
}
#define GetTickCount64() legacy_tick64()

static BOOL legacy_is_admin(void) {
    /* Manual TokenGroups walk: compare SIDs directly instead of
     * CheckTokenMembership (fewer API dependencies on XP).
     * Administrators present+enabled => admin (no UAC on XP). */
    HANDLE tok = NULL;
    DWORD len = 0;
    TOKEN_GROUPS *groups = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID admin_sid = NULL;
    BOOL ok = FALSE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return FALSE;
    GetTokenInformation(tok, TokenGroups, NULL, 0, &len);
    groups = (TOKEN_GROUPS *)malloc(len ? len : 1);
    if (groups && GetTokenInformation(tok, TokenGroups, groups, len, &len)
        && AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_sid)) {
        for (DWORD i = 0; i < groups->GroupCount; i++) {
            if ((groups->Groups[i].Attributes & SE_GROUP_ENABLED)
                && EqualSid(groups->Groups[i].Sid, admin_sid)) {
                ok = TRUE;
                break;
            }
        }
        FreeSid(admin_sid);
    }
    free(groups);
    CloseHandle(tok);
    return ok;
}

#ifndef MS_ENH_RSA_AES_PROV_A
#define MS_ENH_RSA_AES_PROV_A "Microsoft Enhanced RSA and AES Cryptographic Provider"
#endif
#ifndef PROV_RSA_AES
#define PROV_RSA_AES 24
#endif
#ifndef CALG_SHA_256
#define CALG_SHA_256 0x800c
#endif
#ifndef CRYPT_IPSEC_HMAC_KEY
#define CRYPT_IPSEC_HMAC_KEY 0x00000100
#endif

static void legacy_hex32(const unsigned char h[32], char out65[65]) {
    for (int i = 0; i < 32; ++i) snprintf(out65 + (i * 2), 3, "%02x", h[i]);
    out65[64] = '\0';
}

/* Software SHA-256 (FIPS 180-4). XP's rsaenh has no usable SHA-256 provider
 * (PROV_RSA_AES/CALG_SHA_256 fails on XP SP3 VL), so the legacy build hashes
 * in-process. Wire digests are identical by construction; --selftest asserts
 * SHA256("selftest") and the RFC 4231 HMAC-SHA256 vector on every build. */
static const uint32_t sw_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SW_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SW_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define SW_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SW_BSIG0(x) (SW_ROTR(x, 2) ^ SW_ROTR(x, 13) ^ SW_ROTR(x, 22))
#define SW_BSIG1(x) (SW_ROTR(x, 6) ^ SW_ROTR(x, 11) ^ SW_ROTR(x, 25))
#define SW_SSIG0(x) (SW_ROTR(x, 7) ^ SW_ROTR(x, 18) ^ ((x) >> 3))
#define SW_SSIG1(x) (SW_ROTR(x, 17) ^ SW_ROTR(x, 19) ^ ((x) >> 10))

typedef struct {
    uint32_t h[8];
    uint64_t total_len;
    unsigned char buf[64];
    size_t buf_len;
} capi_sha256_stream; /* name kept for the guarded call sites; software-backed */

static void sw_sha256_block(capi_sha256_stream *s, const unsigned char blk[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, hh, t1, t2;
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16)
             | ((uint32_t)blk[i * 4 + 2] << 8) | (uint32_t)blk[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = SW_SSIG1(w[i - 2]) + w[i - 7] + SW_SSIG0(w[i - 15]) + w[i - 16];
    }
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
    e = s->h[4]; f = s->h[5]; g = s->h[6]; hh = s->h[7];
    for (int i = 0; i < 64; ++i) {
        t1 = hh + SW_BSIG1(e) + SW_CH(e, f, g) + sw_sha256_k[i] + w[i];
        t2 = SW_BSIG0(a) + SW_MAJ(a, b, c);
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
    s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += hh;
}

static bool capi_stream_init(capi_sha256_stream *s) {
    s->h[0] = 0x6a09e667; s->h[1] = 0xbb67ae85;
    s->h[2] = 0x3c6ef372; s->h[3] = 0xa54ff53a;
    s->h[4] = 0x510e527f; s->h[5] = 0x9b05688c;
    s->h[6] = 0x1f83d9ab; s->h[7] = 0x5be0cd19;
    s->total_len = 0;
    s->buf_len = 0;
    return true;
}

static bool capi_stream_update(capi_sha256_stream *s, const unsigned char *d, size_t n) {
    if (n == 0) return true;
    if (!d) return false;
    s->total_len += (uint64_t)n;
    while (n > 0) {
        size_t take = 64 - s->buf_len;
        if (take > n) take = n;
        memcpy(s->buf + s->buf_len, d, take);
        s->buf_len += take;
        d += take;
        n -= take;
        if (s->buf_len == 64) {
            sw_sha256_block(s, s->buf);
            s->buf_len = 0;
        }
    }
    return true;
}

static bool capi_stream_final(capi_sha256_stream *s, unsigned char out32[32]) {
    uint64_t bit_len = s->total_len * 8;
    unsigned char pad = 0x80;
    unsigned char zero = 0x00;
    unsigned char len_be[8];
    for (int i = 0; i < 8; ++i) {
        len_be[i] = (unsigned char)((bit_len >> (56 - i * 8)) & 0xff);
    }
    /* pad: 0x80 then zeros until length == 56 (mod 64), then 64-bit length */
    if (s->buf_len >= 56) {
        capi_stream_update(s, &pad, 1);
        while (s->buf_len != 0) capi_stream_update(s, &zero, 1);
    } else {
        capi_stream_update(s, &pad, 1);
    }
    while (s->buf_len != 56) capi_stream_update(s, &zero, 1);
    /* length block: feed raw (total_len must NOT grow) */
    memcpy(s->buf + 56, len_be, 8);
    sw_sha256_block(s, s->buf);
    s->buf_len = 0;
    for (int i = 0; i < 8; ++i) {
        out32[i * 4] = (unsigned char)((s->h[i] >> 24) & 0xff);
        out32[i * 4 + 1] = (unsigned char)((s->h[i] >> 16) & 0xff);
        out32[i * 4 + 2] = (unsigned char)((s->h[i] >> 8) & 0xff);
        out32[i * 4 + 3] = (unsigned char)(s->h[i] & 0xff);
    }
    return true;
}

static bool capi_hmac_sha256_raw(const unsigned char *key, size_t keylen,
        const unsigned char *data, size_t len, unsigned char out32[32]) {
    unsigned char k0[64];
    unsigned char inner[32];
    capi_sha256_stream st;
    size_t i;
    if (!key || keylen == 0 || keylen > 4096 || (!data && len > 0)) return false;
    memset(k0, 0, sizeof(k0));
    if (keylen > 64) {
        if (!capi_stream_init(&st)) return false;
        if (!capi_stream_update(&st, key, keylen)) return false;
        if (!capi_stream_final(&st, k0)) return false;
    } else {
        memcpy(k0, key, keylen);
    }
    for (i = 0; i < 64; ++i) k0[i] ^= 0x36;
    if (!capi_stream_init(&st)) return false;
    if (!capi_stream_update(&st, k0, 64)) return false;
    if (len > 0 && !capi_stream_update(&st, data, len)) return false;
    if (!capi_stream_final(&st, inner)) return false;
    for (i = 0; i < 64; ++i) k0[i] ^= (0x36 ^ 0x5c);
    if (!capi_stream_init(&st)) return false;
    if (!capi_stream_update(&st, k0, 64)) return false;
    if (!capi_stream_update(&st, inner, 32)) return false;
    if (!capi_stream_final(&st, out32)) return false;
    return true;
}

static BOOL legacy_proc_image(HANDLE hProc, char *out, DWORD cap) {
    DWORD n = GetModuleFileNameExA(hProc, NULL, out, cap); /* psapi: XP inbox */
    return n > 0 && n < cap;
}

static bool capi_rng(unsigned char *out, size_t n) {
    HCRYPTPROV hProv = 0;
    /* Default provider (always present, even on XP) for RNG only. */
    if (CryptAcquireContextA(&hProv, NULL, MS_DEF_PROV_A, PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT)) {
        BOOL ok = CryptGenRandom(hProv, (DWORD)n, out);
        CryptReleaseContext(hProv, 0);
        if (ok) return true;
    }
    /* Last-resort uniqueness fallback (non-crypto): time + pid + counter. */
    {
        static volatile LONG ctr = 0;
        DWORD seed = GetTickCount() ^ (GetCurrentProcessId() << 16)
            ^ (DWORD)InterlockedIncrement(&ctr);
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);
        seed ^= (DWORD)pc.LowPart ^ (DWORD)pc.HighPart;
        srand(seed);
        for (size_t i = 0; i < n; ++i) out[i] = (unsigned char)((rand() >> 7) & 0xff);
    }
    return true;
}
#endif /* AGENT_LEGACY_XP */

/* =========================================================================
 * GLOBAL STATE & SYNCHRONIZATION
 * ========================================================================= */
static char g_master_host[256] = "192.168.1.23";
static uint16_t g_master_port = DEFAULT_BRIDGE_PORT;
static char g_psk_token[256] = "";  /* required: --token or BRIDGE_PSK env; never a compiled default */
static void set_title_utf8(const char *utf8); /* defined near main; used by the monitor loop */
static char g_agent_id[64] = "";    /* required: --agent-id or sanitized COMPUTERNAME */
static unsigned char g_sesskey[32]; /* per-connection session key, derived at handshake */
static bool g_have_sess = false;
static volatile LONG g_running = 1;
/* GUI-visible connection state (BW_STATE_* in gui.h; network thread writes, GUI reads) */
static volatile LONG g_conn_state = BW_STATE_IDLE;
static uint64_t g_session_start_tick = 0;
static uint64_t g_reconnect_count = 0;
static uint64_t g_boot_tick = 0;
static char g_last_error[128] = "";
static SOCKET g_session_sock = INVALID_SOCKET;
static bool g_headless = false;
static DWORD g_upgraded_from_pid = 0;
static uint64_t g_rpc_calls_total = 0;

static CRITICAL_SECTION g_log_lock;
static CRITICAL_SECTION g_telemetry_lock;
static CRITICAL_SECTION g_send_lock;
static CRITICAL_SECTION g_console_lock;
static void bw_note_error(const char *msg) {
    EnterCriticalSection(&g_log_lock);
    strncpy(g_last_error, msg, sizeof(g_last_error) - 1);
    g_last_error[sizeof(g_last_error) - 1] = '\0';
    LeaveCriticalSection(&g_log_lock);
}

/* Network Packet & Byte Counters */
static uint64_t g_packets_rx = 0;
static uint64_t g_packets_tx = 0;
static uint64_t g_bytes_rx = 0;
static uint64_t g_bytes_tx = 0;
static bool g_vt_enabled = false;
static int g_last_viewport_h = 0;
static int g_last_viewport_w = 0;
static uint64_t g_ui_start_tick = 0;

/* Telemetry state updated every 1000ms by TelemetryThread */
static double g_cpu_load_pct = 0.0;
static uint64_t g_io_read_bytes_sec = 0;
static uint64_t g_io_write_bytes_sec = 0;
static uint64_t g_io_total_read_bytes = 0;
static uint64_t g_io_total_write_bytes = 0;
static uint64_t g_ram_avail_bytes = 0;
static uint64_t g_ram_total_bytes = 0;
static uint64_t g_telemetry_last_tick = 0;
static volatile LONG g_cmd_executing = 0;

/* Circular Log Ring */
typedef enum {
    LOG_LVL_DEBUG = 0,
    LOG_LVL_INFO  = 1,
    LOG_LVL_WARN  = 2,
    LOG_LVL_ERROR = 3
} LogLevel;

typedef struct {
    uint64_t seq;
    uint64_t uptime_ms;
    int32_t level;
    char msg[LOG_MSG_MAX_LEN];
} LogEntry;

static LogEntry g_log_ring[LOG_RING_CAPACITY];
static size_t g_log_head = 0;
static size_t g_log_count = 0;
static uint64_t g_log_seq = 0;

static const char *log_level_str(int32_t lvl) {
    switch (lvl) {
        case LOG_LVL_DEBUG: return "DEBUG";
        case LOG_LVL_INFO:  return "INFO";
        case LOG_LVL_WARN:  return "WARN";
        case LOG_LVL_ERROR: return "ERROR";
        default:            return "INFO";
    }
}

static int32_t parse_log_level(const char *s) {
    if (!s) return LOG_LVL_DEBUG;
    if (_stricmp(s, "ERROR") == 0) return LOG_LVL_ERROR;
    if (_stricmp(s, "WARN") == 0)  return LOG_LVL_WARN;
    if (_stricmp(s, "INFO") == 0)  return LOG_LVL_INFO;
    return LOG_LVL_DEBUG;
}

static void agent_log(LogLevel lvl, const char *fmt, ...) {
    char buf[LOG_MSG_MAX_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = '\0';

    uint64_t now = GetTickCount64();

    EnterCriticalSection(&g_log_lock);
    uint64_t seq = ++g_log_seq;
    LogEntry *entry = &g_log_ring[g_log_head];
    entry->seq = seq;
    entry->uptime_ms = now;
    entry->level = (int32_t)lvl;
    strncpy(entry->msg, buf, sizeof(entry->msg) - 1);
    entry->msg[sizeof(entry->msg) - 1] = '\0';

    g_log_head = (g_log_head + 1) % LOG_RING_CAPACITY;
    if (g_log_count < LOG_RING_CAPACITY) {
        g_log_count++;
    }
    LeaveCriticalSection(&g_log_lock);

        const char *lvl_clr = CLR_WHITE;
    switch (lvl) {
        case LOG_LVL_DEBUG: lvl_clr = CLR_DIM; break;
        case LOG_LVL_INFO:  lvl_clr = CLR_CYAN; break;
        case LOG_LVL_WARN:  lvl_clr = CLR_YELLOW; break;
        case LOG_LVL_ERROR: lvl_clr = CLR_RED CLR_BOLD; break;
    }
    EnterCriticalSection(&g_console_lock);
    printf("%s[%-5s]%s %s[+%6llums]%s %s\n", lvl_clr, log_level_str(lvl), CLR_RESET, CLR_DIM, (unsigned long long)now, CLR_RESET, buf);
    fflush(stdout);
    LeaveCriticalSection(&g_console_lock);
}

/* =========================================================================
 * LIVE FLOW FEED for the status window: one entry per message that crosses
 * the link (direction, short label, size). Read by gui.c via bw_drain_flows().
 * ========================================================================= */
#define BW_FLOW_CAP 128
typedef struct { uint64_t seq; int dir; uint64_t bytes; char label[48]; } FlowEntry;
static FlowEntry g_flow_ring[BW_FLOW_CAP];
static uint64_t g_flow_seq = 0;
static CRITICAL_SECTION g_flow_lock;
static volatile LONG g_flow_ready = 0;

static void bw_flow_push(int dir, const char *label, uint64_t bytes) {
    if (!InterlockedCompareExchange(&g_flow_ready, 1, 1)) return;
    EnterCriticalSection(&g_flow_lock);
    uint64_t sq = ++g_flow_seq;
    FlowEntry *e = &g_flow_ring[sq % BW_FLOW_CAP];
    e->seq = sq; e->dir = dir; e->bytes = bytes;
    strncpy(e->label, label ? label : "?", sizeof(e->label) - 1);
    e->label[sizeof(e->label) - 1] = '\0';
    LeaveCriticalSection(&g_flow_lock);
}

int bw_drain_flows(uint64_t *last_seq, bw_flow_cb cb, void *ctx) {
    if (!last_seq || !cb || !InterlockedCompareExchange(&g_flow_ready, 1, 1)) return -1;
    FlowEntry out[BW_FLOW_CAP]; int n = 0;
    EnterCriticalSection(&g_flow_lock);
    uint64_t first = *last_seq + 1;
    if (g_flow_seq >= BW_FLOW_CAP && first < g_flow_seq - BW_FLOW_CAP + 1) first = g_flow_seq - BW_FLOW_CAP + 1;
    for (uint64_t q = first; q <= g_flow_seq && n < BW_FLOW_CAP; q++) {
        FlowEntry *e = &g_flow_ring[q % BW_FLOW_CAP];
        if (e->seq == q) out[n++] = *e;
    }
    if (g_flow_seq > *last_seq) *last_seq = g_flow_seq;
    LeaveCriticalSection(&g_flow_lock);
    for (int i = 0; i < n; i++) cb(out[i].dir, out[i].label, out[i].bytes, ctx);
    return n;
}

/* =========================================================================
 * DYNAMIC BUFFER (HEAP ALLOCATION WITH BOUNDS CHECKING)
 * ========================================================================= */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} DynBuf;

static void db_init(DynBuf *b, size_t init_cap) {
    if (init_cap < 128) init_cap = 128;
    b->data = (char *)malloc(init_cap);
    b->len = 0;
    b->cap = init_cap;
    if (b->data) b->data[0] = '\0';
}

static bool db_reserve(DynBuf *b, size_t extra) {
    if (b->len + extra + 1 <= b->cap) return true;
    size_t new_cap = b->cap * 2;
    if (new_cap < b->len + extra + 1) new_cap = b->len + extra + 1024;
    if (new_cap > MAX_FRAME_SIZE) return false;
    char *p = (char *)realloc(b->data, new_cap);
    if (!p) return false;
    b->data = p;
    b->cap = new_cap;
    return true;
}

static void db_append_mem(DynBuf *b, const void *ptr, size_t sz) {
    if (!ptr || sz == 0) return;
    if (!db_reserve(b, sz)) return;
    memcpy(b->data + b->len, ptr, sz);
    b->len += sz;
    b->data[b->len] = '\0';
}

static void db_append_str(DynBuf *b, const char *s) {
    if (!s) return;
    db_append_mem(b, s, strlen(s));
}

static void db_append_char(DynBuf *b, char c) {
    db_append_mem(b, &c, 1);
}

static void db_append_int64(DynBuf *b, int64_t v) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%lld", (long long)v);
    db_append_str(b, tmp);
}

static void db_append_uint64(DynBuf *b, uint64_t v) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
    db_append_str(b, tmp);
}

static void db_append_json_escaped(DynBuf *b, const char *s) {
    if (!s) return;
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        switch (*p) {
            case '\"': db_append_str(b, "\\\""); break;
            case '\\': db_append_str(b, "\\\\"); break;
            case '\b': db_append_str(b, "\\b"); break;
            case '\f': db_append_str(b, "\\f"); break;
            case '\n': db_append_str(b, "\\n"); break;
            case '\r': db_append_str(b, "\\r"); break;
            case '\t': db_append_str(b, "\\t"); break;
            default:
                if (*p < 32) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", *p);
                    db_append_str(b, esc);
                } else {
                    db_append_char(b, (char)*p);
                }
                break;
        }
    }
}

static void db_free(DynBuf *b) {
    if (b->data) {
        free(b->data);
        b->data = NULL;
    }
    b->len = 0;
    b->cap = 0;
}

/* =========================================================================
 * WINDOWS CNG (bcrypt.dll) SHA-256 HASHING
 * ========================================================================= */
#ifdef AGENT_LEGACY_XP
static bool compute_buffer_sha256(const unsigned char *data, size_t len, char *out_hex) {
    capi_sha256_stream st;
    unsigned char rgbHash[32];
    if (!capi_stream_init(&st)) return false;
    if (!capi_stream_update(&st, data, len)) { capi_stream_final(&st, rgbHash); return false; }
    if (!capi_stream_final(&st, rgbHash)) return false;
    legacy_hex32(rgbHash, out_hex);
    return true;
}
#else
static bool compute_buffer_sha256(const unsigned char *data, size_t len, char *out_hex) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;
    DWORD cbHashObj = 0, cbData = 0;
    PBYTE pbHashObj = NULL;
    BYTE rgbHash[32];
    bool ok = false;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObj, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    pbHashObj = (PBYTE)malloc(cbHashObj);
    if (!pbHashObj) goto cleanup;

    status = BCryptCreateHash(hAlg, &hHash, pbHashObj, cbHashObj, NULL, 0, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptHashData(hHash, (PBYTE)data, (ULONG)len, 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = BCryptFinishHash(hHash, rgbHash, sizeof(rgbHash), 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    for (int i = 0; i < 32; ++i) {
        snprintf(out_hex + (i * 2), 3, "%02x", rgbHash[i]);
    }
    out_hex[64] = '\0';
    ok = true;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObj) free(pbHashObj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}
#endif /* AGENT_LEGACY_XP */

/* =========================================================================
 * V4 SESSION CRYPTO: HMAC-SHA256 (CNG), session-key derivation, nonces.
 * The PSK itself never crosses the wire: mutual challenge-response at
 * handshake, then per-frame HMAC under a session key. No secret in logs.
 * ========================================================================= */
#ifdef AGENT_LEGACY_XP
static bool compute_hmac_sha256_hex(const unsigned char *key, size_t keylen,
        const unsigned char *data, size_t len, char *out_hex) {
    unsigned char rgbHash[32];
    if (!capi_hmac_sha256_raw(key, keylen, data, len, rgbHash)) return false;
    legacy_hex32(rgbHash, out_hex);
    return true;
}
#else
static bool compute_hmac_sha256_hex(const unsigned char *key, size_t keylen,
        const unsigned char *data, size_t len, char *out_hex) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = 0;
    DWORD cbHashObj = 0, cbData = 0;
    PBYTE pbHashObj = NULL;
    BYTE rgbHash[32];
    bool ok = false;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObj, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    pbHashObj = (PBYTE)malloc(cbHashObj);
    if (!pbHashObj) goto cleanup;
    status = BCryptCreateHash(hAlg, &hHash, pbHashObj, cbHashObj, (PBYTE)key, (ULONG)keylen, 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = BCryptHashData(hHash, (PBYTE)data, (ULONG)len, 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = BCryptFinishHash(hHash, rgbHash, sizeof(rgbHash), 0);
    if (!NT_SUCCESS(status)) goto cleanup;
    for (int i = 0; i < 32; ++i) {
        snprintf(out_hex + (i * 2), 3, "%02x", rgbHash[i]);
    }
    out_hex[64] = '\0';
    ok = true;
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObj) free(pbHashObj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}
#endif /* AGENT_LEGACY_XP */

/* sesskey = SHA256(psk || agent_nonce || master_nonce), raw 32 bytes. */
#ifdef AGENT_LEGACY_XP
static bool derive_sesskey(const char *psk, const char *agent_nonce, const char *master_nonce, unsigned char out[32]) {
    capi_sha256_stream st;
    if (!capi_stream_init(&st)) return false;
    if (!capi_stream_update(&st, (const unsigned char *)psk, strlen(psk))
        || !capi_stream_update(&st, (const unsigned char *)agent_nonce, strlen(agent_nonce))
        || !capi_stream_update(&st, (const unsigned char *)master_nonce, strlen(master_nonce))) {
        unsigned char tmp[32];
        capi_stream_final(&st, tmp);
        return false;
    }
    return capi_stream_final(&st, out);
}
#else
static bool derive_sesskey(const char *psk, const char *agent_nonce, const char *master_nonce, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObj = 0, cbData = 0;
    PBYTE pbHashObj = NULL;
    bool ok = false;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObj, sizeof(DWORD), &cbData, 0))) goto cleanup;
    pbHashObj = (PBYTE)malloc(cbHashObj);
    if (!pbHashObj) goto cleanup;
    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObj, cbHashObj, NULL, 0, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptHashData(hHash, (PBYTE)psk, (ULONG)strlen(psk), 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptHashData(hHash, (PBYTE)agent_nonce, (ULONG)strlen(agent_nonce), 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptHashData(hHash, (PBYTE)master_nonce, (ULONG)strlen(master_nonce), 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0))) goto cleanup;
    ok = true;
cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObj) free(pbHashObj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}
#endif /* AGENT_LEGACY_XP */

#ifdef AGENT_LEGACY_XP
static bool gen_hex_nonce(char out33[33]) {
    unsigned char r[16];
    if (!capi_rng(r, sizeof(r))) return false;
    for (int i = 0; i < 16; ++i) {
        snprintf(out33 + (i * 2), 3, "%02x", r[i]);
    }
    out33[32] = '\0';
    return true;
}
#else
static bool gen_hex_nonce(char out33[33]) {
    unsigned char r[16];
    if (!NT_SUCCESS(BCryptGenRandom(NULL, r, sizeof(r), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) return false;
    for (int i = 0; i < 16; ++i) {
        snprintf(out33 + (i * 2), 3, "%02x", r[i]);
    }
    out33[32] = '\0';
    return true;
}
#endif /* AGENT_LEGACY_XP */

#ifdef AGENT_LEGACY_XP
static bool compute_file_sha256(const char *path, char *out_hex, uint64_t *out_size, DWORD *out_win32_err) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (out_win32_err) *out_win32_err = GetLastError();
        return false;
    }
    LARGE_INTEGER fsize;
    if (GetFileSizeEx(hFile, &fsize) && out_size) {
        *out_size = (uint64_t)fsize.QuadPart;
    }
    capi_sha256_stream st;
    BYTE chunk[65536];
    unsigned char rgbHash[32];
    bool ok = false;
    DWORD bread = 0;
    if (!capi_stream_init(&st)) { CloseHandle(hFile); return false; }
    while (ReadFile(hFile, chunk, sizeof(chunk), &bread, NULL) && bread > 0) {
        if (!capi_stream_update(&st, chunk, bread)) goto file_cleanup;
    }
    if (!capi_stream_final(&st, rgbHash)) { CloseHandle(hFile); return false; }
    legacy_hex32(rgbHash, out_hex);
    ok = true;
    CloseHandle(hFile);
    return ok;
file_cleanup: {
    unsigned char tmp[32];
    capi_stream_final(&st, tmp);
    CloseHandle(hFile);
    return false;
    }
}
#else
static bool compute_file_sha256(const char *path, char *out_hex, uint64_t *out_size, DWORD *out_win32_err) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        if (out_win32_err) *out_win32_err = GetLastError();
        return false;
    }

    LARGE_INTEGER fsize;
    if (GetFileSizeEx(hFile, &fsize) && out_size) {
        *out_size = (uint64_t)fsize.QuadPart;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObj = 0, cbData = 0;
    PBYTE pbHashObj = NULL;
    BYTE *chunk = NULL;
    BYTE rgbHash[32];
    bool ok = false;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto cleanup;
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObj, sizeof(DWORD), &cbData, 0))) goto cleanup;

    pbHashObj = (PBYTE)malloc(cbHashObj);
    chunk = (BYTE *)malloc(65536);
    if (!pbHashObj || !chunk) goto cleanup;

    if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, pbHashObj, cbHashObj, NULL, 0, 0))) goto cleanup;

    DWORD bread = 0;
    while (ReadFile(hFile, chunk, 65536, &bread, NULL) && bread > 0) {
        if (!NT_SUCCESS(BCryptHashData(hHash, chunk, bread, 0))) goto cleanup;
    }
    if (!NT_SUCCESS(BCryptFinishHash(hHash, rgbHash, sizeof(rgbHash), 0))) goto cleanup;

    for (int i = 0; i < 32; ++i) {
        snprintf(out_hex + (i * 2), 3, "%02x", rgbHash[i]);
    }
    out_hex[64] = '\0';
    ok = true;

cleanup:
    if (chunk) free(chunk);
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObj) free(pbHashObj);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return ok;
}
#endif /* AGENT_LEGACY_XP */

/* =========================================================================
 * BASE64 & JSON HELPERS
 * ========================================================================= */
static const char b64_tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const unsigned char *src, size_t len, size_t *out_len) {
    size_t olen = 4 * ((len + 2) / 3);
    char *out = (char *)malloc(olen + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? src[i++] : 0;
        uint32_t b = i < len ? src[i++] : 0;
        uint32_t c = i < len ? src[i++] : 0;
        uint32_t t = (a << 16) | (b << 8) | c;
        out[j++] = b64_tbl[(t >> 18) & 0x3F];
        out[j++] = b64_tbl[(t >> 12) & 0x3F];
        out[j++] = b64_tbl[(t >> 6) & 0x3F];
        out[j++] = b64_tbl[t & 0x3F];
    }
    size_t mod = len % 3;
    if (mod == 1) { out[olen - 1] = '='; out[olen - 2] = '='; }
    else if (mod == 2) { out[olen - 1] = '='; }
    out[olen] = '\0';
    if (out_len) *out_len = olen;
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char *b64_decode(const char *src, size_t *out_len) {
    if (!src) return NULL;
    size_t slen = strlen(src);
    unsigned char *out = (unsigned char *)malloc((slen * 3) / 4 + 4);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;
    for (i = 0; i < slen; ++i) {
        if (src[i] == '=') break;
        int v = b64_val(src[i]);
        if (v < 0) continue;
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (unsigned char)((buf >> bits) & 0xFF);
        }
    }
    out[j] = '\0';
    if (out_len) *out_len = j;
    return out;
}

static const char *json_find_key(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    size_t plen = strlen(pat);
    const char *p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char *after = p + plen;
        while (*after == ' ' || *after == '\t' || *after == '\r' || *after == '\n') after++;
        if (*after == ':') {
            after++;
            while (*after == ' ' || *after == '\t' || *after == '\r' || *after == '\n') after++;
            return after;
        }
        p += plen;
    }
    return NULL;
}

static char *json_get_string(const char *json, const char *key) {
    const char *val = json_find_key(json, key);
    if (!val || *val != '\"') return NULL;
    val++;
    DynBuf out;
    db_init(&out, 128);
    while (*val && *val != '\"') {
        if (*val == '\\') {
            val++;
            if (!*val) break;
            switch (*val) {
                case '\"': db_append_char(&out, '\"'); break;
                case '\\': db_append_char(&out, '\\'); break;
                case '/':  db_append_char(&out, '/'); break;
                case 'b':  db_append_char(&out, '\b'); break;
                case 'f':  db_append_char(&out, '\f'); break;
                case 'n':  db_append_char(&out, '\n'); break;
                case 'r':  db_append_char(&out, '\r'); break;
                case 't':  db_append_char(&out, '\t'); break;
                default:   db_append_char(&out, *val); break;
            }
        } else {
            db_append_char(&out, *val);
        }
        val++;
    }
    return out.data;
}

static int64_t json_get_int64(const char *json, const char *key, int64_t def_val) {
    const char *val = json_find_key(json, key);
    if (!val) return def_val;
    if (*val == '\"') val++;
    char *endptr = NULL;
    long long r = strtoll(val, &endptr, 10);
    return (endptr == val) ? def_val : (int64_t)r;
}

static bool json_get_bool(const char *json, const char *key, bool def_val) {
    const char *val = json_find_key(json, key);
    if (!val) return def_val;
    if (strncmp(val, "true", 4) == 0 || *val == '1') return true;
    if (strncmp(val, "false", 5) == 0 || *val == '0') return false;
    return def_val;
}

static bool constant_time_eq(const char *a, const char *b) {
    if (!a || !b) return false;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < la; ++i) diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

static void build_error_response(DynBuf *resp, int64_t id, int code, const char *msg, DWORD win32_err) {
    if (code == RPC_ERR_AUTH_FAILED || code == RPC_ERR_INTERNAL || code == RPC_ERR_UPDATE_FAILED) {
        agent_log(LOG_LVL_WARN, "RPC error %d: %s (win32=%lu)", code, msg, (unsigned long)win32_err);
    } else {
        agent_log(LOG_LVL_DEBUG, "RPC notice %d: %s (win32=%lu)", code, msg, (unsigned long)win32_err);
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"error\":{\"code\":");
    db_append_int64(resp, code);
    db_append_str(resp, ",\"message\":\"");
    db_append_json_escaped(resp, msg);
    db_append_str(resp, "\",\"win32_error\":");
    db_append_uint64(resp, (uint64_t)win32_err);
    db_append_str(resp, "}}");
}

static char *convert_oem_or_ansi_to_utf8(const char *src, size_t src_len, size_t *out_len) {
    if (!src || src_len == 0) {
        if (out_len) *out_len = 0;
        char *empty = (char *)malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, (int)src_len, NULL, 0);
    if (wlen > 0) {
        char *copy = (char *)malloc(src_len + 1);
        if (copy) {
            memcpy(copy, src, src_len);
            copy[src_len] = '\0';
            if (out_len) *out_len = src_len;
        }
        return copy;
    }
    wlen = MultiByteToWideChar(CP_OEMCP, 0, src, (int)src_len, NULL, 0);
    if (wlen <= 0) {
        wlen = MultiByteToWideChar(CP_ACP, 0, src, (int)src_len, NULL, 0);
    }
    if (wlen <= 0) {
        char *copy = (char *)malloc(src_len + 1);
        if (copy) {
            memcpy(copy, src, src_len);
            copy[src_len] = '\0';
            if (out_len) *out_len = src_len;
        }
        return copy;
    }
    wchar_t *wbuf = (wchar_t *)malloc((wlen + 1) * sizeof(wchar_t));
    if (!wbuf) return NULL;
    MultiByteToWideChar(CP_OEMCP, 0, src, (int)src_len, wbuf, wlen);
    int ulen = WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, NULL, 0, NULL, NULL);
    char *ubuf = (char *)malloc(ulen + 1);
    if (ubuf) {
        WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, ubuf, ulen, NULL, NULL);
        ubuf[ulen] = '\0';
        if (out_len) *out_len = (size_t)ulen;
    }
    free(wbuf);
    return ubuf;
}

static const char *strcasestr_custom(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return haystack;
    size_t nlen = strlen(needle);
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            if (_strnicmp(haystack, needle, nlen) == 0) return haystack;
        }
    }
    return NULL;
}

/* =========================================================================
 * MODULE: SELF-REGULATING WORKING SET TRIMMER (SWARM-107)
 * ========================================================================= */
static const char *g_trim_whitelist[] = {
    "agent.exe",
    "mpv.exe",
    "supermium.exe",
    "chrome.exe",
    "dwm.exe",
    "explorer.exe",
    "wordpad.exe",
    "audiodg.exe",
    "csrss.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    NULL
};

static volatile LONG g_trim_daemon_enabled = 1;
static uint64_t g_last_trim_tick = 0;
static uint64_t g_trim_effective_cooldown_ms = (60ULL * 1000);
#define TRIM_RAM_PROACTIVE_BYTES (60ULL * 1024 * 1024)  /* Tier 1 proactive trim at < 60 MB */
#define TRIM_RAM_EMERGENCY_BYTES (45ULL * 1024 * 1024)  /* Tier 2 emergency trim at < 45 MB */
#define TRIM_RAM_TARGET_BYTES    (75ULL * 1024 * 1024)  /* Recovery target: 75 MB */
#define TRIM_COOLDOWN_MS         (60ULL * 1000)         /* 60s base cooldown */
#define TRIM_BACKOFF_COOLDOWN_MS (120ULL * 1000)        /* 120s backoff if reclaim < 4 MB */
#define TRIM_MIN_WORKING_SET     (4ULL * 1024 * 1024)   /* Minimum 4 MB footprint */

typedef struct {
    uint32_t candidates_evaluated;
    uint32_t processes_trimmed;
    uint64_t ram_before_bytes;
    uint64_t ram_after_bytes;
} SmartTrimStats;

static bool is_trim_exempt(const char *exe_name) {
    if (!exe_name || !exe_name[0]) return true;
    for (int i = 0; g_trim_whitelist[i] != NULL; i++) {
        if (_stricmp(exe_name, g_trim_whitelist[i]) == 0) return true;
    }
    return false;
}

static void enable_debug_privilege(void) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    LUID luid;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    }
    CloseHandle(hToken);
}

typedef NTSTATUS (NTAPI *pfnNtSetSystemInformation)(INT, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pfnRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

static bool purge_standby_list(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    pfnRtlAdjustPrivilege fnRtl = (pfnRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    pfnNtSetSystemInformation fnSet = (pfnNtSetSystemInformation)GetProcAddress(hNtdll, "NtSetSystemInformation");
    if (!fnSet || !fnRtl) return false;

    BOOLEAN was_enabled = FALSE;
    fnRtl(19, TRUE, FALSE, &was_enabled); /* 19 = SeProfileSingleProcessPrivilege */

    int command = 4; /* MemoryPurgeStandbyList */
    NTSTATUS status = fnSet(80, &command, sizeof(command)); /* SystemMemoryListInformation = 80 */
    return (status == 0);
}

static bool run_smart_trim(SmartTrimStats *stats) {
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    if (!GlobalMemoryStatusEx(&mem)) return false;

    if (stats) {
        stats->ram_before_bytes = mem.ullAvailPhys;
        stats->candidates_evaluated = 0;
        stats->processes_trimmed = 0;
        stats->ram_after_bytes = mem.ullAvailPhys;
    }

    /* SWARM-191: Purge Standby List directly in kernel (zero disk I/O, < 1.5ms) */
    purge_standby_list();

    /* Check if Standby purge recovered enough RAM to avoid touching working sets */
    if (GlobalMemoryStatusEx(&mem)) {
        if (stats) stats->ram_after_bytes = mem.ullAvailPhys;
        if (mem.ullAvailPhys >= TRIM_RAM_TARGET_BYTES) {
            return true;
        }
    }

    enable_debug_privilege();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(hSnap, &pe)) {
        CloseHandle(hSnap);
        return false;
    }

    HWND hFg = GetForegroundWindow();
    DWORD fgPid = 0;
    if (hFg) GetWindowThreadProcessId(hFg, &fgPid);

    do {
        if (pe.th32ProcessID <= 4) continue;
        if (fgPid != 0 && pe.th32ProcessID == fgPid) continue;
        if (is_trim_exempt(pe.szExeFile)) continue;

        if (stats) stats->candidates_evaluated++;

        HANDLE hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (!hProc) {
            hProc = OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        }
        if (hProc) {
            PROCESS_MEMORY_COUNTERS pmc;
            ZeroMemory(&pmc, sizeof(pmc));
            if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                if (pmc.WorkingSetSize >= TRIM_MIN_WORKING_SET) {
                    if (EmptyWorkingSet(hProc)) {
                        if (stats) stats->processes_trimmed++;
                    }
                }
            }
            CloseHandle(hProc);
        }

        Sleep(10);

        if (GlobalMemoryStatusEx(&mem)) {
            if (mem.ullAvailPhys >= TRIM_RAM_TARGET_BYTES) {
                break;
            }
        }
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);

    if (GlobalMemoryStatusEx(&mem) && stats) {
        stats->ram_after_bytes = mem.ullAvailPhys;
    }
    return true;
}

/* =========================================================================
 * IN-MEMORY TELEMETRY RING BUFFER (SWARM-130: ZERO-I/O 1-HOUR ROLLING HISTORY)
 * ========================================================================= */
#define TELEMETRY_HISTORY_SAMPLES 60 /* 60 samples @ 1 sample/min = 1 hour */

typedef struct {
    uint64_t timestamp_sec;   /* Unix epoch in seconds */
    uint32_t uptime_sec;      /* Machine uptime in seconds */
    float    cpu_pct;         /* CPU usage % (0.0 - 100.0) */
    uint32_t ram_avail_mb;    /* Available RAM in MB */
    float    gpu_temp_c;      /* GPU Diode temperature in degC (-1.0f if unavailable) */
    int16_t  gpu_engine_mhz;  /* GPU Core SCLK in MHz (-1 if unavailable) */
    int8_t   gpu_activity_pct;/* GPU Activity % (-1 if unavailable) */
} TelemetrySample;

typedef struct {
    TelemetrySample samples[TELEMETRY_HISTORY_SAMPLES]; /* 1,620 bytes */
    uint32_t head;                                      /* Next insertion slot */
    uint32_t count;                                     /* Total valid entries (max 60) */
    uint64_t total_recorded;                            /* Lifetime sample count */
} TelemetryRingBuffer;

static TelemetryRingBuffer *g_telemetry_ring = NULL;
static CRITICAL_SECTION g_telemetry_ring_lock;

/* AMD Display Library (ADL) Types & Function Pointers for GPU Diode, Clocks & Utilization */
#define ADL_OK                                0
#define ADL_ERR                              -1
#define ADL_ERR_NOT_SUPPORTED                -8
#define ADL_DL_FANCTRL_SPEED_TYPE_PERCENT     1
#define ADL_DL_FANCTRL_SPEED_TYPE_RPM         2

typedef struct {
    int iSize;
    int iTemperature; /* in millidegrees Celsius */
} ADLTemperature;

typedef struct {
    int iSize;
    int iEngineClock;           /* in 10 kHz (divide by 100 for MHz) */
    int iMemoryClock;           /* in 10 kHz (divide by 100 for MHz) */
    int iVddc;                  /* in millivolts */
    int iActivityPercent;       /* 0 to 100 % */
    int iCurrentPerformanceLevel;
    int iCurrentBusSpeed;
    int iCurrentBusLanes;
    int iReserved;
} ADLPMActivity;

typedef struct {
    int iSize;
    int iSpeedType;             /* ADL_DL_FANCTRL_SPEED_TYPE_PERCENT or _RPM */
    int iFanSpeed;              /* Fan speed value */
    int iFlags;
} ADLFanSpeedValue;

typedef int (*ADL_MAIN_CONTROL_CREATE)(void *(*)(int), int);
typedef int (*ADL_MAIN_CONTROL_DESTROY)(void);
typedef int (*ADL_ADAPTER_NUMBEROFADAPTERS_GET)(int *);
typedef int (*ADL_ADAPTER_ACTIVE_GET)(int, int *);
typedef int (*ADL_OVERDRIVE5_TEMPERATURE_GET)(int, int, ADLTemperature *);
typedef int (*ADL_OVERDRIVE5_CURRENTACTIVITY_GET)(int, ADLPMActivity *);
typedef int (*ADL_OVERDRIVE5_FANSPEED_GET)(int, int, ADLFanSpeedValue *);

static void * adl_alloc_cb(int size) {
    return malloc(size);
}

static HMODULE g_hAdl = NULL;
static ADL_OVERDRIVE5_TEMPERATURE_GET g_pfnAdlOverdrive5Get = NULL;
static ADL_OVERDRIVE5_CURRENTACTIVITY_GET g_pfnAdlActivityGet = NULL;
static ADL_OVERDRIVE5_FANSPEED_GET g_pfnAdlFanSpeedGet = NULL;
static int g_adl_primary_adapter = -1;
static bool g_adl_available = false;

typedef struct {
    float temp_c;            /* GPU diode temp (-1.0f if unavailable) */
    int   engine_clock_mhz;  /* Core clock SCLK (-1 if unavailable) */
    int   memory_clock_mhz;  /* Memory clock MCLK (-1 if unavailable) */
    int   activity_pct;      /* GPU activity % 0-100 (-1 if unavailable) */
    int   vddc_mv;           /* Core voltage in mV (-1 if unavailable) */
} GpuTelemetry;

static void init_gpu_telemetry(void) {
    g_hAdl = LoadLibraryA("atiadlxx.dll");
    if (!g_hAdl) {
        g_hAdl = LoadLibraryA("atiadlxy.dll");
    }
    if (!g_hAdl) {
        g_adl_available = false;
        return;
    }

    ADL_MAIN_CONTROL_CREATE pfnCreate = (ADL_MAIN_CONTROL_CREATE)GetProcAddress(g_hAdl, "ADL_Main_Control_Create");
    ADL_ADAPTER_NUMBEROFADAPTERS_GET pfnNumAdapters = (ADL_ADAPTER_NUMBEROFADAPTERS_GET)GetProcAddress(g_hAdl, "ADL_Adapter_NumberOfAdapters_Get");
    ADL_ADAPTER_ACTIVE_GET pfnActiveGet = (ADL_ADAPTER_ACTIVE_GET)GetProcAddress(g_hAdl, "ADL_Adapter_Active_Get");
    g_pfnAdlOverdrive5Get = (ADL_OVERDRIVE5_TEMPERATURE_GET)GetProcAddress(g_hAdl, "ADL_Overdrive5_Temperature_Get");
    g_pfnAdlActivityGet = (ADL_OVERDRIVE5_CURRENTACTIVITY_GET)GetProcAddress(g_hAdl, "ADL_Overdrive5_CurrentActivity_Get");
    g_pfnAdlFanSpeedGet = (ADL_OVERDRIVE5_FANSPEED_GET)GetProcAddress(g_hAdl, "ADL_Overdrive5_FanSpeed_Get");

    if (!pfnCreate || !pfnNumAdapters || !g_pfnAdlOverdrive5Get) {
        FreeLibrary(g_hAdl);
        g_hAdl = NULL;
        g_adl_available = false;
        return;
    }

    if (pfnCreate(adl_alloc_cb, 1) != 0) {
        FreeLibrary(g_hAdl);
        g_hAdl = NULL;
        g_adl_available = false;
        return;
    }

    int num_adapters = 0;
    if (pfnNumAdapters(&num_adapters) == 0 && num_adapters > 0) {
        g_adl_primary_adapter = 0; /* Default fallback */
        if (pfnActiveGet) {
            for (int i = 0; i < num_adapters; ++i) {
                int active = 0;
                if (pfnActiveGet(i, &active) == 0 && active) {
                    g_adl_primary_adapter = i;
                    break;
                }
            }
        }
        g_adl_available = true;
    } else {
        ADL_MAIN_CONTROL_DESTROY pfnDestroy = (ADL_MAIN_CONTROL_DESTROY)GetProcAddress(g_hAdl, "ADL_Main_Control_Destroy");
        if (pfnDestroy) pfnDestroy();
        FreeLibrary(g_hAdl);
        g_hAdl = NULL;
        g_adl_available = false;
    }
}

static void query_gpu_telemetry(GpuTelemetry *out) {
    if (!out) return;
    out->temp_c = -1.0f;
    out->engine_clock_mhz = -1;
    out->memory_clock_mhz = -1;
    out->activity_pct = -1;
    out->vddc_mv = -1;

    if (!g_adl_available || g_adl_primary_adapter < 0) return;

    if (g_pfnAdlOverdrive5Get) {
        ADLTemperature temp;
        ZeroMemory(&temp, sizeof(temp));
        temp.iSize = sizeof(ADLTemperature);
        if (g_pfnAdlOverdrive5Get(g_adl_primary_adapter, 0, &temp) == 0 && temp.iTemperature > 0) {
            out->temp_c = (float)temp.iTemperature / 1000.0f;
        }
    }

    if (g_pfnAdlActivityGet) {
        ADLPMActivity act;
        ZeroMemory(&act, sizeof(act));
        act.iSize = sizeof(ADLPMActivity);
        if (g_pfnAdlActivityGet(g_adl_primary_adapter, &act) == 0) {
            if (act.iEngineClock > 0) {
                out->engine_clock_mhz = act.iEngineClock / 100;
            }
            if (act.iMemoryClock > 0) {
                out->memory_clock_mhz = act.iMemoryClock / 100;
            }
            if (act.iActivityPercent >= 0 && act.iActivityPercent <= 100) {
                out->activity_pct = act.iActivityPercent;
            }
            if (act.iVddc > 0) {
                out->vddc_mv = act.iVddc;
            }
        }
    }
}

static float query_gpu_temperature(void) {
    GpuTelemetry gt;
    query_gpu_telemetry(&gt);
    return gt.temp_c;
}

static void cleanup_gpu_telemetry(void) {
    if (g_hAdl) {
        ADL_MAIN_CONTROL_DESTROY pfnDestroy = (ADL_MAIN_CONTROL_DESTROY)GetProcAddress(g_hAdl, "ADL_Main_Control_Destroy");
        if (pfnDestroy) pfnDestroy();
        FreeLibrary(g_hAdl);
        g_hAdl = NULL;
    }
    g_adl_available = false;
    g_adl_primary_adapter = -1;
}

static void init_telemetry_ring(void) {
    InitializeCriticalSection(&g_telemetry_ring_lock);

    /* Allocate 1 physical page (4096 bytes) */
    g_telemetry_ring = (TelemetryRingBuffer *)VirtualAlloc(
        NULL,
        sizeof(TelemetryRingBuffer),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (g_telemetry_ring) {
        ZeroMemory(g_telemetry_ring, sizeof(TelemetryRingBuffer));
        /* Lock into physical RAM (Non-paged user working set, 0 disk paging) */
        if (!VirtualLock(g_telemetry_ring, sizeof(TelemetryRingBuffer))) {
            SIZE_T dwMin = 0, dwMax = 0;
            if (GetProcessWorkingSetSize(GetCurrentProcess(), &dwMin, &dwMax)) {
                SetProcessWorkingSetSize(GetCurrentProcess(), dwMin + 4096, dwMax + 4096);
                VirtualLock(g_telemetry_ring, sizeof(TelemetryRingBuffer));
            }
        }
    }
}

static void cleanup_telemetry_ring(void) {
    if (g_telemetry_ring) {
        VirtualUnlock(g_telemetry_ring, sizeof(TelemetryRingBuffer));
        VirtualFree(g_telemetry_ring, 0, MEM_RELEASE);
        g_telemetry_ring = NULL;
    }
    DeleteCriticalSection(&g_telemetry_ring_lock);
}

/* =========================================================================
 * AUTONOMOUS DRIFT SENTINEL (SWARM-140: PREEMPTIVE LEAK & THERMAL REGULATOR)
 * ========================================================================= */
typedef struct {
    uint32_t samples_evaluated;
    float    ram_slope_mb_min;
    float    ram_r2;
    float    ram_monotonicity;
    bool     ram_drift_detected;
    uint32_t ram_trims_triggered;
    uint64_t last_ram_trim_sec;
    float    gpu_temp_c;
    bool     thermal_drift_detected;
    bool     thermal_throttled;
    uint32_t thermal_throttle_count;
    uint64_t last_throttle_change_sec;
} DriftSentinelState;

static DriftSentinelState g_drift_sentinel = {0};
static CRITICAL_SECTION g_drift_sentinel_lock;

static void evaluate_drift_sentinel(void) {
    if (!g_telemetry_ring) return;

    EnterCriticalSection(&g_telemetry_ring_lock);
    uint32_t total = g_telemetry_ring->count;
    uint32_t head = g_telemetry_ring->head;
    if (total < 5) {
        LeaveCriticalSection(&g_telemetry_ring_lock);
        return;
    }

    /* Evaluate up to the last 30 samples (30 minutes of telemetry) */
    uint32_t n = (total > 30) ? 30 : total;
    uint32_t start_idx = (head + TELEMETRY_HISTORY_SAMPLES - n) % TELEMETRY_HISTORY_SAMPLES;

    double sum_x = 0.0, sum_y = 0.0;
    double sum_xx = 0.0, sum_xy = 0.0, sum_yy = 0.0;
    int decreasing_steps = 0;
    float latest_ram = 0.0f;
    float latest_gpu = -1.0f;

    /* Thermal tracking: check last 3 samples */
    int hot_samples = 0;
    int cold_samples = 0;
    uint32_t thermal_window = (n >= 3) ? 3 : n;

    for (uint32_t i = 0; i < n; ++i) {
        uint32_t idx = (start_idx + i) % TELEMETRY_HISTORY_SAMPLES;
        TelemetrySample *s = &g_telemetry_ring->samples[idx];
        double x = (double)i;
        double y = (double)s->ram_avail_mb;

        sum_x += x;
        sum_y += y;
        sum_xx += x * x;
        sum_xy += x * y;
        sum_yy += y * y;

        if (i > 0) {
            uint32_t prev_idx = (start_idx + i - 1) % TELEMETRY_HISTORY_SAMPLES;
            if (s->ram_avail_mb <= g_telemetry_ring->samples[prev_idx].ram_avail_mb) {
                decreasing_steps++;
            }
        }

        if (i == n - 1) {
            latest_ram = (float)s->ram_avail_mb;
            latest_gpu = s->gpu_temp_c;
        }

        if (i >= n - thermal_window) {
            if (s->gpu_temp_c >= 68.0f) {
                hot_samples++;
            }
            if (s->gpu_temp_c > 0.0f && s->gpu_temp_c <= 62.0f) {
                cold_samples++;
            }
        }
    }
    LeaveCriticalSection(&g_telemetry_ring_lock);

    /* OLS linear regression: y = m*x + b */
    double dn = (double)n;
    double ss_xx = sum_xx - (sum_x * sum_x) / dn;
    double ss_xy = sum_xy - (sum_x * sum_y) / dn;
    double ss_yy = sum_yy - (sum_y * sum_y) / dn;

    double slope = (ss_xx > 1e-9) ? (ss_xy / ss_xx) : 0.0;
    double r2 = 0.0;
    if (ss_xx > 1e-9 && ss_yy > 1e-9) {
        r2 = (ss_xy * ss_xy) / (ss_xx * ss_yy);
    }
    float monotonicity = (n > 1) ? ((float)decreasing_steps / (float)(n - 1)) : 0.0f;

    /* Leak criteria: RAM <= 45MB AND continuous downward slope AND high correlation */
    bool ram_drift = (latest_ram <= 45.0f && slope < -0.15 && r2 >= 0.50 && monotonicity >= 0.65f);
    bool should_trim = false;
    bool should_throttle = false;
    bool should_unthrottle = false;

    EnterCriticalSection(&g_drift_sentinel_lock);
    g_drift_sentinel.samples_evaluated = n;
    g_drift_sentinel.ram_slope_mb_min = (float)slope;
    g_drift_sentinel.ram_r2 = (float)r2;
    g_drift_sentinel.ram_monotonicity = monotonicity;
    g_drift_sentinel.ram_drift_detected = ram_drift;
    g_drift_sentinel.gpu_temp_c = latest_gpu;

    uint64_t now_sec = (uint64_t)time(NULL);

    if (ram_drift && (now_sec - g_drift_sentinel.last_ram_trim_sec > 600)) {
        should_trim = true;
        g_drift_sentinel.last_ram_trim_sec = now_sec;
        g_drift_sentinel.ram_trims_triggered++;
    }

    if (hot_samples >= 3 && !g_drift_sentinel.thermal_throttled) {
        g_drift_sentinel.thermal_drift_detected = true;
        g_drift_sentinel.thermal_throttled = true;
        g_drift_sentinel.thermal_throttle_count++;
        g_drift_sentinel.last_throttle_change_sec = now_sec;
        should_throttle = true;
    } else if (cold_samples >= 3 && g_drift_sentinel.thermal_throttled) {
        g_drift_sentinel.thermal_drift_detected = false;
        g_drift_sentinel.thermal_throttled = false;
        g_drift_sentinel.last_throttle_change_sec = now_sec;
        should_unthrottle = true;
    }
    LeaveCriticalSection(&g_drift_sentinel_lock);

    if (should_trim) {
        agent_log(LOG_LVL_WARN, "[SENTINEL] Memory drift detected (RAM: %.0fMB, slope: %.2fMB/m, R2: %.2f, mono: %.2f). Executing preemptive trim...",
                  latest_ram, slope, r2, monotonicity);
        SmartTrimStats st;
        run_smart_trim(&st);
        agent_log(LOG_LVL_INFO, "[SENTINEL] Preemptive trim finished: %u processes trimmed, free RAM: %luMB -> %luMB",
                  st.processes_trimmed, (unsigned long)(st.ram_before_bytes / (1024 * 1024)), (unsigned long)(st.ram_after_bytes / (1024 * 1024)));
    }

    if (should_throttle) {
        agent_log(LOG_LVL_WARN, "[SENTINEL] Thermal drift detected (GPU diode %.1f C >= 68C for 3m). Throttling Turbo Core to base 1.0 GHz...", latest_gpu);
        WinExec("powercfg -setacvalueindex scheme_current sub_processor be337238-0d82-4146-a960-4f3749d470c7 0", SW_HIDE);
        WinExec("powercfg -setactive scheme_current", SW_HIDE);
    } else if (should_unthrottle) {
        agent_log(LOG_LVL_INFO, "[SENTINEL] Thermal normalized (GPU diode %.1f C <= 62C). Restoring Turbo Core Aggressive boost...", latest_gpu);
        WinExec("powercfg -setacvalueindex scheme_current sub_processor be337238-0d82-4146-a960-4f3749d470c7 2", SW_HIDE);
        WinExec("powercfg -setactive scheme_current", SW_HIDE);
    }
}

/* =========================================================================
 * AUTONOMOUS KIOSK SENTINEL (SWARM-150: HUNG WINDOW DETECTION & SELF-HEALING)
 * ========================================================================= */
typedef struct {
    bool     enabled;
    bool     is_hung;
    bool     is_running;
    bool     auto_relaunch_on_crash;
    uint32_t restart_count_total;
    uint32_t restarts_in_window;
    uint64_t window_start_sec;
    uint64_t last_restart_sec;
    uint32_t backoff_sec;
    bool     circuit_breaker_tripped;
    char     target_name[64];
    char     last_action[128];
} KioskSentinelState;

static KioskSentinelState g_kiosk_sentinel = {
    .enabled = true,
    .is_hung = false,
    .is_running = false,
    .auto_relaunch_on_crash = false,
    .restart_count_total = 0,
    .restarts_in_window = 0,
    .window_start_sec = 0,
    .last_restart_sec = 0,
    .backoff_sec = 10,
    .circuit_breaker_tripped = false,
    .target_name = "chrome.exe",
    .last_action = "INITIALIZED_MONITORING"
};
static CRITICAL_SECTION g_kiosk_sentinel_lock;

typedef struct {
    char target_name[64];
    bool found_running;
    bool found_hung;
} EnumKioskData;

static BOOL CALLBACK EnumKioskWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumKioskData *data = (EnumKioskData *)lParam;
    if (!IsWindowVisible(hwnd)) return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == 0) return TRUE;

    HANDLE hProc = OpenProcess(
#ifdef AGENT_LEGACY_XP
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, /* XP: LIMITED_INFO does not exist */
#else
        PROCESS_QUERY_LIMITED_INFORMATION,
#endif
        FALSE, pid);
    if (!hProc) return TRUE;

    char exe_path[MAX_PATH];
#ifdef AGENT_LEGACY_XP
    if (legacy_proc_image(hProc, exe_path, sizeof(exe_path))) {
#else
    DWORD sz = sizeof(exe_path);
    if (QueryFullProcessImageNameA(hProc, 0, exe_path, &sz)) {
#endif
        char *fname = strrchr(exe_path, '\\');
        fname = fname ? (fname + 1) : exe_path;
        if (_stricmp(fname, data->target_name) == 0 ||
            (_stricmp(data->target_name, "chrome.exe") == 0 && _stricmp(fname, "mpv.exe") == 0)) {
            data->found_running = true;
            if (IsHungAppWindow(hwnd)) {
                data->found_hung = true;
            } else {
                DWORD_PTR dwResult = 0;
                if (!SendMessageTimeoutA(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_NORMAL, 1000, &dwResult)) {
                    data->found_hung = true;
                }
            }
        }
    }
    CloseHandle(hProc);
    return TRUE;
}

static void evaluate_kiosk_sentinel(void) {
    EnterCriticalSection(&g_kiosk_sentinel_lock);
    if (!g_kiosk_sentinel.enabled) {
        LeaveCriticalSection(&g_kiosk_sentinel_lock);
        return;
    }
    char target[64];
    strncpy(target, g_kiosk_sentinel.target_name, sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    LeaveCriticalSection(&g_kiosk_sentinel_lock);

    EnumKioskData data;
    ZeroMemory(&data, sizeof(data));
    strncpy(data.target_name, target, sizeof(data.target_name) - 1);

    EnumWindows(EnumKioskWindowsProc, (LPARAM)&data);

    uint64_t now_sec = (uint64_t)time(NULL);
    static int s_consecutive_hung = 0;
    static int s_consecutive_not_running = 0;

    EnterCriticalSection(&g_kiosk_sentinel_lock);
    g_kiosk_sentinel.is_running = data.found_running;

    /* Rolling 1-hour window reset */
    if (g_kiosk_sentinel.window_start_sec == 0 || (now_sec - g_kiosk_sentinel.window_start_sec > 3600)) {
        g_kiosk_sentinel.window_start_sec = now_sec;
        g_kiosk_sentinel.restarts_in_window = 0;
        g_kiosk_sentinel.circuit_breaker_tripped = false;
    }

    /* Reset backoff after 30 minutes of clean operation */
    if (g_kiosk_sentinel.backoff_sec > 10 && (now_sec - g_kiosk_sentinel.last_restart_sec > 1800)) {
        g_kiosk_sentinel.backoff_sec = 10;
        g_kiosk_sentinel.circuit_breaker_tripped = false;
    }

    bool should_restart = false;
    bool is_hung_trigger = false;

    if (data.found_running) {
        s_consecutive_not_running = 0;
        if (data.found_hung) {
            s_consecutive_hung++;
            if (s_consecutive_hung >= 2) {
                g_kiosk_sentinel.is_hung = true;
                is_hung_trigger = true;
            }
        } else {
            s_consecutive_hung = 0;
            g_kiosk_sentinel.is_hung = false;
        }
    } else {
        s_consecutive_hung = 0;
        g_kiosk_sentinel.is_hung = false;
        s_consecutive_not_running++;
        if (g_kiosk_sentinel.auto_relaunch_on_crash && s_consecutive_not_running >= 3) {
            should_restart = true;
        }
    }

    if (is_hung_trigger) {
        if (g_kiosk_sentinel.restarts_in_window >= 3) {
            g_kiosk_sentinel.circuit_breaker_tripped = true;
            snprintf(g_kiosk_sentinel.last_action, sizeof(g_kiosk_sentinel.last_action),
                     "CIRCUIT_BREAKER_TRIPPED: %s is hung, max 3/hr reached", target);
        } else if (now_sec - g_kiosk_sentinel.last_restart_sec >= g_kiosk_sentinel.backoff_sec) {
            should_restart = true;
        }
    }

    if (should_restart) {
        g_kiosk_sentinel.restart_count_total++;
        g_kiosk_sentinel.restarts_in_window++;
        g_kiosk_sentinel.last_restart_sec = now_sec;
        if (g_kiosk_sentinel.backoff_sec < 300) {
            g_kiosk_sentinel.backoff_sec *= 2;
        }
        s_consecutive_hung = 0;
        s_consecutive_not_running = 0;
        g_kiosk_sentinel.is_hung = false;
        snprintf(g_kiosk_sentinel.last_action, sizeof(g_kiosk_sentinel.last_action),
                 "RESTART_TRIGGERED (attempt %u, reason: %s)",
                 g_kiosk_sentinel.restart_count_total, is_hung_trigger ? "hung_window" : "crash_exit");
    }
    LeaveCriticalSection(&g_kiosk_sentinel_lock);

    if (should_restart) {
        agent_log(LOG_LVL_WARN, "[KIOSK-SENTINEL] Unresponsive application detected (%s, reason: %s). Terminating and restarting kiosk launcher (attempt %u)...",
                  target, is_hung_trigger ? "HUNG" : "CRASHED", g_kiosk_sentinel.restart_count_total);
        WinExec("taskkill /F /IM chrome.exe /IM mpv.exe", SW_HIDE);
        Sleep(1500);
        WinExec("cmd.exe /c start \"\" \"C:\\Users\\Sea\\Desktop\\Lancer_Supermium_LowRAM.bat\"", SW_HIDE);
    }
}

/* =========================================================================
 * WIN32 CONSOLE VT100 / ANSI HUD & REAL-TIME LOGGING ENGINE (SWARM-161)
 * Target: Windows 10 LTSC Build 19044 | Conhost / Windows Terminal
 * ========================================================================= */
#define VT_CLEAR_SCREEN      "\033[2J"
#define VT_HOME              "\033[H"
#define VT_CLEAR_TO_EOL      "\033[K"
#define VT_SAVE_CURSOR       "\033[s"
#define VT_RESTORE_CURSOR    "\033[u"
#define VT_HIDE_CURSOR       "\033[?25l"
#define VT_SHOW_CURSOR       "\033[?25h"
#define VT_RESET_MARGINS     "\033[r"

#define BG_HEADER1           "\033[48;5;236m"
#define BG_HEADER2           "\033[48;5;234m"

static void format_bytes_human(uint64_t b, char *out, size_t sz) {
    if (b < 1024) snprintf(out, sz, "%llu B", (unsigned long long)b);
    else if (b < 1024 * 1024) snprintf(out, sz, "%.1f KB", (double)b / 1024.0);
    else if (b < 1024 * 1024 * 1024) snprintf(out, sz, "%.1f MB", (double)b / (1024.0 * 1024.0));
    else snprintf(out, sz, "%.2f GB", (double)b / (1024.0 * 1024.0 * 1024.0));
}

static void format_uptime_human(uint64_t sec, char *out, size_t sz) {
    unsigned int h = (unsigned int)(sec / 3600);
    unsigned int m = (unsigned int)((sec % 3600) / 60);
    unsigned int s = (unsigned int)(sec % 60);
    if (h > 0) snprintf(out, sz, "%uh %02um %02us", h, m, s);
    else snprintf(out, sz, "%02um %02us", m, s);
}

static void console_setup_vt(void);
static void console_ui_init(void) {
    InitializeCriticalSection(&g_console_lock);
    g_ui_start_tick = GetTickCount64();
    console_setup_vt();
}

/* ---- ANSI bridge for consoles without VT support (XP, Vista, 7, 8, early 10) ----
 * The agent's console output uses ANSI colour sequences. Old consoles print them raw
 * ("[96m..."), so stdout/stderr are redirected into a pipe; a small thread strips the
 * escape sequences, maps SGR colours to native console attributes and writes UTF-16. */
static HANDLE g_ansi_con = NULL;
static WORD g_ansi_base = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

static WORD ansi_rgb_attr(int r, int g, int b, int bg) {
    int mx = r > g ? (r > b ? r : b) : (g > b ? g : b);
    WORD a = 0;
    if (r > mx / 2 && r > 40) a |= bg ? BACKGROUND_RED : FOREGROUND_RED;
    if (g > mx / 2 && g > 40) a |= bg ? BACKGROUND_GREEN : FOREGROUND_GREEN;
    if (b > mx / 2 && b > 40) a |= bg ? BACKGROUND_BLUE : FOREGROUND_BLUE;
    if (mx > 170) a |= bg ? BACKGROUND_INTENSITY : FOREGROUND_INTENSITY;
    return a;
}
static WORD ansi_apply_sgr(WORD attr, const char *seq) {
    static const WORD c8[8] = { 0, FOREGROUND_RED, FOREGROUND_GREEN, FOREGROUND_RED | FOREGROUND_GREEN, FOREGROUND_BLUE,
                                FOREGROUND_RED | FOREGROUND_BLUE, FOREGROUND_GREEN | FOREGROUND_BLUE,
                                FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE };
    int v[16], n = 0; const char *q = seq;
    if (!*q) { v[n++] = 0; }
    while (*q && n < 16) { v[n++] = atoi(q); while (*q && *q != ';') q++; if (*q == ';') q++; }
    const WORD FG = 0x0F, BG = 0xF0;
    for (int i = 0; i < n; i++) {
        int c = v[i];
        if (c == 0) attr = g_ansi_base;
        else if (c == 1) attr |= FOREGROUND_INTENSITY;
        else if (c == 2 || c == 22) attr &= (WORD)~FOREGROUND_INTENSITY;
        else if (c >= 30 && c <= 37) attr = (WORD)((attr & BG) | c8[c - 30]);
        else if (c >= 90 && c <= 97) attr = (WORD)((attr & BG) | c8[c - 90] | FOREGROUND_INTENSITY);
        else if (c == 39) attr = (WORD)((attr & BG) | (g_ansi_base & FG));
        else if (c >= 40 && c <= 47) attr = (WORD)((attr & FG) | (c8[c - 40] << 4));
        else if (c >= 100 && c <= 107) attr = (WORD)((attr & FG) | (c8[c - 100] << 4) | BACKGROUND_INTENSITY);
        else if (c == 49) attr = (WORD)((attr & FG) | (g_ansi_base & BG));
        else if ((c == 38 || c == 48) && i + 1 < n) {
            int bg = c == 48; WORD a = 0;
            if (v[i + 1] == 5 && i + 2 < n) {                 /* 256-colour: grey ramp / cube / basic */
                int k = v[i + 2], r, g, b;
                if (k < 16) { a = (WORD)(c8[k & 7] | (k > 7 ? FOREGROUND_INTENSITY : 0)); if (bg) a = (WORD)(a << 4); }
                else if (k >= 232) { r = g = b = 8 + (k - 232) * 10; a = ansi_rgb_attr(r, g, b, bg); }
                else { k -= 16; r = (k / 36) * 51; g = ((k / 6) % 6) * 51; b = (k % 6) * 51; a = ansi_rgb_attr(r, g, b, bg); }
                i += 2;
            } else if (v[i + 1] == 2 && i + 4 < n) { a = ansi_rgb_attr(v[i + 2], v[i + 3], v[i + 4], bg); i += 4; }
            attr = bg ? (WORD)((attr & FG) | a) : (WORD)((attr & BG) | a);
        }
    }
    return attr;
}
static void ansi_emit(const char *t, int len, char *carry, int *carry_n) {
    /* keep an incomplete trailing UTF-8 sequence for the next chunk */
    int cut = len, k = len - 1, back = 0;
    while (k >= 0 && back < 3 && ((unsigned char)t[k] & 0xC0) == 0x80) { k--; back++; }
    if (k >= 0) {
        unsigned char lead = (unsigned char)t[k]; int need = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
        if (need > len - k) cut = k;
    }
    if (cut > 0) {
        WCHAR w[4200]; DWORD wr = 0;
        int nw = MultiByteToWideChar(CP_UTF8, 0, t, cut, w, 4200);
        if (nw <= 0) nw = MultiByteToWideChar(CP_ACP, 0, t, cut, w, 4200);
        if (nw > 0) WriteConsoleW(g_ansi_con, w, (DWORD)nw, &wr, NULL);
    }
    *carry_n = len - cut;
    if (*carry_n > 0) memcpy(carry, t + cut, (size_t)*carry_n);
}
static DWORD WINAPI ansi_bridge_thread(LPVOID p) {
    HANDLE rd = (HANDLE)p;
    char in[4096], text[4100], seq[64], carry[4];
    int state = 0, sl = 0, carry_n = 0;
    WORD attr = g_ansi_base;
    DWORD n;
    while (ReadFile(rd, in, sizeof(in), &n, NULL) && n > 0) {
        int tl = 0;
        if (carry_n) { memcpy(text, carry, (size_t)carry_n); tl = carry_n; carry_n = 0; }
        for (DWORD i = 0; i < n; i++) {
            char c = in[i];
            if (state == 0) {
                if (c == 0x1B) { ansi_emit(text, tl, carry, &carry_n); tl = 0; if (carry_n) { memcpy(text, carry, (size_t)carry_n); tl = carry_n; carry_n = 0; } state = 1; }
                else if (c != '\r') { text[tl++] = c; if (tl >= 4096) { ansi_emit(text, tl, carry, &carry_n); tl = 0; if (carry_n) { memcpy(text, carry, (size_t)carry_n); tl = carry_n; carry_n = 0; } } }
            } else if (state == 1) {
                if (c == '[') { state = 2; sl = 0; } else state = 0;      /* ESC 7 / ESC 8 etc.: dropped */
            } else {
                if (c >= 0x40 && c <= 0x7E) {
                    seq[sl] = '\0';
                    if (c == 'm') { attr = ansi_apply_sgr(attr, seq); SetConsoleTextAttribute(g_ansi_con, attr); }
                    state = 0;                                         /* cursor/region sequences: dropped */
                } else if (sl < 63) seq[sl++] = c;
            }
        }
        ansi_emit(text, tl, carry, &carry_n);
    }
    return 0;
}
/* Real OS major version (RtlGetVersion does not lie like GetVersionEx without a manifest). */
static DWORD os_major_version(void) {
    typedef LONG (WINAPI *rtlgetver_t)(OSVERSIONINFOW *);
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    rtlgetver_t fn = nt ? (rtlgetver_t)(void *)GetProcAddress(nt, "RtlGetVersion") : NULL;
    OSVERSIONINFOW vi; ZeroMemory(&vi, sizeof(vi)); vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn && fn(&vi) == 0) return vi.dwMajorVersion;
    return 5;
}
static void console_install_ansi_bridge(void) {
    static volatile LONG installed = 0;
    if (InterlockedCompareExchange(&installed, 1, 0) != 0) return;
    g_ansi_con = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (g_ansi_con == INVALID_HANDLE_VALUE) { g_ansi_con = NULL; InterlockedExchange(&installed, 0); return; }
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (GetConsoleScreenBufferInfo(g_ansi_con, &ci)) g_ansi_base = ci.wAttributes;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, NULL, 1 << 16)) { CloseHandle(g_ansi_con); g_ansi_con = NULL; InterlockedExchange(&installed, 0); return; }
    int fd = _open_osfhandle((intptr_t)wr, _O_BINARY | _O_WRONLY);
    if (fd < 0) { CloseHandle(rd); CloseHandle(wr); CloseHandle(g_ansi_con); g_ansi_con = NULL; InterlockedExchange(&installed, 0); return; }
    fflush(stdout); fflush(stderr);
    _dup2(fd, _fileno(stdout));
    _dup2(fd, _fileno(stderr));
    HANDLE th = CreateThread(NULL, 64 * 1024, ansi_bridge_thread, rd, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (th) CloseHandle(th);
}

/* VT mode + log scroll region on whatever console is attached now (startup or on demand). */
static void console_setup_vt(void) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE || hOut == NULL) return;
    if (GetFileType(hOut) != FILE_TYPE_CHAR) return;

    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return;
    if (os_major_version() >= 10 && SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        g_vt_enabled = true;                 /* VT sequences exist only since Windows 10 */
    } else {
        console_install_ansi_bridge();   /* XP/7/8: translate colours instead of printing raw escapes */
    }
    SetConsoleOutputCP(CP_UTF8);

    if (g_vt_enabled) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        int h = 25;
        if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
            h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
            g_last_viewport_h = h;
            g_last_viewport_w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        }
        printf(VT_CLEAR_SCREEN VT_HOME);
        printf("\033[3;%dr", h > 4 ? h : 25);
        printf("\033[3;1H");
        fflush(stdout);
    }
}

/* Status-window "Show console" button. The GUI build has no console; one is
 * allocated on first use (recent log replayed into it) and then shown/hidden.
 * Its close box is removed: closing a console window would kill the agent. */
void bw_console_toggle(void) {
    EnterCriticalSection(&g_console_lock);
    HWND cw = GetConsoleWindow();
    if (!cw) {
        if (AllocConsole()) {
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
            freopen("CONIN$", "r", stdin);
            /* inherited/redirected std handles survive AllocConsole: point them at the new console */
            HANDLE co = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (co != INVALID_HANDLE_VALUE) { SetStdHandle(STD_OUTPUT_HANDLE, co); SetStdHandle(STD_ERROR_HANDLE, co); }
            cw = GetConsoleWindow();
            if (cw) {
                HMENU sm = GetSystemMenu(cw, FALSE);
                if (sm) DeleteMenu(sm, SC_CLOSE, MF_BYCOMMAND);
            }
            SetConsoleTitleA("Bridge Agent - console (hide it from the status window)");
            console_setup_vt();
            /* replay what happened before the console existed */
            EnterCriticalSection(&g_log_lock);
            size_t n = g_log_count;
            for (size_t i = 0; i < n; i++) {
                LogEntry *e = &g_log_ring[(g_log_head + LOG_RING_CAPACITY - n + i) % LOG_RING_CAPACITY];
                printf("[%-5s] [+%6llums] %s\n", log_level_str(e->level), (unsigned long long)e->uptime_ms, e->msg);
            }
            LeaveCriticalSection(&g_log_lock);
            fflush(stdout);
        }
        if (cw) { ShowWindow(cw, SW_SHOW); SetForegroundWindow(cw); }
    } else {
        ShowWindow(cw, IsWindowVisible(cw) ? SW_HIDE : SW_SHOW);
    }
    LeaveCriticalSection(&g_console_lock);
}

bool bw_console_visible(void) {
    HWND cw = GetConsoleWindow();
    return cw && IsWindowVisible(cw);
}

/* Fatal start-up message: stderr when there is one, else a message box (GUI build, double-click). */
static void startup_fatal(const char *msg) {
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) fprintf(stderr, "%s\n", msg);
    else MessageBoxA(NULL, msg, "Bridge Agent", MB_OK | MB_ICONERROR);
}

static void console_ui_shutdown(void) {
    if (g_vt_enabled) {
        printf(VT_RESET_MARGINS VT_SHOW_CURSOR);
        fflush(stdout);
    }
    DeleteCriticalSection(&g_console_lock);
}

static void hud_render(void) {
    if (!g_vt_enabled) return;

    EnterCriticalSection(&g_console_lock);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
        int cur_h = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        int cur_w = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        if (cur_h != g_last_viewport_h && cur_h > 4) {
            g_last_viewport_h = cur_h;
            g_last_viewport_w = cur_w;
            printf("\033[3;%dr", cur_h);
        }
    }

    const char *cpu_clr = CLR_GREEN;
    if (g_cpu_load_pct > 80.0) cpu_clr = CLR_RED CLR_BOLD;
    else if (g_cpu_load_pct > 50.0) cpu_clr = CLR_YELLOW;

    uint64_t ram_free_mb = g_ram_avail_bytes / (1024 * 1024);
    uint64_t ram_tot_mb = g_ram_total_bytes / (1024 * 1024);
    const char *ram_clr = CLR_GREEN;
    if (ram_free_mb < 50) ram_clr = CLR_RED CLR_BOLD;
    else if (ram_free_mb < 75) ram_clr = CLR_YELLOW;

    float gpu_t = query_gpu_temperature();
    char gpu_str[32];
    const char *gpu_clr = CLR_GREEN;
    if (gpu_t < 0.0f) {
        snprintf(gpu_str, sizeof(gpu_str), "N/A");
        gpu_clr = CLR_DIM;
    } else {
        snprintf(gpu_str, sizeof(gpu_str), "%.1f C", gpu_t);
        if (gpu_t >= 72.0f) gpu_clr = CLR_RED CLR_BOLD;
        else if (gpu_t >= 65.0f) gpu_clr = CLR_YELLOW;
    }

    EnterCriticalSection(&g_kiosk_sentinel_lock);
    KioskSentinelState ks = g_kiosk_sentinel;
    LeaveCriticalSection(&g_kiosk_sentinel_lock);

    const char *kiosk_status;
    if (!ks.enabled) {
        kiosk_status = CLR_DIM "OFF" CLR_RESET;
    } else if (ks.circuit_breaker_tripped) {
        kiosk_status = CLR_RED CLR_BOLD "BREAKER TRIPPED" CLR_RESET;
    } else if (ks.is_hung) {
        kiosk_status = CLR_RED CLR_BOLD "HUNG" CLR_RESET;
    } else if (ks.is_running) {
        kiosk_status = CLR_GREEN CLR_BOLD "HEALTHY" CLR_RESET;
    } else {
        kiosk_status = CLR_YELLOW "STOPPED" CLR_RESET;
    }

    char rx_str[32], tx_str[32], up_str[32];
    format_bytes_human(g_bytes_rx, rx_str, sizeof(rx_str));
    format_bytes_human(g_bytes_tx, tx_str, sizeof(tx_str));
    format_uptime_human((GetTickCount64() - g_ui_start_tick) / 1000ULL, up_str, sizeof(up_str));

    printf(VT_HIDE_CURSOR VT_SAVE_CURSOR);

    /* --- Line 1: Host, PID, CPU, RAM, GPU Diode --- */
    printf("\033[1;1H" BG_HEADER1 CLR_BOLD CLR_CYAN " [BRIDGE v" BRIDGE_PROTOCOL_VERSION "] " CLR_RESET
           BG_HEADER1 CLR_DIM "PID:" CLR_RESET BG_HEADER1 CLR_YELLOW "%-6lu " CLR_RESET
           BG_HEADER1 CLR_DIM "CPU:" CLR_RESET BG_HEADER1 "%s%5.1f%% " CLR_RESET
           BG_HEADER1 CLR_DIM "RAM:" CLR_RESET BG_HEADER1 "%s%lluMB" CLR_DIM "/%lluMB " CLR_RESET
           BG_HEADER1 CLR_DIM "GPU:" CLR_RESET BG_HEADER1 "%s%-8s " CLR_RESET
           BG_HEADER1 CLR_DIM "HOST:" CLR_RESET BG_HEADER1 CLR_WHITE "%s:%u " CLR_RESET
           BG_HEADER1 VT_CLEAR_TO_EOL CLR_RESET,
           (unsigned long)GetCurrentProcessId(), cpu_clr, g_cpu_load_pct, ram_clr,
           (unsigned long long)ram_free_mb, (unsigned long long)ram_tot_mb,
           gpu_clr, gpu_str, g_master_host, (unsigned int)g_master_port);

    /* --- Line 2: Packets RX/TX, Total Calls, Kiosk Sentinel, Uptime --- */
    printf("\033[2;1H" BG_HEADER2 CLR_BOLD CLR_BLUE " [NET/KIOSK]    " CLR_RESET
           BG_HEADER2 CLR_DIM "RX:" CLR_RESET BG_HEADER2 CLR_CYAN "%llu " CLR_DIM "(%s) " CLR_RESET
           BG_HEADER2 CLR_DIM "TX:" CLR_RESET BG_HEADER2 CLR_GREEN "%llu " CLR_DIM "(%s) " CLR_RESET
           BG_HEADER2 CLR_DIM "CALLS:" CLR_RESET BG_HEADER2 CLR_YELLOW "%-5llu " CLR_RESET
           BG_HEADER2 CLR_DIM "KIOSK:" CLR_RESET BG_HEADER2 "[%s" BG_HEADER2 "] " CLR_RESET
           BG_HEADER2 CLR_DIM "UP:" CLR_RESET BG_HEADER2 CLR_WHITE "%-8s " CLR_RESET
           BG_HEADER2 VT_CLEAR_TO_EOL CLR_RESET,
           (unsigned long long)g_packets_rx, rx_str, (unsigned long long)g_packets_tx, tx_str,
           (unsigned long long)g_rpc_calls_total, kiosk_status, up_str);

    printf(VT_RESTORE_CURSOR VT_SHOW_CURSOR);
    fflush(stdout);

    LeaveCriticalSection(&g_console_lock);
}

static void console_log_packet_rx(int64_t id, const char *method, const char *summary) {
    EnterCriticalSection(&g_console_lock);
    g_packets_rx++;

    SYSTEMTIME st;
    GetLocalTime(&st);

    printf("%02d:%02d:%02d.%03d " CLR_CYAN CLR_BOLD "[RX >]" CLR_RESET
           " " CLR_YELLOW "#%-4lld" CLR_RESET
           " " CLR_WHITE CLR_BOLD "%-18s" CLR_RESET
           " " CLR_DIM "%s" CLR_RESET "\n",
           st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
           (long long)id, method ? method : "UNKNOWN", summary ? summary : "");
    fflush(stdout);
    LeaveCriticalSection(&g_console_lock);
}

static void console_log_packet_tx(int64_t id, const char *method, int err_code, uint64_t duration_ms, size_t resp_bytes) {
    EnterCriticalSection(&g_console_lock);
    g_packets_tx++;
    g_bytes_tx += resp_bytes;

    SYSTEMTIME st;
    GetLocalTime(&st);

    const char *dur_clr = CLR_GREEN;
    if (duration_ms > 100) dur_clr = CLR_MAGENTA;
    else if (duration_ms > 20) dur_clr = CLR_YELLOW;

    char sz_str[32];
    format_bytes_human(resp_bytes, sz_str, sizeof(sz_str));

    if (err_code == 0) {
        printf("%02d:%02d:%02d.%03d " CLR_GREEN CLR_BOLD "[TX <]" CLR_RESET
               " " CLR_YELLOW "#%-4lld" CLR_RESET
               " " CLR_WHITE "%-18s" CLR_RESET
               " " CLR_GREEN "OK" CLR_RESET
               "  " CLR_DIM "[" CLR_RESET "%s%3llums" CLR_RESET CLR_DIM "]" CLR_RESET
               "  " CLR_DIM "(%s)" CLR_RESET "\n",
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               (long long)id, method ? method : "UNKNOWN", dur_clr, (unsigned long long)duration_ms, sz_str);
    } else {
        printf("%02d:%02d:%02d.%03d " CLR_RED CLR_BOLD "[TX < ERR]" CLR_RESET
               " " CLR_YELLOW "#%-4lld" CLR_RESET
               " " CLR_WHITE "%-18s" CLR_RESET
               " " CLR_RED CLR_BOLD "ERR %d" CLR_RESET
               "  " CLR_DIM "[" CLR_RESET "%s%3llums" CLR_RESET CLR_DIM "]" CLR_RESET
               "  " CLR_DIM "(%s)" CLR_RESET "\n",
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
               (long long)id, method ? method : "UNKNOWN", err_code, dur_clr, (unsigned long long)duration_ms, sz_str);
    }
    fflush(stdout);
    LeaveCriticalSection(&g_console_lock);
}

/* =========================================================================
 * MODULE: WIN32 PROCESS PRIORITY & AFFINITY GUARDIAN (SWARM-163)
 * Target: Low-power dual-core APU (AMD Ontario C-60 1.0 GHz, 2 cores)
 * Foreground media (chrome.exe, mpv.exe): ABOVE_NORMAL_PRIORITY_CLASS, Core 0 + Core 1 (mask 0x03)
 * Background bloat (SearchApp, telemetry svchost): IDLE_PRIORITY_CLASS, Core 1 only (mask 0x02)
 * ========================================================================= */
#define MAX_TRACKED_PIDS 128
typedef struct {
    DWORD pid;
    DWORD priority_class;
    DWORD_PTR affinity_mask;
} ProcessPriorityEntry;

static ProcessPriorityEntry g_proc_priority_cache[MAX_TRACKED_PIDS];
static size_t g_proc_priority_cache_count = 0;

static bool is_pid_cached_with_settings(DWORD pid, DWORD prio, DWORD_PTR affinity) {
    for (size_t i = 0; i < g_proc_priority_cache_count; i++) {
        if (g_proc_priority_cache[i].pid == pid) {
            if (g_proc_priority_cache[i].priority_class == prio &&
                g_proc_priority_cache[i].affinity_mask == affinity) {
                return true;
            }
            g_proc_priority_cache[i].priority_class = prio;
            g_proc_priority_cache[i].affinity_mask = affinity;
            return false;
        }
    }
    if (g_proc_priority_cache_count < MAX_TRACKED_PIDS) {
        g_proc_priority_cache[g_proc_priority_cache_count].pid = pid;
        g_proc_priority_cache[g_proc_priority_cache_count].priority_class = prio;
        g_proc_priority_cache[g_proc_priority_cache_count].affinity_mask = affinity;
        g_proc_priority_cache_count++;
    }
    return false;
}

static void evaluate_priority_guardian(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(hSnap, &pe)) {
        CloseHandle(hSnap);
        return;
    }

    do {
        if (pe.th32ProcessID <= 4) continue;

        DWORD target_prio = 0;
        DWORD_PTR target_affinity = 0;

        if (_stricmp(pe.szExeFile, "chrome.exe") == 0 ||
            _stricmp(pe.szExeFile, "supermium.exe") == 0 ||
            _stricmp(pe.szExeFile, "mpv.exe") == 0) {
            target_prio = ABOVE_NORMAL_PRIORITY_CLASS;
            target_affinity = 0x03; /* Both cores 0 & 1 */
        } else if (_stricmp(pe.szExeFile, "SearchApp.exe") == 0 ||
                   _stricmp(pe.szExeFile, "StartMenuExperienceHost.exe") == 0 ||
                   _stricmp(pe.szExeFile, "CompatTelRunner.exe") == 0 ||
                   _stricmp(pe.szExeFile, "wermgr.exe") == 0 ||
                   _stricmp(pe.szExeFile, "sedlauncher.exe") == 0 ||
                   _stricmp(pe.szExeFile, "TiWorker.exe") == 0 ||
                   _stricmp(pe.szExeFile, "TrustedInstaller.exe") == 0) {
            target_prio = IDLE_PRIORITY_CLASS;
            target_affinity = 0x02; /* Shield Core 0: bind to Core 1 only */
        }

        if (target_prio != 0) {
            if (!is_pid_cached_with_settings(pe.th32ProcessID, target_prio, target_affinity)) {
                HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    SetPriorityClass(hProc, target_prio);
                    SetProcessAffinityMask(hProc, target_affinity);
                    CloseHandle(hProc);
                }
            }
        }
    } while (Process32Next(hSnap, &pe));

    CloseHandle(hSnap);
}

/* =========================================================================
 * TELEMETRY THREAD (BACKGROUND CPU % & PROCESS I/O SAMPLING)
 * ========================================================================= */
static uint64_t ft_to_u64(const FILETIME *ft) {
    return ((uint64_t)ft->dwHighDateTime << 32) | (uint64_t)ft->dwLowDateTime;
}

static DWORD WINAPI TelemetryThread(LPVOID lpParam) {
    (void)lpParam;
    FILETIME prev_idle, prev_kern, prev_user;
    GetSystemTimes(&prev_idle, &prev_kern, &prev_user);

    IO_COUNTERS prev_io;
    ZeroMemory(&prev_io, sizeof(prev_io));
    GetProcessIoCounters(GetCurrentProcess(), &prev_io);

    while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
        Sleep(1000);
        FILETIME cur_idle, cur_kern, cur_user;
        if (GetSystemTimes(&cur_idle, &cur_kern, &cur_user)) {
            uint64_t idl = ft_to_u64(&cur_idle) - ft_to_u64(&prev_idle);
            uint64_t krn = ft_to_u64(&cur_kern) - ft_to_u64(&prev_kern);
            uint64_t usr = ft_to_u64(&cur_user) - ft_to_u64(&prev_user);
            uint64_t sys = krn + usr;
            double pct = (sys > 0 && idl <= sys) ? ((double)(sys - idl) * 100.0 / (double)sys) : 0.0;
            prev_idle = cur_idle;
            prev_kern = cur_kern;
            prev_user = cur_user;

            IO_COUNTERS cur_io;
            ZeroMemory(&cur_io, sizeof(cur_io));
            GetProcessIoCounters(GetCurrentProcess(), &cur_io);

            MEMORYSTATUSEX msex;
            msex.dwLength = sizeof(msex);
            if (GlobalMemoryStatusEx(&msex)) {
                EnterCriticalSection(&g_telemetry_lock);
                g_ram_avail_bytes = msex.ullAvailPhys;
                g_ram_total_bytes = msex.ullTotalPhys;
                LeaveCriticalSection(&g_telemetry_lock);

                /* SWARM-164: Autonomous Dual-Tier Working Set Memory Guard */
                if (InterlockedCompareExchange(&g_trim_daemon_enabled, 1, 1) == 1) {
                    uint64_t now_tick = GetTickCount64();
                    bool is_emergency = (msex.ullAvailPhys < TRIM_RAM_EMERGENCY_BYTES);
                    bool is_proactive = (msex.ullAvailPhys < TRIM_RAM_PROACTIVE_BYTES);

                    if (is_proactive) {
                        if (now_tick - g_last_trim_tick >= g_trim_effective_cooldown_ms) {
                            g_last_trim_tick = now_tick;
                            if (is_emergency) {
                                agent_log(LOG_LVL_WARN, "[MEM-GUARD] Emergency low RAM: %lu MB < 45 MB. Running urgent trim...",
                                          (unsigned long)(msex.ullAvailPhys / (1024 * 1024)));
                            } else {
                                agent_log(LOG_LVL_INFO, "[MEM-GUARD] Proactive low RAM: %lu MB < 60 MB. Running smart trim...",
                                          (unsigned long)(msex.ullAvailPhys / (1024 * 1024)));
                            }
                            SmartTrimStats st;
                            run_smart_trim(&st);
                            int64_t reclaimed_bytes = (st.ram_after_bytes > st.ram_before_bytes) ? (int64_t)(st.ram_after_bytes - st.ram_before_bytes) : 0;
                            if (reclaimed_bytes < (4LL * 1024 * 1024)) {
                                g_trim_effective_cooldown_ms = TRIM_BACKOFF_COOLDOWN_MS;
                            } else {
                                g_trim_effective_cooldown_ms = TRIM_COOLDOWN_MS;
                            }
                            agent_log(LOG_LVL_INFO, "[MEM-GUARD] Trim finished: %u processes trimmed (%lld KB reclaimed). Free RAM: %lu MB -> %lu MB",
                                      st.processes_trimmed, (long long)(reclaimed_bytes / 1024),
                                      (unsigned long)(st.ram_before_bytes / (1024 * 1024)),
                                      (unsigned long)(st.ram_after_bytes / (1024 * 1024)));
                        }
                    }
                }
            }

            EnterCriticalSection(&g_telemetry_lock);
            g_cpu_load_pct = pct;
            g_io_read_bytes_sec = (cur_io.ReadTransferCount >= prev_io.ReadTransferCount) ? (cur_io.ReadTransferCount - prev_io.ReadTransferCount) : 0;
            g_io_write_bytes_sec = (cur_io.WriteTransferCount >= prev_io.WriteTransferCount) ? (cur_io.WriteTransferCount - prev_io.WriteTransferCount) : 0;
            g_io_total_read_bytes = cur_io.ReadTransferCount;
            g_io_total_write_bytes = cur_io.WriteTransferCount;
            g_telemetry_last_tick = GetTickCount64();
            LeaveCriticalSection(&g_telemetry_lock);

            /* SWARM-130: 60-Second In-Memory Ring Buffer Sampler (Zero-Disk-I/O) */
            static uint32_t s_sample_sec_counter = 0;
            s_sample_sec_counter++;

            /* Record sample at tick 1 (startup) and every 60 seconds thereafter */
            if (s_sample_sec_counter == 1 || s_sample_sec_counter % 60 == 0) {
                if (g_telemetry_ring) {
                    EnterCriticalSection(&g_telemetry_ring_lock);
                    TelemetrySample *s = &g_telemetry_ring->samples[g_telemetry_ring->head];
                    s->timestamp_sec = (uint64_t)time(NULL);
                    s->uptime_sec = (uint32_t)(GetTickCount64() / 1000ULL);
                    s->cpu_pct = (float)pct;
                    s->ram_avail_mb = (uint32_t)(msex.ullAvailPhys / (1024 * 1024));

                    GpuTelemetry gt;
                    query_gpu_telemetry(&gt);
                    s->gpu_temp_c = gt.temp_c;
                    s->gpu_engine_mhz = (int16_t)gt.engine_clock_mhz;
                    s->gpu_activity_pct = (int8_t)gt.activity_pct;

                    g_telemetry_ring->head = (g_telemetry_ring->head + 1) % TELEMETRY_HISTORY_SAMPLES;
                    if (g_telemetry_ring->count < TELEMETRY_HISTORY_SAMPLES) {
                        g_telemetry_ring->count++;
                    }
                    g_telemetry_ring->total_recorded++;
                    LeaveCriticalSection(&g_telemetry_ring_lock);

                    /* SWARM-140: Autonomous Drift Sentinel Evaluation */
                    evaluate_drift_sentinel();
                }
            }

            /* SWARM-150: Autonomous Kiosk Sentinel Evaluation every 3 seconds */
            if (s_sample_sec_counter % 3 == 0) {
                evaluate_kiosk_sentinel();
            }

            /* SWARM-163: Autonomous Process Priority Guardian every 5 seconds */
            if (s_sample_sec_counter % 5 == 0) {
                evaluate_priority_guardian();
            }

            if (InterlockedCompareExchange(&g_cmd_executing, 0, 0) == 0 && InterlockedCompareExchange(&g_running, 1, 1) == 1) {
                char title[160];
                float gpu_t = query_gpu_temperature();
                if (gpu_t >= 0.0f) {
                    snprintf(title, sizeof(title), "Bridge Agent v" BRIDGE_PROTOCOL_VERSION " [IDLE] \xE2\x97\x8F %s:%u | RAM: %luMB Free | CPU: %.1f%% | GPU: %.1f\xC2\xB0" "C",
                             g_master_host, (unsigned int)g_master_port,
                             (unsigned long)(g_ram_avail_bytes / (1024 * 1024)), g_cpu_load_pct, gpu_t);
                } else {
                    snprintf(title, sizeof(title), "Bridge Agent v" BRIDGE_PROTOCOL_VERSION " [IDLE] \xE2\x97\x8F %s:%u | RAM: %luMB Free | CPU: %.1f%%",
                             g_master_host, (unsigned int)g_master_port,
                             (unsigned long)(g_ram_avail_bytes / (1024 * 1024)), g_cpu_load_pct);
                }
                set_title_utf8(title);
            }

            prev_io = cur_io;
        }
    }
    return 0;
}

/* =========================================================================
 * MODULE 1: COMMAND EXECUTION & PROCESS TREE TERMINATION
 * ========================================================================= */
typedef struct {
    HANDLE hPipe;
    DynBuf buf;
} PipeReaderCtx;

static DWORD WINAPI PipeReaderThread(LPVOID lpParam) {
    PipeReaderCtx *ctx = (PipeReaderCtx *)lpParam;
    char tmp[4096];
    DWORD bread = 0;
    while (ReadFile(ctx->hPipe, tmp, sizeof(tmp), &bread, NULL) && bread > 0) {
        if (ctx->buf.len < MAX_PIPE_BUFFER_BYTES) {
            db_append_mem(&ctx->buf, tmp, bread);
        }
    }
    return 0;
}

static int kill_process_tree(DWORD root_pid) {
    int killed = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (pe.th32ParentProcessID == root_pid && pe.th32ProcessID != root_pid) {
                    killed += kill_process_tree(pe.th32ProcessID);
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, root_pid);
    if (hProc) {
        if (TerminateProcess(hProc, 137)) killed++;
        CloseHandle(hProc);
    }
    return killed;
}

static void handle_exec_run(const char *req, int64_t id, DynBuf *resp) {
    char *cmd_b64 = json_get_string(req, "cmd_b64");
    char *plain_cmd = json_get_string(req, "command");
    if (!plain_cmd) plain_cmd = json_get_string(req, "cmd");
    char *shell = json_get_string(req, "shell");
    char *cwd = json_get_string(req, "cwd");
    int64_t timeout_ms = json_get_int64(req, "timeout_ms", 0);
    if (timeout_ms <= 0) {
        timeout_ms = json_get_int64(req, "timeout_seconds", 0) * 1000;
    }
    if (timeout_ms <= 0) {
        timeout_ms = 120000; /* 120s default */
    }

    char *raw_cmd = NULL;
    if (cmd_b64) {
        size_t cmd_len = 0;
        raw_cmd = (char *)b64_decode(cmd_b64, &cmd_len);
        free(cmd_b64);
    } else if (plain_cmd) {
        raw_cmd = plain_cmd;
        plain_cmd = NULL;
    }
    if (plain_cmd) free(plain_cmd);

    if (!raw_cmd) {
        free(shell); free(cwd);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing command or cmd_b64", 0);
        return;
    }

    size_t cmd_len = strlen(raw_cmd);
    DynBuf full_cmd;
    db_init(&full_cmd, cmd_len + 128);
    if (shell && _stricmp(shell, "powershell") == 0) {
        db_append_str(&full_cmd, "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ");
        db_append_str(&full_cmd, raw_cmd);
    } else if (shell && _stricmp(shell, "direct") == 0) {
        db_append_str(&full_cmd, raw_cmd);
    } else {
        db_append_str(&full_cmd, "cmd.exe /c ");
        db_append_str(&full_cmd, raw_cmd);
    }

    InterlockedExchange(&g_cmd_executing, 1);
    uint64_t start_tick = GetTickCount64();

    // Real-time Visual Console Card (Reception)
    printf("\n" CLR_CYAN "  +-- [RX: EXEC] ID #%lld " CLR_RESET "--------------------------------------------------\n", (long long)id);
    printf("  " CLR_DIM "|" CLR_RESET " " CLR_WHITE "%s" CLR_RESET "\n", raw_cmd);
    printf("  " CLR_DIM "|" CLR_RESET " Shell: " CLR_YELLOW "%s" CLR_RESET " | Timeout: " CLR_YELLOW "%lldms" CLR_RESET "%s%s\n",
           shell ? shell : "cmd", (long long)timeout_ms,
           (cwd && strlen(cwd) > 0) ? " | Cwd: " : "",
           (cwd && strlen(cwd) > 0) ? cwd : "");
    printf("  " CLR_DIM "|" CLR_RESET " " CLR_MAGENTA "[EXECUTING...]" CLR_RESET "\n");
    fflush(stdout);

    char title_buf[160];
    snprintf(title_buf, sizeof(title_buf), "Bridge Agent [RUNNING: %.35s...] \xE2\x97\x8F PID %lu", raw_cmd, (unsigned long)GetCurrentProcessId());
    set_title_utf8(title_buf);

    agent_log(LOG_LVL_INFO, CLR_MAGENTA "[EXEC START]" CLR_RESET " %s", raw_cmd);
    free(raw_cmd);
    free(shell);

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hOutR = NULL, hOutW = NULL, hErrR = NULL, hErrW = NULL;
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0) || !SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0) ||
        !CreatePipe(&hErrR, &hErrW, &sa, 0) || !SetHandleInformation(hErrR, HANDLE_FLAG_INHERIT, 0)) {
        DWORD err = GetLastError();
        if (hOutR) CloseHandle(hOutR);
        if (hOutW) CloseHandle(hOutW);
        if (hErrR) CloseHandle(hErrR);
        if (hErrW) CloseHandle(hErrW);
        db_free(&full_cmd);
        free(cwd);
        InterlockedExchange(&g_cmd_executing, 0);
        build_error_response(resp, id, RPC_ERR_EXEC_FAILED, "CreatePipe failed", err);
        return;
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hOutW;
    si.hStdError = hErrW;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    ZeroMemory(&pi, sizeof(pi));

    const char *work_dir = (cwd && strlen(cwd) > 0) ? cwd : NULL;
    BOOL started = CreateProcessA(NULL, full_cmd.data, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, work_dir, &si, &pi);
    DWORD create_err = GetLastError();
    db_free(&full_cmd);
    free(cwd);

    CloseHandle(hOutW);
    CloseHandle(hErrW);

    if (!started) {
        CloseHandle(hOutR);
        CloseHandle(hErrR);
        InterlockedExchange(&g_cmd_executing, 0);
        build_error_response(resp, id, RPC_ERR_EXEC_FAILED, "CreateProcessA failed", create_err);
        return;
    }

    PipeReaderCtx outCtx = { hOutR, { NULL, 0, 0 } };
    PipeReaderCtx errCtx = { hErrR, { NULL, 0, 0 } };
    db_init(&outCtx.buf, 1024);
    db_init(&errCtx.buf, 1024);

    HANDLE hThreads[2];
    hThreads[0] = CreateThread(NULL, 64 * 1024, PipeReaderThread, &outCtx, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    hThreads[1] = CreateThread(NULL, 64 * 1024, PipeReaderThread, &errCtx, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);

    DWORD wait_ms = (timeout_ms <= 0) ? INFINITE : (DWORD)timeout_ms;
    bool timed_out = false;
    DWORD wait_res = WaitForSingleObject(pi.hProcess, wait_ms);
    if (wait_res == WAIT_TIMEOUT) {
        timed_out = true;
        kill_process_tree(pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 1000);
    }

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    DWORD child_pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Fast drain: process has terminated, wait max 100ms for reader threads to complete
    WaitForMultipleObjects(2, hThreads, TRUE, 100);
    CloseHandle(hThreads[0]);
    CloseHandle(hThreads[1]);
    CloseHandle(hOutR);
    CloseHandle(hErrR);

    // Convert stdout & stderr from OEM/ANSI to clean UTF-8
    size_t out_utf8_len = 0, err_utf8_len = 0;
    char *out_utf8 = convert_oem_or_ansi_to_utf8(outCtx.buf.data, outCtx.buf.len, &out_utf8_len);
    char *err_utf8 = convert_oem_or_ansi_to_utf8(errCtx.buf.data, errCtx.buf.len, &err_utf8_len);
    db_free(&outCtx.buf);
    db_free(&errCtx.buf);

    uint64_t elapsed_ms = GetTickCount64() - start_tick;
    const char *status_clr = (timed_out) ? (CLR_RED CLR_BOLD) : ((exit_code == 0) ? CLR_GREEN : CLR_YELLOW);
    const char *status_str = (timed_out) ? "TIMEOUT" : ((exit_code == 0) ? "SUCCESS" : "EXIT_CODE");

    // Real-time Visual Console Card (Completion & Preview)
    printf("  " CLR_DIM "+--" CLR_RESET " " CLR_CYAN "[TX: DONE]" CLR_RESET " Status: %s%s%s (exit %lu) | Time: " CLR_WHITE "%llums" CLR_RESET " | Out: " CLR_WHITE "%u bytes" CLR_RESET "\n",
           status_clr, status_str, CLR_RESET, exit_code, (unsigned long long)elapsed_ms, (unsigned int)(out_utf8_len + err_utf8_len));

    if (out_utf8 && out_utf8_len > 0) {
        int lines = 0;
        const char *p = out_utf8;
        while (*p && lines < 4) {
            const char *eol = strchr(p, '\n');
            size_t llen = eol ? (size_t)(eol - p) : strlen(p);
            if (llen > 0 && p[llen - 1] == '\r') llen--;
            if (llen > 90) llen = 90;
            if (llen > 0) {
                printf("  " CLR_DIM "| " CLR_RESET " %.*s%s\n", (int)llen, p, (eol && (size_t)(eol - p) > 90) ? "..." : "");
                lines++;
            }
            if (!eol) break;
            p = eol + 1;
        }
        if (lines >= 4 && *p) {
            printf("  " CLR_DIM "|  ... (%u more bytes)" CLR_RESET "\n", (unsigned int)(out_utf8_len - (size_t)(p - out_utf8)));
        }
    }
    if (err_utf8 && err_utf8_len > 0) {
        printf("  " CLR_DIM "| " CLR_RED "Stderr:" CLR_RESET " %.*s\n", (int)(err_utf8_len > 90 ? 90 : err_utf8_len), err_utf8);
    }
    printf("  " CLR_CYAN "  +------------------------------------------------------------------------" CLR_RESET "\n\n");
    fflush(stdout);

    if (timed_out) {
        agent_log(LOG_LVL_WARN, CLR_RED "[EXEC TIMEOUT]" CLR_RESET " pid=%lu exceeded %lldms", child_pid, (long long)timeout_ms);
    } else if (exit_code == 0) {
        agent_log(LOG_LVL_INFO, CLR_GREEN "[EXEC DONE]" CLR_RESET " pid=%lu exit=0 in %llums", child_pid, (unsigned long long)elapsed_ms);
    } else {
        agent_log(LOG_LVL_INFO, CLR_YELLOW "[EXEC END]" CLR_RESET " pid=%lu exit=%lu in %llums", child_pid, exit_code, (unsigned long long)elapsed_ms);
    }

    InterlockedExchange(&g_cmd_executing, 0);

    char *out_b64 = b64_encode((const unsigned char *)(out_utf8 ? out_utf8 : ""), out_utf8_len, NULL);
    char *err_b64 = b64_encode((const unsigned char *)(err_utf8 ? err_utf8 : ""), err_utf8_len, NULL);
    if (out_utf8) free(out_utf8);
    if (err_utf8) free(err_utf8);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"pid\":");
    db_append_uint64(resp, child_pid);
    db_append_str(resp, ",\"exit_code\":");
    db_append_int64(resp, (int64_t)exit_code);
    db_append_str(resp, ",\"timed_out\":");
    db_append_str(resp, timed_out ? "true" : "false");
    db_append_str(resp, ",\"stdout_b64\":\"");
    db_append_str(resp, out_b64 ? out_b64 : "");
    db_append_str(resp, "\",\"stderr_b64\":\"");
    db_append_str(resp, err_b64 ? err_b64 : "");
    db_append_str(resp, "\"}}");

    free(out_b64);
    free(err_b64);
}

/* =========================================================================
 * MODULE 2: FILE SYSTEM & CNG SHA-256 VERIFICATION
 * ========================================================================= */
static void handle_fs_hash(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) {
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0);
        return;
    }
    char sha_hex[65];
    uint64_t fsize = 0;
    DWORD err = 0;
    bool ok = compute_file_sha256(path, sha_hex, &fsize, &err);
    free(path);

    if (!ok) {
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "compute_file_sha256 failed", err);
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"sha256\":\"");
    db_append_str(resp, sha_hex);
    db_append_str(resp, "\",\"size\":");
    db_append_uint64(resp, fsize);
    db_append_str(resp, "}}");
}

static void handle_fs_read(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    int64_t offset = json_get_int64(req, "offset", 0);
    int64_t length = json_get_int64(req, "length", MAX_IO_CHUNK_BYTES);

    if (!path) {
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0);
        return;
    }
    if (length <= 0 || length > (8 * 1024 * 1024)) length = MAX_IO_CHUNK_BYTES;

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(path);
    if (hFile == INVALID_HANDLE_VALUE) {
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "CreateFileA read failed", GetLastError());
        return;
    }

    LARGE_INTEGER fsize, li_off;
    GetFileSizeEx(hFile, &fsize);
    li_off.QuadPart = offset;
    if (!SetFilePointerEx(hFile, li_off, NULL, FILE_BEGIN)) {
        DWORD err = GetLastError();
        CloseHandle(hFile);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "SetFilePointerEx failed", err);
        return;
    }

    unsigned char *buf = (unsigned char *)malloc((size_t)length);
    if (!buf) {
        CloseHandle(hFile);
        build_error_response(resp, id, RPC_ERR_INTERNAL, "Out of memory", 0);
        return;
    }

    DWORD bread = 0;
    BOOL ok = ReadFile(hFile, buf, (DWORD)length, &bread, NULL);
    DWORD err = GetLastError();
    CloseHandle(hFile);
    if (!ok) {
        free(buf);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "ReadFile failed", err);
        return;
    }

    char chunk_sha[65] = "";
    compute_buffer_sha256(buf, bread, chunk_sha);
    char *data_b64 = b64_encode(buf, bread, NULL);
    free(buf);
    bool eof = ((offset + (int64_t)bread) >= fsize.QuadPart);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"total_size\":");
    db_append_int64(resp, fsize.QuadPart);
    db_append_str(resp, ",\"offset\":");
    db_append_int64(resp, offset);
    db_append_str(resp, ",\"bytes_read\":");
    db_append_uint64(resp, bread);
    db_append_str(resp, ",\"eof\":");
    db_append_str(resp, eof ? "true" : "false");
    db_append_str(resp, ",\"chunk_sha256\":\"");
    db_append_str(resp, chunk_sha);
    db_append_str(resp, "\",\"data_b64\":\"");
    db_append_str(resp, data_b64 ? data_b64 : "");
    db_append_str(resp, "\"}}");
    free(data_b64);
}

static void handle_fs_write(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    char *data_b64 = json_get_string(req, "data_b64");
    int64_t offset = json_get_int64(req, "offset", 0);
    bool truncate = json_get_bool(req, "truncate", true);
    bool finalize_hash = json_get_bool(req, "finalize_hash", false);

    if (!path || !data_b64) {
        free(path); free(data_b64);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path or data_b64", 0);
        return;
    }

    size_t raw_len = 0;
    unsigned char *raw_data = b64_decode(data_b64, &raw_len);
    free(data_b64);
    if (!raw_data) {
        free(path);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Invalid data_b64", 0);
        return;
    }

    DWORD disp = (truncate && offset == 0) ? CREATE_ALWAYS : OPEN_ALWAYS;
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        free(path); free(raw_data);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "CreateFileA write failed", err);
        return;
    }

    if (offset > 0) {
        LARGE_INTEGER li_off;
        li_off.QuadPart = offset;
        if (!SetFilePointerEx(hFile, li_off, NULL, FILE_BEGIN)) {
            DWORD err = GetLastError();
            CloseHandle(hFile);
            free(path); free(raw_data);
            build_error_response(resp, id, RPC_ERR_FS_FAILED, "SetFilePointerEx failed", err);
            return;
        }
    }

    DWORD written = 0;
    BOOL ok = WriteFile(hFile, raw_data, (DWORD)raw_len, &written, NULL);
    DWORD err = GetLastError();
    CloseHandle(hFile);

    char chunk_sha[65] = "";
    compute_buffer_sha256(raw_data, written, chunk_sha);
    free(raw_data);

    if (!ok) {
        free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "WriteFile failed", err);
        return;
    }

    char file_sha[65] = "";
    uint64_t total_sz = 0;
    if (finalize_hash) {
        compute_file_sha256(path, file_sha, &total_sz, NULL);
    }
    free(path);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"bytes_written\":");
    db_append_uint64(resp, written);
    db_append_str(resp, ",\"chunk_sha256\":\"");
    db_append_str(resp, chunk_sha);
    db_append_str(resp, "\",\"file_sha256\":\"");
    db_append_str(resp, file_sha);
    db_append_str(resp, "\"}}");
}

static void handle_fs_patch(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) path = json_get_string(req, "TargetFile");
    if (!path) path = json_get_string(req, "file_path");

    char *search_b64 = json_get_string(req, "search_b64");
    char *replace_b64 = json_get_string(req, "replace_b64");
    bool replace_all = json_get_bool(req, "replace_all", false);

    if (!search_b64) {
        char *target = json_get_string(req, "target");
        if (!target) target = json_get_string(req, "TargetContent");
        if (!target) target = json_get_string(req, "search");
        if (target) {
            search_b64 = b64_encode((const unsigned char *)target, strlen(target), NULL);
            free(target);
        }
    }
    if (!replace_b64) {
        char *replacement = json_get_string(req, "replacement");
        if (!replacement) replacement = json_get_string(req, "ReplacementContent");
        if (!replacement) replacement = json_get_string(req, "replace");
        if (replacement) {
            replace_b64 = b64_encode((const unsigned char *)replacement, strlen(replacement), NULL);
            free(replacement);
        }
    }

    if (!path || !search_b64 || !replace_b64) {
        free(path); free(search_b64); free(replace_b64);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path/search_b64/replace_b64", 0);
        return;
    }

    size_t s_len = 0, r_len = 0;
    unsigned char *s_buf = b64_decode(search_b64, &s_len);
    unsigned char *r_buf = b64_decode(replace_b64, &r_len);
    free(search_b64); free(replace_b64);
    if (!s_buf || !r_buf || s_len == 0) {
        free(path); free(s_buf); free(r_buf);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Invalid patch payload", 0);
        return;
    }

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        free(path); free(s_buf); free(r_buf);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Cannot open file for patch", err);
        return;
    }

    LARGE_INTEGER fsize;
    GetFileSizeEx(hFile, &fsize);
    size_t orig_len = (size_t)fsize.QuadPart;
    unsigned char *orig = (unsigned char *)malloc(orig_len + 1);
    DWORD bread = 0;
    ReadFile(hFile, orig, (DWORD)orig_len, &bread, NULL);
    CloseHandle(hFile);

    DynBuf patched;
    db_init(&patched, orig_len + 1024);
    size_t pos = 0;
    int replacements = 0;
    while (pos < orig_len) {
        if ((orig_len - pos) >= s_len && memcmp(orig + pos, s_buf, s_len) == 0 && (replace_all || replacements == 0)) {
            db_append_mem(&patched, r_buf, r_len);
            pos += s_len;
            replacements++;
        } else {
            db_append_char(&patched, (char)orig[pos++]);
        }
    }
    free(orig); free(s_buf); free(r_buf);

    if (replacements == 0) {
        db_free(&patched); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Search pattern not found", 0);
        return;
    }

    char tmp_path[MAX_PATH + 16];
    snprintf(tmp_path, sizeof(tmp_path), "%s.bridge_tmp", path);
    HANDLE hOut = CreateFileA(tmp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        db_free(&patched); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Temp file creation failed", err);
        return;
    }
    DWORD bwritten = 0;
    WriteFile(hOut, patched.data, (DWORD)patched.len, &bwritten, NULL);
    CloseHandle(hOut);

    if (!MoveFileExA(tmp_path, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD err = GetLastError();
        DeleteFileA(tmp_path);
        db_free(&patched); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "MoveFileExA failed", err);
        return;
    }

    char sha_hex[65] = "";
    compute_file_sha256(path, sha_hex, NULL, NULL);
    size_t final_len = patched.len;
    db_free(&patched); free(path);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"replacements\":");
    db_append_int64(resp, replacements);
    db_append_str(resp, ",\"new_size\":");
    db_append_uint64(resp, final_len);
    db_append_str(resp, ",\"sha256\":\"");
    db_append_str(resp, sha_hex);
    db_append_str(resp, "\"}}");
}

static void handle_fs_list(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) {
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0);
        return;
    }
    char pattern[MAX_PATH + 8];
    size_t plen = strlen(path);
    if (plen > 0 && (path[plen - 1] == '\\' || path[plen - 1] == '/'))
        snprintf(pattern, sizeof(pattern), "%s*", path);
    else
        snprintf(pattern, sizeof(pattern), "%s\\*", path);
    free(path);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "FindFirstFileA failed", GetLastError());
        return;
    }

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"entries\":[");
    bool first = true;
    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
        if (!first) db_append_char(resp, ',');
        first = false;
        uint64_t fsize = ((uint64_t)ffd.nFileSizeHigh << 32) | (uint64_t)ffd.nFileSizeLow;
        bool is_dir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        db_append_str(resp, "{\"name\":\"");
        db_append_json_escaped(resp, ffd.cFileName);
        db_append_str(resp, "\",\"is_dir\":");
        db_append_str(resp, is_dir ? "true" : "false");
        db_append_str(resp, ",\"size\":");
        db_append_uint64(resp, fsize);
        db_append_str(resp, "}");
    } while (FindNextFileA(hFind, &ffd));
    FindClose(hFind);
    db_append_str(resp, "]}}");
}

static bool delete_dir_recursive(const char *dir_path, int *files_deleted, uint64_t *bytes_freed) {
    char pattern[MAX_PATH + 8];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir_path);
    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(pattern, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return false;
    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
        char full[MAX_PATH * 2];
        snprintf(full, sizeof(full), "%s\\%s", dir_path, ffd.cFileName);
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            delete_dir_recursive(full, files_deleted, bytes_freed);
            RemoveDirectoryA(full);
        } else {
            SetFileAttributesA(full, FILE_ATTRIBUTE_NORMAL);
            uint64_t sz = ((uint64_t)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
            if (DeleteFileA(full)) {
                if (files_deleted) (*files_deleted)++;
                if (bytes_freed) (*bytes_freed) += sz;
            }
        }
    } while (FindNextFileA(hFind, &ffd));
    FindClose(hFind);
    return true;
}

static void handle_fs_delete(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) {
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0);
        return;
    }
    DWORD attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Path does not exist", err);
        return;
    }
    BOOL ok = FALSE;
    if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        delete_dir_recursive(path, NULL, NULL);
        ok = RemoveDirectoryA(path);
    } else {
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        ok = DeleteFileA(path);
    }
    DWORD err = GetLastError();
    free(path);
    if (!ok) {
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Delete failed", err);
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"deleted\":true}}");
}

static void handle_fs_mkdir(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) {
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0);
        return;
    }
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t start_idx = 0;
    if (tmp[0] != '\0' && tmp[1] == ':' && (tmp[2] == '\\' || tmp[2] == '/')) {
        start_idx = 3;
    }
    for (char *p = tmp + start_idx; *p; p++) {
        if (*p == '\\' || *p == '/') {
            char old = *p;
            *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = old;
        }
    }
    BOOL ok = CreateDirectoryA(path, NULL);
    DWORD err = GetLastError();
    free(path);
    if (!ok && err != ERROR_ALREADY_EXISTS) {
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "CreateDirectoryA failed", err);
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"created\":true}}");
}

typedef struct {
    DynBuf *resp;
    int count;
    int max_results;
    int max_depth;
    const char *pattern;
} FindCtx;

static bool matches_simple_pattern(const char *name, const char *pat) {
    if (!pat || strcmp(pat, "*") == 0 || strcmp(pat, "*.*") == 0) return true;
    size_t nlen = strlen(name);
    size_t plen = strlen(pat);
    if (pat[0] == '*' && plen > 1) {
        const char *sub = pat + 1;
        size_t slen = strlen(sub);
        if (slen > 0 && sub[slen - 1] == '*') {
            char term[256];
            strncpy(term, sub, slen - 1);
            term[slen - 1] = '\0';
            return (strcasestr_custom(name, term) != NULL);
        } else {
            if (nlen < slen) return false;
            return (_stricmp(name + nlen - slen, sub) == 0);
        }
    }
    if (plen > 1 && pat[plen - 1] == '*') {
        return (_strnicmp(name, pat, plen - 1) == 0);
    }
    return (_stricmp(name, pat) == 0 || strcasestr_custom(name, pat) != NULL);
}

static void fs_find_recurse(const char *dir, int current_depth, FindCtx *ctx) {
    if (ctx->count >= ctx->max_results || current_depth > ctx->max_depth) return;

    char search_path[MAX_PATH + 16];
    snprintf(search_path, sizeof(search_path), "%s\\*", dir);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) continue;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        char full_item[MAX_PATH * 2];
        snprintf(full_item, sizeof(full_item), "%s\\%s", dir, ffd.cFileName);

        bool is_dir = (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        if (!is_dir) {
            if (matches_simple_pattern(ffd.cFileName, ctx->pattern)) {
                if (ctx->count > 0) db_append_char(ctx->resp, ',');
                uint64_t fsz = ((uint64_t)ffd.nFileSizeHigh << 32) | ffd.nFileSizeLow;
                db_append_str(ctx->resp, "{\"path\":\"");
                db_append_json_escaped(ctx->resp, full_item);
                db_append_str(ctx->resp, "\",\"size\":");
                db_append_uint64(ctx->resp, fsz);
                db_append_str(ctx->resp, "}");
                ctx->count++;
                if (ctx->count >= ctx->max_results) break;
            }
        } else if (current_depth < ctx->max_depth) {
            fs_find_recurse(full_item, current_depth + 1, ctx);
            if (ctx->count >= ctx->max_results) break;
        }
    } while (FindNextFileA(hFind, &ffd));

    FindClose(hFind);
}

static void handle_fs_find(const char *req, int64_t id, DynBuf *resp) {
    char *root = json_get_string(req, "root");
    if (!root) root = json_get_string(req, "path");
    char *pattern = json_get_string(req, "pattern");
    if (!pattern) pattern = json_get_string(req, "filter");
    int64_t max_depth = json_get_int64(req, "max_depth", 6);
    int64_t max_results = json_get_int64(req, "max_results", 50);

    const char *start_root = root ? root : "C:\\";
    const char *start_pat = pattern ? pattern : "*";

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"root\":\"");
    db_append_json_escaped(resp, start_root);
    db_append_str(resp, "\",\"pattern\":\"");
    db_append_json_escaped(resp, start_pat);
    db_append_str(resp, "\",\"matches\":[");

    FindCtx ctx;
    ctx.resp = resp;
    ctx.count = 0;
    ctx.max_results = (int)max_results;
    ctx.max_depth = (int)max_depth;
    ctx.pattern = start_pat;

    uint64_t t0 = GetTickCount64();
    fs_find_recurse(start_root, 0, &ctx);
    uint64_t duration = GetTickCount64() - t0;

    db_append_str(resp, "],\"count\":");
    db_append_int64(resp, ctx.count);
    db_append_str(resp, ",\"duration_ms\":");
    db_append_uint64(resp, duration);
    db_append_str(resp, "}}");

    free(root);
    free(pattern);
}

/* =========================================================================
 * MODULE 3: SELF-UPDATE (SIDE-BY-SIDE SELFTEST + ATOMIC RENAME + ROLLBACK)
 * ========================================================================= */
static bool verify_pe_binary(const char *file_path) {
    HANDLE hFile = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    IMAGE_DOS_HEADER dos;
    DWORD bread = 0;
    bool valid = false;
    if (ReadFile(hFile, &dos, sizeof(dos), &bread, NULL) && bread == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
        LARGE_INTEGER off;
        off.QuadPart = dos.e_lfanew;
        if (SetFilePointerEx(hFile, off, NULL, FILE_BEGIN)) {
            DWORD pe_sig = 0;
            if (ReadFile(hFile, &pe_sig, sizeof(pe_sig), &bread, NULL) && bread == sizeof(pe_sig) && pe_sig == IMAGE_NT_SIGNATURE) {
                valid = true;
            }
        }
    }
    CloseHandle(hFile);
    return valid;
}

static void handle_agent_update(const char *req, int64_t id, DynBuf *resp, bool *trigger_exit) {
    char *staging_path = json_get_string(req, "staging_path");
    char *expected_sha256 = json_get_string(req, "expected_sha256");

    wchar_t self_w[MAX_PATH];
    GetModuleFileNameW(NULL, self_w, MAX_PATH);
    char self_a[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, self_w, -1, self_a, sizeof(self_a), NULL, NULL);

    char new_a[MAX_PATH + 16];
    if (staging_path && strlen(staging_path) > 0) {
        snprintf(new_a, sizeof(new_a), "%s", staging_path);
    } else {
        snprintf(new_a, sizeof(new_a), "%s.new", self_a);
    }
    free(staging_path);

    if (!verify_pe_binary(new_a)) {
        DeleteFileA(new_a);
        free(expected_sha256);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "Invalid DOS/PE header on staged binary", 0);
        return;
    }

    char actual_sha[65] = "";
    uint64_t fsize = 0;
    DWORD err = 0;
    if (!compute_file_sha256(new_a, actual_sha, &fsize, &err)) {
        DeleteFileA(new_a);
        free(expected_sha256);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "Failed to compute SHA-256 of staged binary", err);
        return;
    }

    if (expected_sha256 && strlen(expected_sha256) == 64 && _stricmp(actual_sha, expected_sha256) != 0) {
        DeleteFileA(new_a);
        free(expected_sha256);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "SHA-256 mismatch on staged binary", 0);
        return;
    }
    free(expected_sha256);

    /* Phase 1: Side-by-Side execution pre-flight validation (--selftest) */
    char selftest_cmd[MAX_PATH + 64];
    snprintf(selftest_cmd, sizeof(selftest_cmd), "\"%s\" --selftest", new_a);
    STARTUPINFOA si_test;
    PROCESS_INFORMATION pi_test;
    ZeroMemory(&si_test, sizeof(si_test));
    si_test.cb = sizeof(si_test);
    ZeroMemory(&pi_test, sizeof(pi_test));

    if (!CreateProcessA(NULL, selftest_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si_test, &pi_test)) {
        DWORD cerr = GetLastError();
        DeleteFileA(new_a);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "Side-by-side selftest failed to start", cerr);
        return;
    }
    DWORD wait_test = WaitForSingleObject(pi_test.hProcess, 15000);
    DWORD test_exit = 1;
    GetExitCodeProcess(pi_test.hProcess, &test_exit);
    CloseHandle(pi_test.hProcess);
    CloseHandle(pi_test.hThread);

    if (wait_test != WAIT_OBJECT_0 || test_exit != 0) {
        DeleteFileA(new_a);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "Side-by-side --selftest returned non-zero exit code", test_exit);
        return;
    }

    /* Phase 2: Atomic MoveFileExW swap */
    wchar_t old_w[MAX_PATH + 16];
    wchar_t new_w[MAX_PATH + 16];
    swprintf(old_w, MAX_PATH + 16, L"%s.old", self_w);
    MultiByteToWideChar(CP_ACP, 0, new_a, -1, new_w, MAX_PATH + 16);

    DeleteFileW(old_w);
    if (!MoveFileExW(self_w, old_w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD merr = GetLastError();
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "MoveFileExW(agent.exe -> agent.exe.old) failed", merr);
        return;
    }

    if (!MoveFileExW(new_w, self_w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD merr = GetLastError();
        MoveFileExW(old_w, self_w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "MoveFileExW(new -> agent.exe) failed; rolled back", merr);
        return;
    }

    /* Phase 3: Spawn replacement process with CreateProcessW & Watchdog */
    wchar_t cmd_w[MAX_PATH + 512];
    wchar_t host_w[256], token_w[256], id_w[64];
    MultiByteToWideChar(CP_ACP, 0, g_master_host, -1, host_w, 256);
    MultiByteToWideChar(CP_ACP, 0, g_psk_token, -1, token_w, 256);
    MultiByteToWideChar(CP_ACP, 0, g_agent_id, -1, id_w, 64);
    swprintf(cmd_w, MAX_PATH + 512, L"\"%s\" --host %s --port %u --token \"%s\" --agent-id \"%s\"%s --upgraded-from %lu",
             self_w, host_w, (unsigned int)g_master_port, token_w, id_w,
             g_headless ? L" --headless" : L"", (unsigned long)GetCurrentProcessId());

    STARTUPINFOW si_new;
    PROCESS_INFORMATION pi_new;
    ZeroMemory(&si_new, sizeof(si_new));
    si_new.cb = sizeof(si_new);
    si_new.dwFlags = STARTF_USESHOWWINDOW;
    si_new.wShowWindow = SW_SHOW;
    ZeroMemory(&pi_new, sizeof(pi_new));

    { /* diagnostics for spawn failures: log what CreateProcessW will see */
        char self_a2[MAX_PATH], cmd_a[1024], cwd_a[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, self_w, -1, self_a2, sizeof(self_a2), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, cmd_w, -1, cmd_a, sizeof(cmd_a), NULL, NULL);
        DWORD cl = GetCurrentDirectoryA(sizeof(cwd_a), cwd_a);
        DWORD attrs = GetFileAttributesW(self_w);
        { /* redact --token "secret" before logging */
            char *t = strstr(cmd_a, "--token \"");
            if (t) {
                t += 9;
                char *e = strchr(t, '"');
                if (e) while (t < e) *t++ = '*';
            }
        }
        agent_log(LOG_LVL_INFO, "[UPDATE] spawn self=%s exists=%d cwd=%s cmd=%.300s",
                  self_a2, attrs != INVALID_FILE_ATTRIBUTES, cl ? cwd_a : "?", cmd_a);
    }
    if (!CreateProcessW(NULL, cmd_w, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si_new, &pi_new)) {
        DWORD cerr = GetLastError();
        MoveFileExW(old_w, self_w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "CreateProcessW failed; rolled back to previous binary", cerr);
        return;
    }

    /* Watchdog: monitor new process for 1000ms to ensure it does not crash on startup */
    DWORD wres = WaitForSingleObject(pi_new.hProcess, 1000);
    DWORD new_pid = pi_new.dwProcessId;
    CloseHandle(pi_new.hProcess);
    CloseHandle(pi_new.hThread);

    if (wres != WAIT_TIMEOUT) {
        DeleteFileW(self_w);
        MoveFileExW(old_w, self_w, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "New agent crashed within watchdog window; rolled back", 0);
        return;
    }

    agent_log(LOG_LVL_INFO, "Self-update succeeded! New PID=%lu, SHA256=%s", (unsigned long)new_pid, actual_sha);
    *trigger_exit = true;

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"updated\":true,\"new_pid\":");
    db_append_uint64(resp, new_pid);
    db_append_str(resp, ",\"sha256\":\"");
    db_append_str(resp, actual_sha);
    db_append_str(resp, "\"}}");
}

/* =========================================================================
 * MODULE 4: REGISTRY, SERVICES, PROCESSES
 * ========================================================================= */
static HKEY parse_hive(const char *h) {
    if (!h) return NULL;
    if (_stricmp(h, "HKLM") == 0 || _stricmp(h, "HKEY_LOCAL_MACHINE") == 0) return HKEY_LOCAL_MACHINE;
    if (_stricmp(h, "HKCU") == 0 || _stricmp(h, "HKEY_CURRENT_USER") == 0) return HKEY_CURRENT_USER;
    if (_stricmp(h, "HKCR") == 0 || _stricmp(h, "HKEY_CLASSES_ROOT") == 0) return HKEY_CLASSES_ROOT;
    if (_stricmp(h, "HKU") == 0  || _stricmp(h, "HKEY_USERS") == 0) return HKEY_USERS;
    if (_stricmp(h, "HKCC") == 0 || _stricmp(h, "HKEY_CURRENT_CONFIG") == 0) return HKEY_CURRENT_CONFIG;
    return NULL;
}

static void handle_reg_read(const char *req, int64_t id, DynBuf *resp) {
    char *hive_s = json_get_string(req, "hive");
    char *subkey = json_get_string(req, "subkey");
    char *value_name = json_get_string(req, "value_name");
    HKEY hive = parse_hive(hive_s);
    free(hive_s);
    if (!hive || !subkey) {
        free(subkey); free(value_name);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Invalid hive or subkey", 0);
        return;
    }
    HKEY hKey = NULL;
    LSTATUS st = RegOpenKeyExA(hive, subkey, 0, KEY_READ, &hKey);
    free(subkey);
    if (st != ERROR_SUCCESS) {
        free(value_name);
        build_error_response(resp, id, RPC_ERR_REG_FAILED, "RegOpenKeyExA failed", (DWORD)st);
        return;
    }
    DWORD type = 0, dsize = 0;
    const char *vname = (value_name && strlen(value_name) > 0) ? value_name : NULL;
    st = RegQueryValueExA(hKey, vname, NULL, &type, NULL, &dsize);
    if (st != ERROR_SUCCESS) {
        RegCloseKey(hKey); free(value_name);
        build_error_response(resp, id, RPC_ERR_REG_FAILED, "RegQueryValueExA failed", (DWORD)st);
        return;
    }
    unsigned char *buf = (unsigned char *)calloc(1, dsize + 4);
    st = RegQueryValueExA(hKey, vname, NULL, &type, buf, &dsize);
    RegCloseKey(hKey); free(value_name);
    if (st != ERROR_SUCCESS) {
        free(buf);
        build_error_response(resp, id, RPC_ERR_REG_FAILED, "RegQueryValueExA read failed", (DWORD)st);
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"reg_type\":");
    db_append_uint64(resp, type);
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        db_append_str(resp, ",\"value\":\"");
        db_append_json_escaped(resp, (const char *)buf);
        db_append_str(resp, "\"}}");
    } else if (type == REG_DWORD && dsize >= 4) {
        db_append_str(resp, ",\"value\":");
        db_append_uint64(resp, *(DWORD *)buf);
        db_append_str(resp, "}}");
    } else {
        char *b64 = b64_encode(buf, dsize, NULL);
        db_append_str(resp, ",\"value_b64\":\"");
        db_append_str(resp, b64 ? b64 : "");
        db_append_str(resp, "\"}}");
        free(b64);
    }
    free(buf);
}

static void handle_reg_write(const char *req, int64_t id, DynBuf *resp) {
    char *hive_s = json_get_string(req, "hive");
    char *subkey = json_get_string(req, "subkey");
    char *value_name = json_get_string(req, "value_name");
    char *reg_type = json_get_string(req, "reg_type");
    char *val_str = json_get_string(req, "value_str");
    int64_t val_int = json_get_int64(req, "value_int", 0);

    HKEY hive = parse_hive(hive_s);
    free(hive_s);
    if (!hive || !subkey || !reg_type) {
        free(subkey); free(value_name); free(reg_type); free(val_str);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing hive/subkey/reg_type", 0);
        return;
    }
    HKEY hKey = NULL;
    LSTATUS st = RegCreateKeyExA(hive, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    free(subkey);
    if (st != ERROR_SUCCESS) {
        free(value_name); free(reg_type); free(val_str);
        build_error_response(resp, id, RPC_ERR_REG_FAILED, "RegCreateKeyExA failed", (DWORD)st);
        return;
    }
    const char *vname = (value_name && strlen(value_name) > 0) ? value_name : NULL;
    if (_stricmp(reg_type, "REG_DWORD") == 0) {
        DWORD dw = (DWORD)val_int;
        st = RegSetValueExA(hKey, vname, 0, REG_DWORD, (const BYTE *)&dw, sizeof(DWORD));
    } else if (_stricmp(reg_type, "REG_QWORD") == 0) {
        uint64_t qw = (uint64_t)val_int;
        st = RegSetValueExA(hKey, vname, 0, REG_QWORD, (const BYTE *)&qw, sizeof(uint64_t));
    } else {
        const char *s = val_str ? val_str : "";
        DWORD t = (_stricmp(reg_type, "REG_EXPAND_SZ") == 0) ? REG_EXPAND_SZ : REG_SZ;
        st = RegSetValueExA(hKey, vname, 0, t, (const BYTE *)s, (DWORD)(strlen(s) + 1));
    }
    RegCloseKey(hKey);
    free(value_name); free(reg_type); free(val_str);
    if (st != ERROR_SUCCESS) {
        build_error_response(resp, id, RPC_ERR_REG_FAILED, "RegSetValueExA failed", (DWORD)st);
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"written\":true}}");
}

static void handle_reg_delete(const char *req, int64_t id, DynBuf *resp) {
    char *hive_s = json_get_string(req, "hive");
    char *subkey = json_get_string(req, "subkey");
    char *value_name = json_get_string(req, "value_name");
    bool delete_key = json_get_bool(req, "delete_key", false);
    HKEY hive = parse_hive(hive_s);
    free(hive_s);
    if (!hive || !subkey) {
        free(subkey); free(value_name);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing hive or subkey", 0);
        return;
    }
    LSTATUS st = ERROR_SUCCESS;
    if (delete_key) {
        st = RegDeleteKeyA(hive, subkey);
    } else {
        HKEY hKey = NULL;
        st = RegOpenKeyExA(hive, subkey, 0, KEY_SET_VALUE, &hKey);
        if (st == ERROR_SUCCESS) {
            st = RegDeleteValueA(hKey, value_name ? value_name : "");
            RegCloseKey(hKey);
        }
    }
    free(subkey); free(value_name);
    if (st != ERROR_SUCCESS) {
        build_error_response(resp, id, RPC_ERR_REG_FAILED, "Registry delete failed", (DWORD)st);
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"deleted\":true}}");
}

static void handle_svc_op(const char *req, int64_t id, DynBuf *resp) {
    char *name = json_get_string(req, "service_name");
    char *action = json_get_string(req, "action");
    char *start_type = json_get_string(req, "start_type");
    if (!name || !action) {
        free(name); free(action); free(start_type);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing service_name or action", 0);
        return;
    }
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        DWORD err = GetLastError();
        free(name); free(action); free(start_type);
        build_error_response(resp, id, RPC_ERR_SVC_FAILED, "OpenSCManagerA failed", err);
        return;
    }
    DWORD acc = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG;
    if (_stricmp(action, "start") == 0) acc |= SERVICE_START;
    else if (_stricmp(action, "stop") == 0) acc |= SERVICE_STOP;
    else if (_stricmp(action, "set_start_type") == 0) acc |= SERVICE_CHANGE_CONFIG;

    SC_HANDLE hSvc = OpenServiceA(hSCM, name, acc);
    if (!hSvc) {
        DWORD err = GetLastError();
        CloseServiceHandle(hSCM);
        free(name); free(action); free(start_type);
        build_error_response(resp, id, RPC_ERR_SVC_FAILED, "OpenServiceA failed", err);
        return;
    }
    if (_stricmp(action, "start") == 0) {
        if (!StartServiceA(hSvc, 0, NULL) && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            DWORD err = GetLastError();
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
            free(name); free(action); free(start_type);
            build_error_response(resp, id, RPC_ERR_SVC_FAILED, "StartServiceA failed", err);
            return;
        }
    } else if (_stricmp(action, "stop") == 0) {
        SERVICE_STATUS ss;
        if (!ControlService(hSvc, SERVICE_CONTROL_STOP, &ss) && GetLastError() != ERROR_SERVICE_NOT_ACTIVE) {
            DWORD err = GetLastError();
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
            free(name); free(action); free(start_type);
            build_error_response(resp, id, RPC_ERR_SVC_FAILED, "ControlService STOP failed", err);
            return;
        }
    } else if (_stricmp(action, "set_start_type") == 0 && start_type) {
        DWORD st_code = SERVICE_DEMAND_START;
        if (_stricmp(start_type, "auto") == 0) st_code = SERVICE_AUTO_START;
        else if (_stricmp(start_type, "disabled") == 0) st_code = SERVICE_DISABLED;
        if (!ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, st_code, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) {
            DWORD err = GetLastError();
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
            free(name); free(action); free(start_type);
            build_error_response(resp, id, RPC_ERR_SVC_FAILED, "ChangeServiceConfigA failed", err);
            return;
        }
    }
    SERVICE_STATUS_PROCESS ssp;
    ZeroMemory(&ssp, sizeof(ssp));
    DWORD needed = 0;
    QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"service_name\":\"");
    db_append_json_escaped(resp, name);
    db_append_str(resp, "\",\"state_code\":");
    db_append_uint64(resp, ssp.dwCurrentState);
    db_append_str(resp, ",\"pid\":");
    db_append_uint64(resp, ssp.dwProcessId);
    db_append_str(resp, "}}");
    free(name); free(action); free(start_type);
}

static void handle_proc_list(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        build_error_response(resp, id, RPC_ERR_PROC_FAILED, "CreateToolhelp32Snapshot failed", GetLastError());
        return;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(hSnap, &pe)) {
        CloseHandle(hSnap);
        build_error_response(resp, id, RPC_ERR_PROC_FAILED, "Process32First failed", GetLastError());
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"processes\":[");
    bool first = true;
    do {
        if (!first) db_append_char(resp, ',');
        first = false;
        uint64_t mem_bytes = 0;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (hProc) {
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) mem_bytes = (uint64_t)pmc.WorkingSetSize;
            CloseHandle(hProc);
        }
        db_append_str(resp, "{\"pid\":");
        db_append_uint64(resp, pe.th32ProcessID);
        db_append_str(resp, ",\"ppid\":");
        db_append_uint64(resp, pe.th32ParentProcessID);
        db_append_str(resp, ",\"name\":\"");
        db_append_json_escaped(resp, pe.szExeFile);
        db_append_str(resp, "\",\"working_set_bytes\":");
        db_append_uint64(resp, mem_bytes);
        db_append_str(resp, "}");
    } while (Process32Next(hSnap, &pe));
    CloseHandle(hSnap);
    db_append_str(resp, "]}}");
}

static void handle_proc_kill(const char *req, int64_t id, DynBuf *resp) {
    int64_t pid = json_get_int64(req, "pid", -1);
    bool tree = json_get_bool(req, "kill_tree", true);
    if (pid <= 0) {
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Invalid pid", 0);
        return;
    }
    int count = tree ? kill_process_tree((DWORD)pid) : 0;
    if (!tree) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
        if (h && TerminateProcess(h, 1)) count = 1;
        if (h) CloseHandle(h);
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"terminated_count\":");
    db_append_int64(resp, count);
    db_append_str(resp, "}}");
}

static void handle_proc_priority(const char *req, int64_t id, DynBuf *resp) {
    int64_t pid = json_get_int64(req, "pid", -1);
    char *prio = json_get_string(req, "priority");
    if (pid <= 0 || !prio) {
        free(prio);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing pid or priority", 0);
        return;
    }
    DWORD cls = NORMAL_PRIORITY_CLASS;
    if (_stricmp(prio, "idle") == 0) cls = IDLE_PRIORITY_CLASS;
    else if (_stricmp(prio, "below_normal") == 0) cls = BELOW_NORMAL_PRIORITY_CLASS;
    else if (_stricmp(prio, "above_normal") == 0) cls = ABOVE_NORMAL_PRIORITY_CLASS;
    else if (_stricmp(prio, "high") == 0) cls = HIGH_PRIORITY_CLASS;
    else if (_stricmp(prio, "realtime") == 0) cls = REALTIME_PRIORITY_CLASS;
    free(prio);

    HANDLE h = OpenProcess(PROCESS_SET_INFORMATION, FALSE, (DWORD)pid);
    if (!h) {
        build_error_response(resp, id, RPC_ERR_PROC_FAILED, "OpenProcess failed", GetLastError());
        return;
    }
    BOOL ok = SetPriorityClass(h, cls);
    DWORD err = GetLastError();
    CloseHandle(h);
    if (!ok) {
        build_error_response(resp, id, RPC_ERR_PROC_FAILED, "SetPriorityClass failed", err);
        return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"updated\":true}}");
}

/* =========================================================================
 * MODULE 5: DIAGNOSTICS, REAL-TIME TELEMETRY & LOG STREAMING
 * ========================================================================= */
typedef LONG (WINAPI *RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static void handle_sys_diag(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    EnterCriticalSection(&g_telemetry_lock);
    double cpu_pct = g_cpu_load_pct;
    uint64_t io_r_sec = g_io_read_bytes_sec;
    uint64_t io_w_sec = g_io_write_bytes_sec;
    uint64_t io_r_tot = g_io_total_read_bytes;
    uint64_t io_w_tot = g_io_total_write_bytes;
    uint64_t last_tick = g_telemetry_last_tick;
    LeaveCriticalSection(&g_telemetry_lock);

    /* Immediate fallback calculation if telemetry thread hasn't run yet */
    if (last_tick == 0 || cpu_pct == 0.0) {
        FILETIME i1, k1, u1, i2, k2, u2;
        if (GetSystemTimes(&i1, &k1, &u1)) {
            Sleep(50);
            if (GetSystemTimes(&i2, &k2, &u2)) {
                uint64_t idl = ft_to_u64(&i2) - ft_to_u64(&i1);
                uint64_t krn = ft_to_u64(&k2) - ft_to_u64(&k1);
                uint64_t usr = ft_to_u64(&u2) - ft_to_u64(&u1);
                uint64_t sys = krn + usr;
                if (sys > 0 && idl <= sys) {
                    cpu_pct = (double)(sys - idl) * 100.0 / (double)sys;
                }
            }
        }
    }

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    PROCESS_MEMORY_COUNTERS pmc;
    ZeroMemory(&pmc, sizeof(pmc));
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));

    RTL_OSVERSIONINFOW rovi;
    ZeroMemory(&rovi, sizeof(rovi));
    rovi.dwOSVersionInfoSize = sizeof(rovi);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
        if (fn) fn(&rovi);
    }

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const char *arch = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) ? "x86 (32-bit)" :
                       (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64 (64-bit)" : "unknown";

    char hostname[256] = "";
    DWORD hlen = sizeof(hostname);
    GetComputerNameA(hostname, &hlen);

    char cpu_str[32];
    snprintf(cpu_str, sizeof(cpu_str), "%.2f", cpu_pct);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"hostname\":\"");
    db_append_json_escaped(resp, hostname);
    db_append_str(resp, "\",\"version\":\"" BRIDGE_PROTOCOL_VERSION "\",\"architecture\":\"");
    db_append_str(resp, arch);
    db_append_str(resp, "\",\"os_build\":");
    db_append_uint64(resp, rovi.dwBuildNumber);
    db_append_str(resp, ",\"cpu_cores\":");
    db_append_uint64(resp, si.dwNumberOfProcessors);
    db_append_str(resp, ",\"cpu_load_percent\":");
    db_append_str(resp, cpu_str);
    db_append_str(resp, ",\"ram_total_bytes\":");
    db_append_uint64(resp, ms.ullTotalPhys);
    db_append_str(resp, ",\"ram_avail_bytes\":");
    db_append_uint64(resp, ms.ullAvailPhys);
    db_append_str(resp, ",\"agent_working_set_bytes\":");
    db_append_uint64(resp, pmc.WorkingSetSize);
    db_append_str(resp, ",\"io_read_bytes_sec\":");
    db_append_uint64(resp, io_r_sec);
    db_append_str(resp, ",\"io_write_bytes_sec\":");
    db_append_uint64(resp, io_w_sec);
    db_append_str(resp, ",\"io_total_read_bytes\":");
    db_append_uint64(resp, io_r_tot);
    db_append_str(resp, ",\"io_total_write_bytes\":");
    db_append_uint64(resp, io_w_tot);
    db_append_str(resp, ",\"uptime_seconds\":");
    db_append_uint64(resp, GetTickCount64() / 1000ULL);
    db_append_str(resp, ",\"agent_pid\":");
    db_append_uint64(resp, GetCurrentProcessId());
    db_append_str(resp, ",\"disks\":[");

    char drives[512];
    DWORD dlen = GetLogicalDriveStringsA(sizeof(drives) - 1, drives);
    bool first = true;
    for (char *drv = drives; *drv && (drv - drives) < (int)dlen; drv += strlen(drv) + 1) {
        if (GetDriveTypeA(drv) == DRIVE_FIXED) {
            ULARGE_INTEGER fc, tb, tf;
            if (GetDiskFreeSpaceExA(drv, &fc, &tb, &tf)) {
                if (!first) db_append_char(resp, ',');
                first = false;
                db_append_str(resp, "{\"mount\":\"");
                db_append_json_escaped(resp, drv);
                db_append_str(resp, "\",\"total_bytes\":");
                db_append_uint64(resp, tb.QuadPart);
                db_append_str(resp, ",\"free_bytes\":");
                db_append_uint64(resp, tf.QuadPart);
                db_append_str(resp, "}");
            }
        }
    }
    db_append_str(resp, "]");
    GpuTelemetry gpu;
    query_gpu_telemetry(&gpu);
    if (gpu.temp_c >= 0.0f) {
        char gbuf[32];
        snprintf(gbuf, sizeof(gbuf), "%.1f", gpu.temp_c);
        db_append_str(resp, ",\"gpu_temp_c\":");
        db_append_str(resp, gbuf);
    }
    if (gpu.engine_clock_mhz > 0) {
        db_append_str(resp, ",\"gpu_engine_clock_mhz\":");
        db_append_uint64(resp, (uint64_t)gpu.engine_clock_mhz);
    }
    if (gpu.memory_clock_mhz > 0) {
        db_append_str(resp, ",\"gpu_mem_clock_mhz\":");
        db_append_uint64(resp, (uint64_t)gpu.memory_clock_mhz);
    }
    if (gpu.activity_pct >= 0) {
        db_append_str(resp, ",\"gpu_activity_pct\":");
        db_append_uint64(resp, (uint64_t)gpu.activity_pct);
    }
    if (gpu.vddc_mv > 0) {
        db_append_str(resp, ",\"gpu_vddc_mv\":");
        db_append_uint64(resp, (uint64_t)gpu.vddc_mv);
    }
    db_append_str(resp, "}}");
}

static void handle_sys_telemetry_history(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"interval_sec\":60,\"capacity\":60,\"count\":");

    EnterCriticalSection(&g_telemetry_ring_lock);
    uint32_t count = g_telemetry_ring ? g_telemetry_ring->count : 0;
    uint32_t head = g_telemetry_ring ? g_telemetry_ring->head : 0;
    uint64_t total = g_telemetry_ring ? g_telemetry_ring->total_recorded : 0;

    db_append_uint64(resp, count);
    db_append_str(resp, ",\"total_recorded\":");
    db_append_uint64(resp, total);
    db_append_str(resp, ",\"samples\":[");

    if (g_telemetry_ring && count > 0) {
        /* Chronological iteration: oldest sample to newest sample */
        uint32_t start_idx = (head + TELEMETRY_HISTORY_SAMPLES - count) % TELEMETRY_HISTORY_SAMPLES;
        char num_buf[32];
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t idx = (start_idx + i) % TELEMETRY_HISTORY_SAMPLES;
            TelemetrySample *s = &g_telemetry_ring->samples[idx];
            if (i > 0) db_append_char(resp, ',');

            db_append_str(resp, "{\"ts\":");
            db_append_uint64(resp, s->timestamp_sec);
            db_append_str(resp, ",\"uptime_s\":");
            db_append_uint64(resp, s->uptime_sec);
            db_append_str(resp, ",\"cpu_pct\":");
            snprintf(num_buf, sizeof(num_buf), "%.1f", s->cpu_pct);
            db_append_str(resp, num_buf);
            db_append_str(resp, ",\"ram_avail_mb\":");
            db_append_uint64(resp, s->ram_avail_mb);
            db_append_str(resp, ",\"gpu_temp_c\":");
            if (s->gpu_temp_c >= 0.0f) {
                snprintf(num_buf, sizeof(num_buf), "%.1f", s->gpu_temp_c);
                db_append_str(resp, num_buf);
            } else {
                db_append_str(resp, "null");
            }
            if (s->gpu_engine_mhz > 0) {
                db_append_str(resp, ",\"gpu_clock_mhz\":");
                db_append_int64(resp, s->gpu_engine_mhz);
            }
            if (s->gpu_activity_pct >= 0) {
                db_append_str(resp, ",\"gpu_activity_pct\":");
                db_append_int64(resp, s->gpu_activity_pct);
            }
            db_append_str(resp, "}");
        }
    }
    LeaveCriticalSection(&g_telemetry_ring_lock);
    db_append_str(resp, "]}}");
}

static void handle_sys_drift_status(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    EnterCriticalSection(&g_drift_sentinel_lock);
    DriftSentinelState st = g_drift_sentinel;
    LeaveCriticalSection(&g_drift_sentinel_lock);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"samples_evaluated\":");
    db_append_uint64(resp, st.samples_evaluated);

    char num[256];
    snprintf(num, sizeof(num), ",\"ram_slope_mb_min\":%.3f,\"ram_r2\":%.3f,\"ram_monotonicity\":%.3f",
             st.ram_slope_mb_min, st.ram_r2, st.ram_monotonicity);
    db_append_str(resp, num);

    db_append_str(resp, ",\"ram_drift_detected\":");
    db_append_str(resp, st.ram_drift_detected ? "true" : "false");
    db_append_str(resp, ",\"ram_trims_triggered\":");
    db_append_uint64(resp, st.ram_trims_triggered);
    db_append_str(resp, ",\"last_ram_trim_sec\":");
    db_append_uint64(resp, st.last_ram_trim_sec);

    snprintf(num, sizeof(num), ",\"gpu_temp_c\":%.1f", st.gpu_temp_c);
    db_append_str(resp, num);

    db_append_str(resp, ",\"thermal_drift_detected\":");
    db_append_str(resp, st.thermal_drift_detected ? "true" : "false");
    db_append_str(resp, ",\"thermal_throttled\":");
    db_append_str(resp, st.thermal_throttled ? "true" : "false");
    db_append_str(resp, ",\"thermal_throttle_count\":");
    db_append_uint64(resp, st.thermal_throttle_count);
    db_append_str(resp, ",\"turbo_core_mode\":");
    db_append_str(resp, st.thermal_throttled ? "\"Disabled (Thermal Guard)\"" : "\"Aggressive\"");
    db_append_str(resp, "}}");
}

static void handle_log_get(const char *req, int64_t id, DynBuf *resp) {
    uint64_t since_seq = (uint64_t)json_get_int64(req, "since_seq", 0);
    char *min_lvl_str = json_get_string(req, "min_level");
    bool clear_logs = json_get_bool(req, "clear", false);
    int32_t min_lvl = parse_log_level(min_lvl_str);
    free(min_lvl_str);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"logs\":[");

    EnterCriticalSection(&g_log_lock);
    size_t start_idx = (g_log_head + LOG_RING_CAPACITY - g_log_count) % LOG_RING_CAPACITY;
    bool first = true;
    for (size_t i = 0; i < g_log_count; ++i) {
        size_t idx = (start_idx + i) % LOG_RING_CAPACITY;
        LogEntry *e = &g_log_ring[idx];
        if (e->seq > since_seq && e->level >= min_lvl) {
            if (!first) db_append_char(resp, ',');
            first = false;
            db_append_str(resp, "{\"seq\":");
            db_append_uint64(resp, e->seq);
            db_append_str(resp, ",\"uptime_ms\":");
            db_append_uint64(resp, e->uptime_ms);
            db_append_str(resp, ",\"level\":\"");
            db_append_str(resp, log_level_str(e->level));
            db_append_str(resp, "\",\"message\":\"");
            db_append_json_escaped(resp, e->msg);
            db_append_str(resp, "\"}");
        }
    }
    if (clear_logs) {
        g_log_head = 0;
        g_log_count = 0;
    }
    LeaveCriticalSection(&g_log_lock);
    db_append_str(resp, "]}}");
}

static void handle_log_clear(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    EnterCriticalSection(&g_log_lock);
    g_log_head = 0;
    g_log_count = 0;
    LeaveCriticalSection(&g_log_lock);
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"cleared\":true}}");
}

static void handle_sys_hardware(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    ULARGE_INTEGER free_bytes, total_bytes, total_free;
    BOOL disk_ok = GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, &total_free);

    SYSTEM_POWER_STATUS pwr;
    BOOL pwr_ok = GetSystemPowerStatus(&pwr);

    char comp_name[MAX_COMPUTERNAME_LENGTH + 1] = "";
    DWORD comp_len = sizeof(comp_name);
    GetComputerNameA(comp_name, &comp_len);

    char user_name[256] = "";
    DWORD user_len = sizeof(user_name);
    GetUserNameA(user_name, &user_len);

    char cpu_brand[128] = "Unknown Processor";
    HKEY hCpu;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hCpu) == ERROR_SUCCESS) {
        DWORD dsz = sizeof(cpu_brand);
        RegQueryValueExA(hCpu, "ProcessorNameString", NULL, NULL, (LPBYTE)cpu_brand, &dsz);
        RegCloseKey(hCpu);
    }
    char *cpu_p = cpu_brand;
    while (*cpu_p == ' ') cpu_p++;

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{");

    db_append_str(resp, "\"computer_name\":\"");
    db_append_json_escaped(resp, comp_name);
    db_append_str(resp, "\",\"username\":\"");
    db_append_json_escaped(resp, user_name);
    db_append_str(resp, "\",\"cpu_brand\":\"");
    db_append_json_escaped(resp, cpu_p);
    db_append_str(resp, "\",\"cpu_cores\":");
    db_append_uint64(resp, si.dwNumberOfProcessors);

    db_append_str(resp, ",\"ram_total_mb\":");
    db_append_uint64(resp, mem.ullTotalPhys / (1024 * 1024));
    db_append_str(resp, ",\"ram_avail_mb\":");
    db_append_uint64(resp, mem.ullAvailPhys / (1024 * 1024));
    db_append_str(resp, ",\"ram_load_pct\":");
    db_append_uint64(resp, mem.dwMemoryLoad);

    if (disk_ok) {
        db_append_str(resp, ",\"c_drive_total_gb\":");
        db_append_uint64(resp, total_bytes.QuadPart / (1024 * 1024 * 1024));
        db_append_str(resp, ",\"c_drive_free_gb\":");
        db_append_uint64(resp, free_bytes.QuadPart / (1024 * 1024 * 1024));
    }

    if (pwr_ok) {
        db_append_str(resp, ",\"ac_online\":");
        db_append_str(resp, (pwr.ACLineStatus == 1) ? "true" : "false");
        db_append_str(resp, ",\"battery_pct\":");
        db_append_int64(resp, (pwr.BatteryLifePercent <= 100) ? (int64_t)pwr.BatteryLifePercent : -1);
    }

    db_append_str(resp, ",\"uptime_sec\":");
    db_append_uint64(resp, GetTickCount64() / 1000);
    db_append_str(resp, "}}");
}

static void handle_sys_trim(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    SmartTrimStats st;
    run_smart_trim(&st);

    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"trimmed\":true,\"processes_trimmed\":");
    db_append_uint64(resp, st.processes_trimmed);
    db_append_str(resp, ",\"candidates_evaluated\":");
    db_append_uint64(resp, st.candidates_evaluated);
    db_append_str(resp, ",\"ram_before_mb\":");
    db_append_uint64(resp, st.ram_before_bytes / (1024 * 1024));
    db_append_str(resp, ",\"avail_ram_mb\":");
    db_append_uint64(resp, mem.ullAvailPhys / (1024 * 1024));
    db_append_str(resp, "}}");
}

/* =========================================================================
 * MODULE 6: GUI SCREENSHOT & INPUT + WINDOWS 10 OPTIMIZATION
 * ========================================================================= */
static void handle_gui_screenshot(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    HDC hScreen = GetDC(NULL);
    if (!hScreen) {
        build_error_response(resp, id, RPC_ERR_GUI_FAILED, "GetDC(NULL) failed", GetLastError());
        return;
    }
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    HGDIOBJ hOld = SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY | CAPTUREBLT);

    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = w;
    bi.biHeight = h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    DWORD stride = ((w * 24 + 31) / 32) * 4;
    DWORD img_sz = stride * (DWORD)h;
    DWORD total_sz = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + img_sz;
    unsigned char *bmp = (unsigned char *)malloc(total_sz);
    if (!bmp) {
        SelectObject(hMem, hOld); DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(NULL, hScreen);
        build_error_response(resp, id, RPC_ERR_GUI_FAILED, "Out of memory", 0);
        return;
    }

    BITMAPFILEHEADER *bfh = (BITMAPFILEHEADER *)bmp;
    bfh->bfType = 0x4D42;
    bfh->bfSize = total_sz;
    bfh->bfReserved1 = 0;
    bfh->bfReserved2 = 0;
    bfh->bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    memcpy(bmp + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
    GetDIBits(hMem, hBmp, 0, (UINT)h, bmp + bfh->bfOffBits, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

    SelectObject(hMem, hOld); DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(NULL, hScreen);

    char *b64 = b64_encode(bmp, total_sz, NULL);
    free(bmp);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"width\":");
    db_append_int64(resp, w);
    db_append_str(resp, ",\"height\":");
    db_append_int64(resp, h);
    db_append_str(resp, ",\"image_b64\":\"");
    db_append_str(resp, b64 ? b64 : "");
    db_append_str(resp, "\"}}");
    free(b64);
}

static void handle_gui_input(const char *req, int64_t id, DynBuf *resp) {
    char *type = json_get_string(req, "input_type");
    int64_t x = json_get_int64(req, "x", 0);
    int64_t y = json_get_int64(req, "y", 0);
    char *button = json_get_string(req, "button");
    int64_t vk = json_get_int64(req, "vk", 0);
    char *text = json_get_string(req, "text");

    if (!type) {
        free(button); free(text);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing input_type", 0);
        return;
    }
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    if (sw <= 1) sw = 1024;
    if (sh <= 1) sh = 768;

    if (_stricmp(type, "mouse_move") == 0 || _stricmp(type, "mouse_click") == 0) {
        INPUT inp[3];
        ZeroMemory(inp, sizeof(inp));
        int cnt = 0;
        inp[cnt].type = INPUT_MOUSE;
        inp[cnt].mi.dx = (LONG)((x * 65535) / (sw - 1));
        inp[cnt].mi.dy = (LONG)((y * 65535) / (sh - 1));
        inp[cnt].mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
        cnt++;
        if (_stricmp(type, "mouse_click") == 0) {
            DWORD df = MOUSEEVENTF_LEFTDOWN, uf = MOUSEEVENTF_LEFTUP;
            if (button && _stricmp(button, "right") == 0) { df = MOUSEEVENTF_RIGHTDOWN; uf = MOUSEEVENTF_RIGHTUP; }
            inp[cnt].type = INPUT_MOUSE; inp[cnt++].mi.dwFlags = df;
            inp[cnt].type = INPUT_MOUSE; inp[cnt++].mi.dwFlags = uf;
        }
        SendInput((UINT)cnt, inp, sizeof(INPUT));
    } else if (_stricmp(type, "key_vk") == 0 && vk > 0) {
        INPUT inp[2];
        ZeroMemory(inp, sizeof(inp));
        inp[0].type = INPUT_KEYBOARD; inp[0].ki.wVk = (WORD)vk;
        inp[1].type = INPUT_KEYBOARD; inp[1].ki.wVk = (WORD)vk; inp[1].ki.dwFlags = KEYEVENTF_KEYUP;
        SendInput(2, inp, sizeof(INPUT));
    } else if (_stricmp(type, "text") == 0 && text) {
        for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
            INPUT inp[2];
            ZeroMemory(inp, sizeof(inp));
            inp[0].type = INPUT_KEYBOARD; inp[0].ki.wScan = (WORD)(*p); inp[0].ki.dwFlags = KEYEVENTF_UNICODE;
            inp[1].type = INPUT_KEYBOARD; inp[1].ki.wScan = (WORD)(*p); inp[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
            SendInput(2, inp, sizeof(INPUT));
        }
    }
    free(type); free(button); free(text);
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"injected\":true}}");
}

static void handle_opt_run(const char *req, int64_t id, DynBuf *resp) {
    bool disable_telemetry = json_get_bool(req, "disable_telemetry", true);
    bool disable_services = json_get_bool(req, "disable_unneeded_services", true);
    bool optimize_visuals = json_get_bool(req, "optimize_visual_effects", true);
    bool cleanup_disk = json_get_bool(req, "cleanup_disk", true);

    int svc_mod = 0, reg_mod = 0, files_del = 0;
    uint64_t bytes_freed = 0;
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);

    if (disable_telemetry && hSCM) {
        const char *tel_svcs[] = { "DiagTrack", "dmwappushservice" };
        for (size_t i = 0; i < 2; ++i) {
            SC_HANDLE hS = OpenServiceA(hSCM, tel_svcs[i], SERVICE_STOP | SERVICE_CHANGE_CONFIG);
            if (hS) {
                SERVICE_STATUS ss;
                ControlService(hS, SERVICE_CONTROL_STOP, &ss);
                if (ChangeServiceConfigA(hS, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) svc_mod++;
                CloseServiceHandle(hS);
            }
        }
    }
    if (disable_services && hSCM) {
        const char *svcs[] = { "SysMain", "WSearch", "MapsBroker", "XblAuthManager", "XblGameSave", "XboxNetApiSvc", "Fax" };
        for (size_t i = 0; i < sizeof(svcs) / sizeof(svcs[0]); ++i) {
            SC_HANDLE hS = OpenServiceA(hSCM, svcs[i], SERVICE_STOP | SERVICE_CHANGE_CONFIG);
            if (hS) {
                SERVICE_STATUS ss;
                ControlService(hS, SERVICE_CONTROL_STOP, &ss);
                if (ChangeServiceConfigA(hS, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL)) svc_mod++;
                CloseServiceHandle(hS);
            }
        }
    }
    if (hSCM) CloseServiceHandle(hSCM);

    if (optimize_visuals) {
        HKEY hK = NULL;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hK, NULL) == ERROR_SUCCESS) {
            DWORD v = 2;
            if (RegSetValueExA(hK, "VisualFXSetting", 0, REG_DWORD, (const BYTE *)&v, sizeof(DWORD)) == ERROR_SUCCESS) reg_mod++;
            RegCloseKey(hK);
        }
    }
    if (cleanup_disk) {
        char tmp[MAX_PATH];
        if (GetTempPathA(sizeof(tmp), tmp) > 0) {
            size_t l = strlen(tmp);
            if (l > 0 && tmp[l - 1] == '\\') tmp[l - 1] = '\0';
            delete_dir_recursive(tmp, &files_del, &bytes_freed);
        }
        delete_dir_recursive("C:\\Windows\\Temp", &files_del, &bytes_freed);
    }

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"services_adjusted\":");
    db_append_int64(resp, svc_mod);
    db_append_str(resp, ",\"registry_keys_updated\":");
    db_append_int64(resp, reg_mod);
    db_append_str(resp, ",\"temp_files_deleted\":");
    db_append_int64(resp, files_del);
    db_append_str(resp, ",\"disk_bytes_freed\":");
    db_append_uint64(resp, bytes_freed);
    db_append_str(resp, "}}");
}

static void handle_kiosk_status(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    EnterCriticalSection(&g_kiosk_sentinel_lock);
    KioskSentinelState st = g_kiosk_sentinel;
    LeaveCriticalSection(&g_kiosk_sentinel_lock);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"enabled\":");
    db_append_str(resp, st.enabled ? "true" : "false");
    db_append_str(resp, ",\"target_name\":\"");
    db_append_json_escaped(resp, st.target_name);
    db_append_str(resp, "\",\"is_running\":");
    db_append_str(resp, st.is_running ? "true" : "false");
    db_append_str(resp, ",\"is_hung\":");
    db_append_str(resp, st.is_hung ? "true" : "false");
    db_append_str(resp, ",\"auto_relaunch_on_crash\":");
    db_append_str(resp, st.auto_relaunch_on_crash ? "true" : "false");
    db_append_str(resp, ",\"restart_count_total\":");
    db_append_uint64(resp, st.restart_count_total);
    db_append_str(resp, ",\"restarts_in_window\":");
    db_append_uint64(resp, st.restarts_in_window);
    db_append_str(resp, ",\"circuit_breaker_tripped\":");
    db_append_str(resp, st.circuit_breaker_tripped ? "true" : "false");
    db_append_str(resp, ",\"backoff_sec\":");
    db_append_uint64(resp, st.backoff_sec);
    db_append_str(resp, ",\"last_restart_sec\":");
    db_append_uint64(resp, st.last_restart_sec);
    db_append_str(resp, ",\"last_action\":\"");
    db_append_json_escaped(resp, st.last_action);
    db_append_str(resp, "\"}}");
}

static void handle_kiosk_restart(const char *req, int64_t id, DynBuf *resp) {
    bool force = json_get_bool(req, "force", true);
    char *custom_target = json_get_string(req, "target");

    EnterCriticalSection(&g_kiosk_sentinel_lock);
    if (custom_target && strlen(custom_target) > 0) {
        strncpy(g_kiosk_sentinel.target_name, custom_target, sizeof(g_kiosk_sentinel.target_name) - 1);
        g_kiosk_sentinel.target_name[sizeof(g_kiosk_sentinel.target_name) - 1] = '\0';
    }
    g_kiosk_sentinel.is_hung = false;
    g_kiosk_sentinel.circuit_breaker_tripped = false;
    g_kiosk_sentinel.restart_count_total++;
    g_kiosk_sentinel.last_restart_sec = (uint64_t)time(NULL);
    snprintf(g_kiosk_sentinel.last_action, sizeof(g_kiosk_sentinel.last_action), "MANUAL_RESTART_FORCED");
    LeaveCriticalSection(&g_kiosk_sentinel_lock);
    free(custom_target);

    agent_log(LOG_LVL_INFO, "[KIOSK-SENTINEL] Manual kiosk restart requested (force=%s). Killing and relaunching...", force ? "true" : "false");

    WinExec("taskkill /F /IM chrome.exe /IM mpv.exe", SW_HIDE);
    Sleep(1500);

    UINT r = WinExec("cmd.exe /c start \"\" \"C:\\Users\\Sea\\Desktop\\Lancer_Supermium_LowRAM.bat\"", SW_HIDE);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"success\":");
    db_append_str(resp, (r > 31) ? "true" : "false");
    db_append_str(resp, ",\"action\":\"restarted\",\"target\":\"");
    EnterCriticalSection(&g_kiosk_sentinel_lock);
    db_append_json_escaped(resp, g_kiosk_sentinel.target_name);
    LeaveCriticalSection(&g_kiosk_sentinel_lock);
    db_append_str(resp, "\"}}");
}

static void handle_kiosk_configure(const char *req, int64_t id, DynBuf *resp) {
    bool enabled = json_get_bool(req, "enabled", true);
    bool auto_relaunch = json_get_bool(req, "auto_relaunch_on_crash", false);
    char *target = json_get_string(req, "target");

    EnterCriticalSection(&g_kiosk_sentinel_lock);
    g_kiosk_sentinel.enabled = enabled;
    g_kiosk_sentinel.auto_relaunch_on_crash = auto_relaunch;
    if (target && strlen(target) > 0) {
        strncpy(g_kiosk_sentinel.target_name, target, sizeof(g_kiosk_sentinel.target_name) - 1);
        g_kiosk_sentinel.target_name[sizeof(g_kiosk_sentinel.target_name) - 1] = '\0';
    }
    LeaveCriticalSection(&g_kiosk_sentinel_lock);
    free(target);

    handle_kiosk_status(req, id, resp);
}

/* =========================================================================
 * NETWORK FRAMING & RPC DISPATCHER
 * ========================================================================= */
static bool send_all(SOCKET s, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        int n = send(s, buf + total, (int)(len - total), 0);
        if (n <= 0) return false;
        total += (size_t)n;
    }
    return true;
}

static bool recv_all(SOCKET s, char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        int n = recv(s, buf + total, (int)(len - total), 0);
        if (n <= 0) return false;
        total += (size_t)n;
    }
    return true;
}

static bool send_frame(SOCKET s, const char *json_str) {
    uint32_t len = (uint32_t)strlen(json_str);
    uint32_t net_len = htonl(len);
    EnterCriticalSection(&g_send_lock);
    bool ok = send_all(s, (const char *)&net_len, 4) && send_all(s, json_str, len);
    LeaveCriticalSection(&g_send_lock);
    return ok;
}

static char *recv_frame(SOCKET s) {
    uint32_t net_len = 0;
    if (!recv_all(s, (char *)&net_len, 4)) return NULL;
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > MAX_FRAME_SIZE) return NULL;
    char *buf = (char *)malloc(len + 1);
    if (!buf) return NULL;
    if (!recv_all(s, buf, len)) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/* =========================================================================
 * FAST IEEE 802.3 CRC32 (SLICING-BY-4) - 4 KB L1 CACHE FOOTPRINT (SWARM-189)
 * ========================================================================= */
static uint32_t g_crc32_table[4][256];
static volatile LONG g_crc32_initialized = 0;

static void crc32_init(void) {
    if (InterlockedCompareExchange(&g_crc32_initialized, 1, 0) == 0) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (int j = 0; j < 8; j++) {
                crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320U : 0);
            }
            g_crc32_table[0][i] = crc;
        }
        for (uint32_t i = 0; i < 256; i++) {
            for (int slice = 1; slice < 4; slice++) {
                g_crc32_table[slice][i] = (g_crc32_table[slice - 1][i] >> 8) ^
                                          g_crc32_table[0][g_crc32_table[slice - 1][i] & 0xFF];
            }
        }
    }
}

static uint32_t crc32_compute(const void *buf, size_t len, uint32_t initial_crc) {
    if (!g_crc32_initialized) crc32_init();
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t crc = initial_crc ^ 0xFFFFFFFFU;

    while (len >= 4) {
        uint32_t one_word = *(const uint32_t *)p ^ crc;
        crc = g_crc32_table[3][one_word & 0xFF] ^
              g_crc32_table[2][(one_word >> 8) & 0xFF] ^
              g_crc32_table[1][(one_word >> 16) & 0xFF] ^
              g_crc32_table[0][(one_word >> 24) & 0xFF];
        p += 4;
        len -= 4;
    }

    while (len > 0) {
        crc = (crc >> 8) ^ g_crc32_table[0][(crc ^ *p) & 0xFF];
        p++;
        len--;
    }

    return crc ^ 0xFFFFFFFFU;
}

/* =========================================================================
 * BINARY TRANSFER SESSION STATE (ZERO-HEAP CHUNKING - SWARM-180/189)
 * ========================================================================= */
typedef struct {
    volatile LONG is_active;
    uint32_t file_id;
    HANDLE hFile;
    char file_path[MAX_PATH];
    uint64_t total_written;
    uint64_t expected_size;
    DWORD start_tick;
    DWORD last_activity_tick;

    /* Streaming SHA-256 state: CNG normally, CryptoAPI on legacy (same digest) */
#ifdef AGENT_LEGACY_XP
    capi_sha256_stream capi;
    bool capi_active;
#else
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    PBYTE pbHashObj;
    DWORD cbHashObj;
#endif
    char final_sha256[65];
    bool hash_finalized;

    CRITICAL_SECTION lock;
} BinaryTransferSession;

static BinaryTransferSession g_bin_session;
static uint8_t g_bin_chunk_buf[BRIDGE_BIN_MAX_CHUNK_SIZE]; /* 64 KB in .bss */

static void bin_session_abort_locked(void) {
#ifdef AGENT_LEGACY_XP
    if (g_bin_session.capi_active) {
        unsigned char tmp[32];
        capi_stream_final(&g_bin_session.capi, tmp);
        g_bin_session.capi_active = false;
    }
#else
    if (g_bin_session.hHash) {
        BCryptDestroyHash(g_bin_session.hHash);
        g_bin_session.hHash = NULL;
    }
    if (g_bin_session.pbHashObj) {
        free(g_bin_session.pbHashObj);
        g_bin_session.pbHashObj = NULL;
    }
    if (g_bin_session.hAlg) {
        BCryptCloseAlgorithmProvider(g_bin_session.hAlg, 0);
        g_bin_session.hAlg = NULL;
    }
#endif
    if (g_bin_session.hFile != INVALID_HANDLE_VALUE && g_bin_session.hFile != NULL) {
        CloseHandle(g_bin_session.hFile);
        g_bin_session.hFile = INVALID_HANDLE_VALUE;
    }
    g_bin_session.is_active = 0;
}

static bool send_bin_ack(SOCKET s, uint32_t file_id, uint32_t status, uint64_t offset, uint32_t bytes_written, uint32_t chunk_crc32) {
    BridgeBinaryFrameTag tag;
    tag.magic = BRIDGE_BIN_MAGIC;
    tag.frame_type = BIN_FRAME_TYPE_ACK;
    tag.version = BRIDGE_BIN_VERSION;
    tag.flags = 0;

    BridgeBinaryChunkAck ack;
    ack.file_id = file_id;
    ack.status = status;
    ack.offset = offset;
    ack.bytes_written = bytes_written;
    ack.chunk_crc32 = chunk_crc32;

    EnterCriticalSection(&g_send_lock);
    bool ok = send_all(s, (const char *)&tag, sizeof(tag)) &&
              send_all(s, (const char *)&ack, sizeof(ack));
    LeaveCriticalSection(&g_send_lock);

    if (ok) {
        bw_flow_push(BW_FLOW_OUT, "chunk.ack", (uint64_t)(sizeof(tag) + sizeof(ack)));
        EnterCriticalSection(&g_telemetry_lock);
        g_bytes_tx += sizeof(tag) + sizeof(ack);
        g_packets_tx++;
        LeaveCriticalSection(&g_telemetry_lock);
    }
    return ok;
}

static bool handle_bin_chunk(SOCKET s, const uint8_t *prefix) {
    if (!prefix) return false;
    const BridgeBinaryFrameTag *tag = (const BridgeBinaryFrameTag *)prefix;
    if (tag->magic != BRIDGE_BIN_MAGIC) {
        agent_log(LOG_LVL_ERROR, "[BIN] Invalid binary magic: 0x%02X", tag->magic);
        return false;
    }

    if (tag->frame_type == BIN_FRAME_TYPE_ABORT) {
        EnterCriticalSection(&g_bin_session.lock);
        bin_session_abort_locked();
        LeaveCriticalSection(&g_bin_session.lock);
        agent_log(LOG_LVL_WARN, "[BIN] Master aborted binary transfer session");
        return true;
    }

    /* 1. Receive 24-byte chunk header */
    BridgeBinaryChunkHeader hdr;
    if (!recv_all(s, (char *)&hdr, sizeof(BridgeBinaryChunkHeader))) {
        agent_log(LOG_LVL_ERROR, "[BIN] Failed to receive 24-byte chunk header");
        return false;
    }

    /* 2. Validate payload length against static .bss buffer */
    if (hdr.length > BRIDGE_BIN_MAX_CHUNK_SIZE) {
        agent_log(LOG_LVL_ERROR, "[BIN] Chunk length %u exceeds max limit (%u)", 
                  (unsigned int)hdr.length, BRIDGE_BIN_MAX_CHUNK_SIZE);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_SIZE, hdr.offset, 0, 0);
        return false;
    }

    /* 3. Direct socket recv into static 64 KB .bss buffer (malloc = 0) */
    if (hdr.length > 0) {
        if (!recv_all(s, (char *)g_bin_chunk_buf, hdr.length)) {
            agent_log(LOG_LVL_ERROR, "[BIN] Failed receiving %u payload bytes", (unsigned int)hdr.length);
            return false;
        }
    }

    bw_flow_push(BW_FLOW_IN, "file.chunk", (uint64_t)hdr.length);
    EnterCriticalSection(&g_telemetry_lock);
    g_bytes_rx += sizeof(BridgeBinaryChunkHeader) + hdr.length;
    g_packets_rx++;
    LeaveCriticalSection(&g_telemetry_lock);

    /* 4. Fast CRC32 verification (IEEE 802.3 Slicing-by-4) */
    uint32_t calc_crc = crc32_compute(g_bin_chunk_buf, hdr.length, 0);
    if (calc_crc != hdr.crc32) {
        agent_log(LOG_LVL_WARN, "[BIN] CRC32 mismatch file_id %u off %llu: got 0x%08X exp 0x%08X",
                  hdr.file_id, (unsigned long long)hdr.offset, calc_crc, hdr.crc32);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_CRC, hdr.offset, 0, calc_crc);
        return true; /* Keep connection open so master can retry */
    }

    EnterCriticalSection(&g_bin_session.lock);

    /* 5. Validate active transfer session */
    if (!g_bin_session.is_active || g_bin_session.file_id != hdr.file_id || 
        g_bin_session.hFile == INVALID_HANDLE_VALUE || g_bin_session.hFile == NULL) {
        LeaveCriticalSection(&g_bin_session.lock);
        agent_log(LOG_LVL_ERROR, "[BIN] No active session for file_id %u", hdr.file_id);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_SESSION, hdr.offset, 0, calc_crc);
        return true;
    }

    /* 6. Seek to file offset */
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)hdr.offset;
    if (!SetFilePointerEx(g_bin_session.hFile, li, NULL, FILE_BEGIN)) {
        DWORD err = GetLastError();
        LeaveCriticalSection(&g_bin_session.lock);
        agent_log(LOG_LVL_ERROR, "[BIN] SetFilePointerEx failed at %llu: %lu", (unsigned long long)hdr.offset, err);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_IO, hdr.offset, 0, err);
        return true;
    }

    /* 7. Direct WriteFile to disk */
    DWORD written = 0;
    BOOL write_ok = TRUE;
    if (hdr.length > 0) {
        write_ok = WriteFile(g_bin_session.hFile, g_bin_chunk_buf, (DWORD)hdr.length, &written, NULL);
    }

    if (!write_ok || written != hdr.length) {
        DWORD err = GetLastError();
        LeaveCriticalSection(&g_bin_session.lock);
        agent_log(LOG_LVL_ERROR, "[BIN] WriteFile failed: len=%u written=%lu err=%lu", 
                  (unsigned int)hdr.length, written, err);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_IO, hdr.offset, written, err);
        return true;
    }

    /* 8. Stream SHA-256 while data is hot in CPU cache */
#ifdef AGENT_LEGACY_XP
    if (g_bin_session.capi_active && written > 0) {
        capi_stream_update(&g_bin_session.capi, g_bin_chunk_buf, written);
    }
#else
    if (g_bin_session.hHash && written > 0) {
        BCryptHashData(g_bin_session.hHash, (PBYTE)g_bin_chunk_buf, (ULONG)written, 0);
    }
#endif

    g_bin_session.total_written += written;
    g_bin_session.last_activity_tick = GetTickCount();

    if (hdr.flags & BIN_FLAG_SYNC) {
        FlushFileBuffers(g_bin_session.hFile);
    }

    /* 9. Finalize if EOF flag set */
    if (hdr.flags & BIN_FLAG_EOF) {
        BYTE rgbHash[32];
#ifdef AGENT_LEGACY_XP
        if (g_bin_session.capi_active) {
            if (capi_stream_final(&g_bin_session.capi, rgbHash)) {
                legacy_hex32(rgbHash, g_bin_session.final_sha256);
                g_bin_session.hash_finalized = true;
            }
            g_bin_session.capi_active = false;
        }
#else
        if (g_bin_session.hHash) {
            if (NT_SUCCESS(BCryptFinishHash(g_bin_session.hHash, rgbHash, sizeof(rgbHash), 0))) {
                for (int i = 0; i < 32; ++i) {
                    snprintf(g_bin_session.final_sha256 + (i * 2), 3, "%02x", rgbHash[i]);
                }
                g_bin_session.final_sha256[64] = '\0';
                g_bin_session.hash_finalized = true;
            }
            BCryptDestroyHash(g_bin_session.hHash);
            g_bin_session.hHash = NULL;
        }
#endif

        CloseHandle(g_bin_session.hFile);
        g_bin_session.hFile = INVALID_HANDLE_VALUE;

        agent_log(LOG_LVL_INFO, CLR_GREEN "[BIN] Transfer completed: file_id=%u total=%llu bytes, SHA-256=%s" CLR_RESET,
                  hdr.file_id, (unsigned long long)g_bin_session.total_written, g_bin_session.final_sha256);
    }

    LeaveCriticalSection(&g_bin_session.lock);

    /* 10. Send Binary ACK */
    return send_bin_ack(s, hdr.file_id, BIN_ACK_OK, hdr.offset, written, calc_crc);
}

static void handle_fs_bin_open(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    uint32_t file_id = (uint32_t)json_get_int64(req, "file_id", 0);
    bool truncate = json_get_bool(req, "truncate", true);
    int64_t expected_size = json_get_int64(req, "size", 0);

    if (!path || file_id == 0) {
        free(path);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path or file_id", 0);
        return;
    }

    EnterCriticalSection(&g_bin_session.lock);
    if (g_bin_session.is_active) {
        bin_session_abort_locked();
    }

    DWORD disp = truncate ? CREATE_ALWAYS : OPEN_ALWAYS;
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, disp, 
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        LeaveCriticalSection(&g_bin_session.lock);
        free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "CreateFileA failed", err);
        return;
    }

    bool stream_ok = false;
#ifdef AGENT_LEGACY_XP
    capi_sha256_stream open_st;
    if (capi_stream_init(&open_st)) {
        g_bin_session.capi = open_st;
        g_bin_session.capi_active = true;
        stream_ok = true;
    } else {
        g_bin_session.capi_active = false;
    }
#else
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PBYTE pbHashObj = NULL;
    DWORD cbHashObj = 0, cbData = 0;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObj, sizeof(DWORD), &cbData, 0);
        if (NT_SUCCESS(status)) {
            pbHashObj = (PBYTE)malloc(cbHashObj);
            if (pbHashObj) {
                status = BCryptCreateHash(hAlg, &hHash, pbHashObj, cbHashObj, NULL, 0, 0);
                if (!NT_SUCCESS(status)) {
                    free(pbHashObj);
                    pbHashObj = NULL;
                }
            }
        }
    }
#endif
    (void)stream_ok;

    g_bin_session.is_active = 1;
    g_bin_session.file_id = file_id;
    g_bin_session.hFile = h;
    strncpy(g_bin_session.file_path, path, sizeof(g_bin_session.file_path) - 1);
    g_bin_session.file_path[sizeof(g_bin_session.file_path) - 1] = '\0';
    g_bin_session.total_written = 0;
    g_bin_session.expected_size = (uint64_t)expected_size;
    g_bin_session.start_tick = GetTickCount();
    g_bin_session.last_activity_tick = GetTickCount();
#ifndef AGENT_LEGACY_XP
    g_bin_session.hAlg = hAlg;
    g_bin_session.hHash = hHash;
    g_bin_session.pbHashObj = pbHashObj;
    g_bin_session.cbHashObj = cbHashObj;
#endif
    g_bin_session.final_sha256[0] = '\0';
    g_bin_session.hash_finalized = false;

    LeaveCriticalSection(&g_bin_session.lock);
    free(path);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"status\":\"ready\",\"file_id\":");
    db_append_uint64(resp, file_id);
    db_append_str(resp, ",\"chunk_size\":");
    db_append_uint64(resp, BRIDGE_BIN_MAX_CHUNK_SIZE);
    db_append_str(resp, "}}");
}

static void handle_fs_bin_close(const char *req, int64_t id, DynBuf *resp) {
    uint32_t file_id = (uint32_t)json_get_int64(req, "file_id", 0);

    EnterCriticalSection(&g_bin_session.lock);
    if (!g_bin_session.is_active || (file_id != 0 && g_bin_session.file_id != file_id)) {
        LeaveCriticalSection(&g_bin_session.lock);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "No matching active binary session", 0);
        return;
    }

#ifdef AGENT_LEGACY_XP
    if (!g_bin_session.hash_finalized && g_bin_session.capi_active) {
        BYTE rgbHash[32];
        if (capi_stream_final(&g_bin_session.capi, rgbHash)) {
            legacy_hex32(rgbHash, g_bin_session.final_sha256);
            g_bin_session.hash_finalized = true;
        }
        g_bin_session.capi_active = false;
    }
#else
    if (!g_bin_session.hash_finalized && g_bin_session.hHash) {
        BYTE rgbHash[32];
        if (NT_SUCCESS(BCryptFinishHash(g_bin_session.hHash, rgbHash, sizeof(rgbHash), 0))) {
            for (int i = 0; i < 32; ++i) {
                snprintf(g_bin_session.final_sha256 + (i * 2), 3, "%02x", rgbHash[i]);
            }
            g_bin_session.final_sha256[64] = '\0';
            g_bin_session.hash_finalized = true;
        }
    }

    if (g_bin_session.hHash) { BCryptDestroyHash(g_bin_session.hHash); g_bin_session.hHash = NULL; }
    if (g_bin_session.pbHashObj) { free(g_bin_session.pbHashObj); g_bin_session.pbHashObj = NULL; }
    if (g_bin_session.hAlg) { BCryptCloseAlgorithmProvider(g_bin_session.hAlg, 0); g_bin_session.hAlg = NULL; }
#endif
    if (g_bin_session.hFile != INVALID_HANDLE_VALUE && g_bin_session.hFile != NULL) {
        CloseHandle(g_bin_session.hFile);
        g_bin_session.hFile = INVALID_HANDLE_VALUE;
    }

    uint64_t total = g_bin_session.total_written;
    char sha[65];
    strncpy(sha, g_bin_session.final_sha256, sizeof(sha));
    sha[64] = '\0';

    g_bin_session.is_active = 0;
    LeaveCriticalSection(&g_bin_session.lock);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"file_id\":");
    db_append_uint64(resp, file_id);
    db_append_str(resp, ",\"total_written\":");
    db_append_uint64(resp, total);
    db_append_str(resp, ",\"file_sha256\":\"");
    db_append_str(resp, sha);
    db_append_str(resp, "\"}}");
}

static void dispatch_rpc(const char *req, DynBuf *resp, bool *trigger_exit) {
    int64_t id = json_get_int64(req, "id", 0);
    /* v4: authentication is session-level (mutual handshake + per-frame HMAC).
       By the time dispatch runs, the envelope MAC is already verified. */
    char *method = json_get_string(req, "method");

    if (!method) {
        build_error_response(resp, id, RPC_ERR_INVALID_REQ, "Missing method", 0);
        return;
    }

    g_rpc_calls_total++;
    const char *short_method = method ? method : "UNKNOWN";

    if (strcmp(method, "sys.ping") == 0) {
        db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
        db_append_int64(resp, id);
        db_append_str(resp, ",\"result\":{\"pong\":true,\"version\":\"" BRIDGE_PROTOCOL_VERSION "\",\"uptime_ms\":");
        db_append_uint64(resp, GetTickCount64());
        db_append_str(resp, "}}");
    } else if (strcmp(method, "exec.run") == 0) {
        handle_exec_run(req, id, resp);
    } else if (strcmp(method, "fs.read") == 0) {
        handle_fs_read(req, id, resp);
    } else if (strcmp(method, "fs.write") == 0) {
        handle_fs_write(req, id, resp);
    } else if (strcmp(method, "fs.hash") == 0) {
        handle_fs_hash(req, id, resp);
    } else if (strcmp(method, "fs.patch") == 0) {
        handle_fs_patch(req, id, resp);
    } else if (strcmp(method, "fs.list") == 0) {
        handle_fs_list(req, id, resp);
    } else if (strcmp(method, "fs.find") == 0 || strcmp(method, "fs.search") == 0) {
        handle_fs_find(req, id, resp);
    } else if (strcmp(method, "fs.delete") == 0) {
        handle_fs_delete(req, id, resp);
    } else if (strcmp(method, "fs.mkdir") == 0) {
        handle_fs_mkdir(req, id, resp);
    } else if (strcmp(method, "fs.bin_open") == 0) {
        handle_fs_bin_open(req, id, resp);
    } else if (strcmp(method, "fs.bin_close") == 0) {
        handle_fs_bin_close(req, id, resp);
    } else if (strcmp(method, "agent.update") == 0) {
        handle_agent_update(req, id, resp, trigger_exit);
    } else if (strcmp(method, "reg.read") == 0) {
        handle_reg_read(req, id, resp);
    } else if (strcmp(method, "reg.write") == 0) {
        handle_reg_write(req, id, resp);
    } else if (strcmp(method, "reg.delete") == 0) {
        handle_reg_delete(req, id, resp);
    } else if (strcmp(method, "svc.op") == 0) {
        handle_svc_op(req, id, resp);
    } else if (strcmp(method, "proc.list") == 0) {
        handle_proc_list(req, id, resp);
    } else if (strcmp(method, "proc.kill") == 0) {
        handle_proc_kill(req, id, resp);
    } else if (strcmp(method, "proc.priority") == 0) {
        handle_proc_priority(req, id, resp);
    } else if (strcmp(method, "sys.diag") == 0 || strcmp(method, "sys.telemetry") == 0) {
        handle_sys_diag(req, id, resp);
    } else if (strcmp(method, "sys.telemetry_history") == 0) {
        handle_sys_telemetry_history(req, id, resp);
    } else if (strcmp(method, "sys.drift_status") == 0) {
        handle_sys_drift_status(req, id, resp);
    } else if (strcmp(method, "kiosk.status") == 0) {
        handle_kiosk_status(req, id, resp);
    } else if (strcmp(method, "kiosk.restart") == 0) {
        handle_kiosk_restart(req, id, resp);
    } else if (strcmp(method, "kiosk.configure") == 0) {
        handle_kiosk_configure(req, id, resp);
    } else if (strcmp(method, "sys.hardware") == 0) {
        handle_sys_hardware(req, id, resp);
    } else if (strcmp(method, "sys.trim") == 0) {
        handle_sys_trim(req, id, resp);
    } else if (strcmp(method, "log.get") == 0) {
        handle_log_get(req, id, resp);
    } else if (strcmp(method, "log.clear") == 0) {
        handle_log_clear(req, id, resp);
    } else if (strcmp(method, "gui.screenshot") == 0) {
        handle_gui_screenshot(req, id, resp);
    } else if (strcmp(method, "gui.input") == 0) {
        handle_gui_input(req, id, resp);
    } else if (strcmp(method, "opt.run") == 0) {
        handle_opt_run(req, id, resp);
    } else {
        build_error_response(resp, id, RPC_ERR_METHOD_NOT_FOUND, "Method not found", 0);
    }

    free(method);
}

/* Read one length-prefixed JSON frame (binary tag refused here). Caller frees *out_json. */
static bool recv_json_frame(SOCKET s, char **out_json) {
    uint8_t prefix[4];
    if (!recv_all(s, (char *)prefix, 4)) return false;
    if (prefix[0] == BRIDGE_BIN_MAGIC) return false;
    uint32_t len = ntohl(*(uint32_t *)prefix);
    if (len == 0 || len > MAX_FRAME_SIZE) return false;
    char *buf = (char *)malloc(len + 1);
    if (!buf) return false;
    if (!recv_all(s, buf, len)) { free(buf); return false; }
    buf[len] = '\0';
    *out_json = buf;
    return true;
}

static void run_reverse_session(SOCKET s, bool *trigger_exit) {
    /* Link is up but nothing is proven yet: the green CONNECTED banner only
     * fires after mutual auth below, so auth rejections never spam it. */
    agent_log(LOG_LVL_DEBUG, "Link up to %s:%u, authenticating...", g_master_host, (unsigned int)g_master_port);

    g_have_sess = false;

    /* v4 hello: identity + fresh nonce. The PSK itself NEVER crosses the wire. */
    char agent_nonce[33];
    if (!gen_hex_nonce(agent_nonce)) return;
    char hello[768];
    snprintf(hello, sizeof(hello),
             "{\"jsonrpc\":\"2.0\",\"method\":\"agent.hello\",\"params\":{\"version\":\"" BRIDGE_PROTOCOL_VERSION "\",\"arch\":\"" AGENT_ARCH "\",\"os\":\"windows\",\"pid\":%lu,\"agent_id\":\"%s\",\"agent_nonce\":\"%s\"}}",
             (unsigned long)GetCurrentProcessId(), g_agent_id, agent_nonce);
    if (!send_frame(s, hello)) return;
    bw_flow_push(BW_FLOW_OUT, "agent.hello", strlen(hello));

    /* Expect auth.challenge {master_nonce} */
    char *ch = NULL;
    if (!recv_json_frame(s, &ch)) return;
    bw_flow_push(BW_FLOW_IN, "auth.challenge", strlen(ch));
    char *ch_method = json_get_string(ch, "method");
    char *master_nonce = json_get_string(ch, "master_nonce");
    bool ch_ok = ch_method && strcmp(ch_method, "auth.challenge") == 0 && master_nonce && strlen(master_nonce) == 32;
    free(ch_method);
    free(ch);
    if (!ch_ok) { if (master_nonce) free(master_nonce); return; }

    /* Prove PSK possession: HMAC(psk, agent_nonce + master_nonce + agent_id) */
    char rab[32 + 32 + 64 + 1];
    snprintf(rab, sizeof(rab), "%s%s%s", agent_nonce, master_nonce, g_agent_id);
    char rh[65];
    if (!compute_hmac_sha256_hex((unsigned char *)g_psk_token, strlen(g_psk_token),
                                 (unsigned char *)rab, strlen(rab), rh)) { free(master_nonce); return; }
    char aresp[512];
    snprintf(aresp, sizeof(aresp),
             "{\"jsonrpc\":\"2.0\",\"method\":\"auth.response\",\"params\":{\"agent_id\":\"%s\",\"hmac\":\"%s\"}}",
             g_agent_id, rh);
    if (!send_frame(s, aresp)) { free(master_nonce); return; }
    bw_flow_push(BW_FLOW_OUT, "auth.response", strlen(aresp));

    /* Expect auth.confirm; verify the MASTER (mutual auth) */
    char *cf = NULL;
    if (!recv_json_frame(s, &cf)) { free(master_nonce); return; }
    bw_flow_push(BW_FLOW_IN, "auth.confirm", strlen(cf));
    char *cf_method = json_get_string(cf, "method");
    char *peer_h = json_get_string(cf, "hmac");
    char rab2[32 + 32 + 64 + 1];
    snprintf(rab2, sizeof(rab2), "%s%s%s", master_nonce, agent_nonce, g_agent_id);
    char expect2[65];
    bool cf_ok = cf_method && strcmp(cf_method, "auth.confirm") == 0 && peer_h
        && compute_hmac_sha256_hex((unsigned char *)g_psk_token, strlen(g_psk_token),
                                   (unsigned char *)rab2, strlen(rab2), expect2)
        && constant_time_eq(peer_h, expect2);
    free(cf_method);
    free(peer_h);
    free(cf);
    if (!cf_ok) { free(master_nonce); bw_note_error("master auth failed"); return; }
    if (!derive_sesskey(g_psk_token, agent_nonce, master_nonce, g_sesskey)) { free(master_nonce); bw_note_error("session key failed"); return; }
    free(master_nonce);
    g_have_sess = true;
    g_session_start_tick = GetTickCount64();
    InterlockedExchange(&g_conn_state, BW_STATE_CONNECTED);
    bw_note_error("");
    agent_log(LOG_LVL_INFO, "Mutual auth complete as '%s'; session key derived.", g_agent_id);
    agent_log(LOG_LVL_INFO, CLR_GREEN CLR_BOLD "[CONNECTED]" CLR_RESET " Connected to Master at %s:%u (Zero-latency queue ready)", g_master_host, (unsigned int)g_master_port); SetConsoleTitleA("Bridge Agent [CONNECTED - Ready]");

    while (InterlockedCompareExchange(&g_running, 1, 1) == 1 && !(*trigger_exit)) {
        uint8_t prefix[4];
        if (!recv_all(s, (char *)prefix, 4)) break;

        /* Check for Binary Frame (0xBF) - only valid on this authenticated session */
        if (prefix[0] == BRIDGE_BIN_MAGIC) {
            if (!handle_bin_chunk(s, prefix)) {
                break;
            }
            continue;
        }

        /* v4 envelope: {"v":4,"body_b64":"...","mac":"..."} */
        uint32_t net_len = *(uint32_t *)prefix;
        uint32_t len = ntohl(net_len);
        if (len == 0 || len > MAX_FRAME_SIZE) {
            agent_log(LOG_LVL_ERROR, "Invalid JSON-RPC frame length: %u", (unsigned int)len);
            break;
        }

        char *frame = (char *)malloc(len + 1);
        if (!frame) break;
        if (!recv_all(s, frame, len)) {
            free(frame);
            break;
        }
        frame[len] = '\0';

        size_t frame_bytes = len;
        g_bytes_rx += frame_bytes;

        char *b64 = json_get_string(frame, "body_b64");
        char *mac = json_get_string(frame, "mac");
        int64_t v = json_get_int64(frame, "v", 0);
        bool mac_ok = (v == 4 && b64 && mac);
        char expect[65];
        if (mac_ok) {
            mac_ok = compute_hmac_sha256_hex(g_sesskey, 32, (unsigned char *)b64, strlen(b64), expect)
                && constant_time_eq(mac, expect);
        }
        if (!mac_ok) {
            agent_log(LOG_LVL_ERROR, "Bad session MAC; dropping connection.");
            if (b64) free(b64);
            if (mac) free(mac);
            free(frame);
            break;
        }
        size_t inner_len = 0;
        unsigned char *inner = b64_decode(b64, &inner_len);
        free(b64);
        free(mac);
        free(frame);
        if (!inner || inner_len == 0 || inner_len > MAX_FRAME_SIZE) {
            if (inner) free(inner);
            break;
        }
        char *req = (char *)malloc(inner_len + 1);
        if (!req) { free(inner); break; }
        memcpy(req, inner, inner_len);
        req[inner_len] = '\0';
        free(inner);

        char *method = json_get_string(req, "method");
        int64_t id = json_get_int64(req, "id", 0);
        const char *short_method = method ? method : "UNKNOWN";
        bw_flow_push(BW_FLOW_IN, short_method, (uint64_t)frame_bytes);

        if (strcmp(short_method, "sys.ping") != 0 && strcmp(short_method, "exec.run") != 0) {
            char summary[64] = "";
            char *param_path = json_get_string(req, "path");
            if (param_path) {
                snprintf(summary, sizeof(summary), "path=%.45s", param_path);
                free(param_path);
            }
            console_log_packet_rx(id, short_method, summary);
        }

        uint64_t t_start = GetTickCount64();
        DynBuf resp;
        db_init(&resp, 1024);
        dispatch_rpc(req, &resp, trigger_exit);
        uint64_t elapsed = GetTickCount64() - t_start;
        free(req);

        if (resp.len > 0) {
            if (strcmp(short_method, "sys.ping") != 0 && strcmp(short_method, "exec.run") != 0) {
                console_log_packet_tx(id, short_method, 0, elapsed, resp.len);
            }
            size_t b64_len = 0;
            char *b64out = (char *)b64_encode((const unsigned char *)resp.data, resp.len, &b64_len);
            bool ok = false;
            if (b64out) {
                char mhex[65];
                if (compute_hmac_sha256_hex(g_sesskey, 32, (unsigned char *)b64out, b64_len, mhex)) {
                    size_t env_cap = b64_len + 128;
                    char *env = (char *)malloc(env_cap);
                    if (env) {
                        snprintf(env, env_cap, "{\"v\":4,\"body_b64\":\"%s\",\"mac\":\"%s\"}", b64out, mhex);
                        ok = send_frame(s, env);
                        if (ok) bw_flow_push(BW_FLOW_OUT, short_method, (uint64_t)resp.len);
                        free(env);
                    }
                }
                free(b64out);
            }
            db_free(&resp);
            if (method) free(method);
            if (!ok) {
                break;
            }
        } else {
            db_free(&resp);
            if (method) free(method);
        }

        if (*trigger_exit) {
            agent_log(LOG_LVL_INFO, "Self-update requested shutdown; closing current session.");
            Sleep(200);
            break;
        }
    }
    g_have_sess = false;
    agent_log(LOG_LVL_INFO, CLR_YELLOW "[SESSION END]" CLR_RESET " Session closed. Reconnecting..."); SetConsoleTitleA("Bridge Agent [RECONNECTING...]");
}

/* =========================================================================
 * MODULE: WIN32 CRASH INTERCEPTION & FAULT SUPPRESSION (SWARM-170)
 * ========================================================================= */
typedef HRESULT (WINAPI *pfn_WerSetFlags)(DWORD);

static LONG WINAPI unhandled_exception_filter(EXCEPTION_POINTERS *ep) {
    DWORD code = ep ? ep->ExceptionRecord->ExceptionCode : 0;
    void *addr = ep ? ep->ExceptionRecord->ExceptionAddress : NULL;
    char crash_msg[256];
    snprintf(crash_msg, sizeof(crash_msg),
             "[CRASH INTERCEPTED] Exception 0x%08lX at address %p. Suppressed UI popup.",
             (unsigned long)code, addr);
    agent_log(LOG_LVL_ERROR, "%s", crash_msg);
    return EXCEPTION_EXECUTE_HANDLER;
}

static void init_crash_interception(void) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    HMODULE hWer = LoadLibraryA("wer.dll");
    if (hWer) {
        pfn_WerSetFlags pWerSetFlags = (pfn_WerSetFlags)GetProcAddress(hWer, "WerSetFlags");
        if (pWerSetFlags) {
            pWerSetFlags(1); /* WER_FAULT_REPORTING_NO_UI */
        }
        FreeLibrary(hWer);
    }

    SetUnhandledExceptionFilter(unhandled_exception_filter);
}

static bool valid_agent_id(const char *s) {
    if (!s || !s[0]) return false;
    size_t n = strlen(s);
    if (n > 32) return false;
    if (!isalnum((unsigned char)s[0])) return false;
    for (size_t i = 1; i < n; ++i) {
        char c = s[i];
        if (!isalnum((unsigned char)c) && c != '_' && c != '-') return false;
    }
    return true;
}

static void default_agent_id(char out[64]) {
    char host[64] = "";
    DWORD n = sizeof(host);
    if (GetComputerNameA(host, &n) && host[0]) {
        size_t j = 0;
        for (size_t i = 0; host[i] && j < 32; ++i) {
            char c = host[i];
            out[j++] = (isalnum((unsigned char)c) || c == '_' || c == '-') ? c : '-';
        }
        out[j] = '\0';
        if (valid_agent_id(out)) return;
    }
    snprintf(out, 64, "agent-%lu", (unsigned long)GetCurrentProcessId());
}

/* =========================================================================
 * GUI accessors (gui.c side calls these; network thread owns the state)
 * ========================================================================= */
void bw_snapshot(bw_snapshot_t *out) {
    uint64_t now = GetTickCount64();
    out->state = (int)InterlockedCompareExchange(&g_conn_state, BW_STATE_IDLE, BW_STATE_IDLE);
    strncpy(out->agent_id, g_agent_id, sizeof(out->agent_id) - 1);
    snprintf(out->master, sizeof(out->master), "%s:%u", g_master_host, (unsigned int)g_master_port);
    strncpy(out->version, BRIDGE_PROTOCOL_VERSION, sizeof(out->version) - 1);
    strncpy(out->arch, AGENT_ARCH, sizeof(out->arch) - 1);
    strncpy(out->os, "windows", sizeof(out->os) - 1);
    out->uptime_s = g_boot_tick ? (now - g_boot_tick) / 1000 : 0;
    out->session_uptime_s = (out->state == BW_STATE_CONNECTED && g_session_start_tick) ?
        (now - g_session_start_tick) / 1000 : 0;
    out->rpc_total = g_rpc_calls_total;
    out->packets_rx = g_packets_rx;
    out->packets_tx = g_packets_tx;
    out->bytes_rx = g_bytes_rx;
    out->bytes_tx = g_bytes_tx;
    out->reconnects = g_reconnect_count;
    out->cpu_pct = g_cpu_load_pct;
    out->ram_avail_mb = g_ram_avail_bytes / (1024 * 1024);
    out->ram_total_mb = g_ram_total_bytes / (1024 * 1024);
    EnterCriticalSection(&g_log_lock);
    strncpy(out->last_error, g_last_error, sizeof(out->last_error) - 1);
    LeaveCriticalSection(&g_log_lock);
}

int bw_drain_logs(uint64_t *last_seq, bw_log_cb cb, void *ctx) {
    if (!last_seq || !cb) return -1;
    EnterCriticalSection(&g_log_lock);
    size_t n = g_log_count, delivered = 0;
    for (size_t i = 0; i < n && delivered < 300; i++) {
        size_t idx = (g_log_head + LOG_RING_CAPACITY - n + i) % LOG_RING_CAPACITY;
        LogEntry *e = &g_log_ring[idx];
        if (e->seq > *last_seq) {
            uint64_t sq = e->seq;
            int lvl = (int)e->level;
            uint64_t ms = e->uptime_ms;
            char msg[LOG_MSG_MAX_LEN];
            strncpy(msg, e->msg, sizeof(msg) - 1);
            msg[sizeof(msg) - 1] = '\0';
            *last_seq = sq;
            LeaveCriticalSection(&g_log_lock);
            cb(sq, lvl, ms, msg, ctx);
            delivered++;
            EnterCriticalSection(&g_log_lock);
            if (n != g_log_count) break; /* ring moved under us; next tick resumes */
        }
    }
    LeaveCriticalSection(&g_log_lock);
    return 0;
}

void bw_force_reconnect(void) {
    SOCKET s = g_session_sock;
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
}

void bw_quit(void) {
    InterlockedExchange(&g_running, 0);
    bw_force_reconnect();
}

/* =========================================================================
 * MAIN ENTRYPOINT
 * ========================================================================= */
/* ---- zero-config sidecar: agent.provision next to the exe (or cwd) ----
 * key=value lines: host, port, token, agent-id. Loaded BEFORE env/CLI so
 * explicit flags always win. The token is never logged. */
static void provision__set(const char *key, const char *val) {
    if (strcmp(key, "host") == 0 && val[0]) {
        strncpy(g_master_host, val, sizeof(g_master_host) - 1);
        g_master_host[sizeof(g_master_host) - 1] = '\0';
    } else if (strcmp(key, "port") == 0 && val[0]) {
        int p = atoi(val);
        if (p > 0 && p < 65536) g_master_port = (uint16_t)p;
    } else if (strcmp(key, "token") == 0 && val[0]) {
        strncpy(g_psk_token, val, sizeof(g_psk_token) - 1);
        g_psk_token[sizeof(g_psk_token) - 1] = '\0';
    } else if ((strcmp(key, "agent-id") == 0 || strcmp(key, "agent_id") == 0) && val[0]) {
        strncpy(g_agent_id, val, sizeof(g_agent_id) - 1);
        g_agent_id[sizeof(g_agent_id) - 1] = '\0';
    }
}
static int provision__load_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '\0' || *s == '\n' || *s == '\r' || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *e = s + strlen(s);
        while (e > s && (e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
        char *v = eq + 1;
        while (*v == ' ' || *v == '\t') v++;
        e = v + strlen(v);
        while (e > v && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r')) *--e = '\0';
        provision__set(s, v);
    }
    fclose(f);
    return 1;
}
static void provision_load(void) {
    char path[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, path, sizeof(path));
    if (n > 0 && n < sizeof(path)) {
        char *sep = strrchr(path, '\\');
        if (sep) {
            *sep = '\0';
            char full[MAX_PATH + 32];
            snprintf(full, sizeof(full), "%s\\agent.provision", path);
            if (provision__load_file(full)) return;
        }
    }
    provision__load_file("agent.provision"); /* cwd fallback */
}

/* Mandatory admin: tools must run elevated (telemetry, priority guardian,
 * firewall helpers, self-update). Builds with the requireAdministrator manifest
 * get there via UAC automatically; this covers manifest-less builds (x86/ARM64)
 * by relaunching once through the runas verb. Returns 1 to continue here,
 * 0 when the elevated twin takes over, -1 when elevation failed/declined. */
static int ensure_elevated(int argc, char *argv[]) {
#ifdef AGENT_LEGACY_XP
    /* XP has no TokenElevation: Administrators-membership check instead. */
    if (legacy_is_admin()) return 1;
#else
    BOOL elevated = FALSE;
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION te; DWORD n = 0;
        if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &n)) elevated = te.TokenIsElevated;
        CloseHandle(tok);
    }
    if (elevated) return 1;
#endif
    char cmd[4096]; size_t o = 0;
    for (int i = 1; i < argc && o < sizeof(cmd) - 4; i++) {
        if (strchr(argv[i], '"')) continue; /* never pass a quote through the relaunch */
        o += (size_t)snprintf(cmd + o, sizeof(cmd) - o, "%s\"%s\"", i > 1 ? " " : "", argv[i]);
    }
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, sizeof(self));
    SHELLEXECUTEINFOA sei; ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = self;
    sei.lpParameters = cmd;
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExA(&sei)) return -1;
    return 0;
}

/* Console titles carry UTF-8 glyphs; the A-API would show mojibake. */
static void set_title_utf8(const char *utf8) {
    WCHAR w[256];
    if (MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w, 256) > 0) SetConsoleTitleW(w);
    else SetConsoleTitleA(utf8);
}

int main(int argc, char *argv[]) {
    int el = ensure_elevated(argc, argv);
    if (el == 0) return 0; /* elevated twin takes over */
    if (el < 0) {
        startup_fatal("agent.exe: administrator rights required (UAC declined or failed). Refusing to run degraded.");
        return 2;
    }
    provision_load(); /* zero-config sidecar first; CLI/env override below */
    /* Step 0: Parse flags */
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--selftest") == 0) {
            /* Side-by-side pre-flight test */
            { HANDLE so = GetStdHandle(STD_OUTPUT_HANDLE);
              if ((!so || so == INVALID_HANDLE_VALUE) && AttachConsole(ATTACH_PARENT_PROCESS)) {
                  freopen("CONOUT$", "w", stdout); freopen("CONOUT$", "w", stderr); } }
            WSADATA wsa;
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 101;
            char test_hex[65] = "";
            const char *dummy = "selftest";
            if (!compute_buffer_sha256((const unsigned char *)dummy, strlen(dummy), test_hex)) {
                WSACleanup();
                return 102;
            }
            /* RFC 4231 test case 1: HMAC-SHA256(key=0x0b*20, "Hi There") */
            unsigned char rfc_key[20];
            memset(rfc_key, 0x0b, sizeof(rfc_key));
            char hmac_hex[65] = "";
            if (!compute_hmac_sha256_hex(rfc_key, sizeof(rfc_key),
                                         (const unsigned char *)"Hi There", 8, hmac_hex)
                || strcmp(hmac_hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") != 0) {
                WSACleanup();
                printf("[SELFTEST] FAIL - HMAC-SHA256 vector mismatch: %s\n", hmac_hex);
                return 103;
            }
            WSACleanup();
            printf("[SELFTEST] OK - SHA256=%s HMAC=%s\n", test_hex, hmac_hex);
            return 0;
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            strncpy(g_master_host, argv[++i], sizeof(g_master_host) - 1);
            g_master_host[sizeof(g_master_host) - 1] = '\0';
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            g_master_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc) {
            strncpy(g_psk_token, argv[++i], sizeof(g_psk_token) - 1);
            g_psk_token[sizeof(g_psk_token) - 1] = '\0';
        } else if (strcmp(argv[i], "--agent-id") == 0 && i + 1 < argc) {
            strncpy(g_agent_id, argv[++i], sizeof(g_agent_id) - 1);
            g_agent_id[sizeof(g_agent_id) - 1] = '\0';
        } else if (strcmp(argv[i], "--headless") == 0 || strcmp(argv[i], "--no-gui") == 0) {
            g_headless = true;
        } else if (strcmp(argv[i], "--upgraded-from") == 0 && i + 1 < argc) {
            g_upgraded_from_pid = (DWORD)strtoul(argv[++i], NULL, 10);
        }
    }

    if (!g_psk_token[0]) {
        DWORD n = GetEnvironmentVariableA("BRIDGE_PSK", g_psk_token, sizeof(g_psk_token));
        if (n == 0 || n >= sizeof(g_psk_token)) g_psk_token[0] = '\0';
    }
    if (!g_psk_token[0]) {
        startup_fatal("agent.exe: PSK required (--token <psk>, BRIDGE_PSK env or agent.provision sidecar). Refusing to run unauthenticated.");
        return 2;
    }
    if (!g_agent_id[0]) {
        default_agent_id(g_agent_id);
    }
    if (!valid_agent_id(g_agent_id)) {
        startup_fatal("agent.exe: bad --agent-id (1-32 chars: A-Za-z0-9_-, starts alnum).");
        return 2;
    }

    init_crash_interception();

    // Console: headless keeps the classic visible console; GUI mode only reuses
    // an existing console and never allocates one (the window is the UI).
    // GUI-subsystem build: no console unless headless. Redirected std handles
    // (tests, services) are kept; otherwise reuse the launching terminal or allocate one.
    if (g_headless && GetConsoleWindow() == NULL) {
        HANDLE so = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!so || so == INVALID_HANDLE_VALUE) {
            if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
            freopen("CONIN$", "r", stdin);
        }
    }
    HWND hConsoleWnd = GetConsoleWindow();
    if (hConsoleWnd) {
        DWORD procs[4];
        bool private_console = GetConsoleProcessList(procs, 4) <= 1;
        if (g_headless) {
            ShowWindow(hConsoleWnd, SW_SHOW);
            SetForegroundWindow(hConsoleWnd);
        } else if (private_console) {
            /* console-subsystem build double-clicked: the window is the UI, keep the console hidden */
            HMENU sm = GetSystemMenu(hConsoleWnd, FALSE);
            if (sm) DeleteMenu(sm, SC_CLOSE, MF_BYCOMMAND);
            ShowWindow(hConsoleWnd, SW_HIDE);
        }
    }
    console_ui_init();
    SetConsoleTitleA("Bridge Agent [INITIALIZING]");

    /* Initialize synchronization primitives strictly before any thread or log */
    InitializeCriticalSection(&g_log_lock);
    InitializeCriticalSection(&g_flow_lock);
    InterlockedExchange(&g_flow_ready, 1);
    InitializeCriticalSection(&g_telemetry_lock);
    InitializeCriticalSection(&g_send_lock);
    init_telemetry_ring();
    init_gpu_telemetry();
    InitializeCriticalSection(&g_drift_sentinel_lock);
    InitializeCriticalSection(&g_kiosk_sentinel_lock);
    InitializeCriticalSection(&g_bin_session.lock);
    crc32_init();
    g_boot_tick = GetTickCount64();

    /* Status GUI (own thread). Falls back to headless when no desktop exists. */
    if (!g_headless) {
        if (gui_start()) {
            agent_log(LOG_LVL_INFO, "Status window started (use --headless to disable).");
        } else {
            g_headless = true;
            if (GetConsoleWindow()) ShowWindow(GetConsoleWindow(), SW_SHOW);
            agent_log(LOG_LVL_WARN, "No desktop available; running headless.");
        }
    }

    printf("\n" CLR_CYAN CLR_BOLD
           "  =========================================================================\n"
           "   BRIDGE WINDOWS AGENT v%s (" AGENT_ARCH " Native High-Speed Engine)\n"
           "  =========================================================================\n" CLR_RESET
           "  " CLR_DIM "Master Target:" CLR_RESET "  " CLR_WHITE "%s:%u" CLR_RESET "\n"
           "  " CLR_DIM "Process PID:" CLR_RESET "    " CLR_YELLOW "%lu" CLR_RESET "\n"
           "  " CLR_DIM "Execution:" CLR_RESET "      " CLR_GREEN "Real-Time I/O Echo + Fast Native Completion" CLR_RESET "\n"
           "  " CLR_DIM "Encoding:" CLR_RESET "       " CLR_GREEN "Automatic OEM/ANSI -> UTF-8 Normalization" CLR_RESET "\n"
           "  " CLR_DIM "Fast Search:" CLR_RESET "    " CLR_GREEN "Native Win32 fs.find Enabled" CLR_RESET "\n"
           "  " CLR_DIM "Telemetry:" CLR_RESET "      " CLR_GREEN "Live RAM & CPU Sampling Active" CLR_RESET "\n"
           CLR_CYAN "  -------------------------------------------------------------------------\n\n" CLR_RESET,
           BRIDGE_PROTOCOL_VERSION, g_master_host, (unsigned int)g_master_port, (unsigned long)GetCurrentProcessId());
    SetConsoleTitleA("Bridge Agent [CONNECTING...]");

    /* If launched after upgrade, delete old binary */
    if (g_upgraded_from_pid > 0) {
        Sleep(300);
        wchar_t self_w[MAX_PATH];
        GetModuleFileNameW(NULL, self_w, MAX_PATH);
        wchar_t old_w[MAX_PATH + 16];
        swprintf(old_w, MAX_PATH + 16, L"%s.old", self_w);
        DeleteFileW(old_w);
        agent_log(LOG_LVL_INFO, "Cleaned up old binary after successful upgrade.");
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        agent_log(LOG_LVL_ERROR, "WSAStartup failed: %lu", GetLastError());
        return 1;
    }

    /* Launch telemetry background thread (64 KB stack reservation - SWARM-198) */
    HANDLE hTelThread = CreateThread(NULL, 64 * 1024, TelemetryThread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (hTelThread) CloseHandle(hTelThread);

    /* Main reverse connection loop with exponential backoff */
    DWORD backoff_ms = 1000;
    while (InterlockedCompareExchange(&g_running, 1, 1) == 1) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            Sleep(backoff_ms);
            continue;
        }

        struct sockaddr_in sin;
        ZeroMemory(&sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(g_master_port);

        struct hostent *he = gethostbyname(g_master_host);
        if (he && he->h_addr_list && he->h_addr_list[0]) {
            memcpy(&sin.sin_addr, he->h_addr_list[0], he->h_length);
        } else {
            sin.sin_addr.s_addr = inet_addr(g_master_host);
        }

        if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) == 0) {
            backoff_ms = 1000;
            g_session_sock = s;
            InterlockedExchange(&g_conn_state, BW_STATE_CONNECTING);
            bool trigger_exit = false;
            run_reverse_session(s, &trigger_exit);
            g_session_sock = INVALID_SOCKET;
            if (InterlockedCompareExchange(&g_conn_state, BW_STATE_IDLE, BW_STATE_IDLE) == BW_STATE_CONNECTED)
                bw_note_error("connection lost");
            InterlockedExchange(&g_conn_state, BW_STATE_IDLE);
            g_reconnect_count++;
            closesocket(s);
            if (trigger_exit) {
                break;
            }
        } else {
            closesocket(s);
            bw_note_error("master unreachable");
            agent_log(LOG_LVL_DEBUG, "Connection attempt failed; retrying in %lums...", (unsigned long)backoff_ms);
            Sleep(backoff_ms);
            backoff_ms = (backoff_ms < 16000) ? (backoff_ms * 2) : 16000;
        }
    }

    InterlockedExchange(&g_running, 0);
    if (!g_headless) gui_stop();
    cleanup_gpu_telemetry();
    cleanup_telemetry_ring();
    DeleteCriticalSection(&g_drift_sentinel_lock);
    DeleteCriticalSection(&g_kiosk_sentinel_lock);
    EnterCriticalSection(&g_bin_session.lock);
    bin_session_abort_locked();
    LeaveCriticalSection(&g_bin_session.lock);
    DeleteCriticalSection(&g_bin_session.lock);
    WSACleanup();
    DeleteCriticalSection(&g_log_lock);
    DeleteCriticalSection(&g_telemetry_lock);
    DeleteCriticalSection(&g_send_lock);
    console_ui_shutdown();

    return 0;
}
