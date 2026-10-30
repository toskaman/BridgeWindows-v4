/*
 * BridgeLinux - Linux Remote Agent v4.0.0 (x86_64 + aarch64)
 * Single static ELF, POSIX + embedded SHA-256 (no OpenSSL needed).
 * Speaks protocol v4: mutual HMAC auth + session-MAC envelopes (no v3 compat).
 *
 * Build (from Windows, zig toolchain):
 *   zig cc -target x86_64-linux-musl -O2 -s agent_linux.c -o agent-linux-x64 -lpthread -lm
 *   zig cc -target aarch64-linux-musl -O2 -s agent_linux.c -o agent-linux-arm64 -lpthread -lm
 * Native gcc build works too (same flags, no extra libs).
 *
 * Usage:
 *   ./agent-linux-x64 --host <MASTER_IP> --port 9876 --agent-id <NAME>
 *   (PSK via --token <psk> or BRIDGE_PSK env; --agent-id defaults to hostname)
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "protocol.h"
#include "orb_hud.h"
#include <termios.h>

/* =========================================================================
 * PLATFORM COMPAT SHIMS
 * ========================================================================= */
#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

static inline int strcasecmp_compat(const char *a, const char *b) {
    return strcasecmp(a, b);
}
__attribute__((unused)) static inline int strncasecmp_compat(const char *a, const char *b, size_t n) {
    return strncasecmp(a, b, n);
}
#define _stricmp  strcasecmp_compat
#define _strnicmp strncasecmp_compat

/* =========================================================================
 * ANSI COLORS
 * ========================================================================= */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_DIM     "\033[90m"
#define CLR_RED     "\033[91m"
#define CLR_GREEN   "\033[92m"
#define CLR_YELLOW  "\033[93m"
#define CLR_BLUE    "\033[94m"
#define CLR_MAGENTA "\033[95m"
#define CLR_CYAN    "\033[96m"
#define CLR_WHITE   "\033[97m"

/* =========================================================================
 * GLOBAL STATE & SYNCHRONIZATION
 * ========================================================================= */
#if defined(__aarch64__)
#define AGENT_ARCH "arm64"
#elif defined(__x86_64__)
#define AGENT_ARCH "x64"
#else
#define AGENT_ARCH "x86"
#endif
#define AGENT_OS "linux"

static char g_master_host[256] = "127.0.0.1";
static uint16_t g_master_port = DEFAULT_BRIDGE_PORT;
static char g_psk_token[256] = "";  /* required: --token or BRIDGE_PSK env; never a compiled default */
static char g_agent_id[64] = "";    /* required: --agent-id or sanitized hostname */
static unsigned char g_sesskey[32]; /* per-connection session key, derived at handshake */
static bool g_have_sess = false;
static volatile int g_running = 1;
static pid_t g_upgraded_from_pid = 0;
static uint64_t g_rpc_calls_total = 0;
static volatile int g_link_connected = 0;   /* orb HUD: 1 while a master socket is open */
static orb_t g_orb;                         /* orb HUD presence model */
static void hud_flow_push(int dir, const char *label, uint64_t bytes);   /* live flows (HUD) */

static pthread_mutex_t g_log_lock      = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_telemetry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_send_lock     = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_console_lock  = PTHREAD_MUTEX_INITIALIZER;

/* Network counters */
static uint64_t g_packets_rx = 0;
static uint64_t g_packets_tx = 0;
static uint64_t g_bytes_rx   = 0;
static uint64_t g_bytes_tx   = 0;
static bool g_vt_enabled = true;
static uint64_t g_ui_start_tick = 0;

/* Telemetry (updated by TelemetryThread every 1 s) */
static double   g_cpu_load_pct         = 0.0;
static uint64_t g_ram_avail_bytes      = 0;
static uint64_t g_ram_total_bytes      = 0;
static uint64_t g_telemetry_last_tick  = 0;
static volatile int g_cmd_executing    = 0;

/* =========================================================================
 * TIME HELPERS
 * ========================================================================= */
static uint64_t get_tick_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static void sleep_ms(unsigned int ms) {
    struct timespec ts = { (time_t)(ms / 1000), (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* =========================================================================
 * CIRCULAR LOG RING
 * ========================================================================= */
typedef enum {
    LOG_LVL_DEBUG = 0,
    LOG_LVL_INFO  = 1,
    LOG_LVL_WARN  = 2,
    LOG_LVL_ERROR = 3
} LogLevel;

typedef struct {
    uint64_t seq;
    uint64_t uptime_ms;
    int32_t  level;
    char     msg[LOG_MSG_MAX_LEN];
} LogEntry;

static LogEntry g_log_ring[LOG_RING_CAPACITY];
static size_t   g_log_head  = 0;
static size_t   g_log_count = 0;
static uint64_t g_log_seq   = 0;

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
    if (_stricmp(s, "WARN")  == 0) return LOG_LVL_WARN;
    if (_stricmp(s, "INFO")  == 0) return LOG_LVL_INFO;
    return LOG_LVL_DEBUG;
}

static void agent_log(LogLevel lvl, const char *fmt, ...) {
    char buf[LOG_MSG_MAX_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = '\0';

    uint64_t now = get_tick_ms();

    pthread_mutex_lock(&g_log_lock);
    uint64_t seq = ++g_log_seq;
    LogEntry *entry = &g_log_ring[g_log_head];
    entry->seq       = seq;
    entry->uptime_ms = now;
    entry->level     = (int32_t)lvl;
    strncpy(entry->msg, buf, sizeof(entry->msg) - 1);
    entry->msg[sizeof(entry->msg) - 1] = '\0';
    g_log_head = (g_log_head + 1) % LOG_RING_CAPACITY;
    if (g_log_count < LOG_RING_CAPACITY) g_log_count++;
    pthread_mutex_unlock(&g_log_lock);

    const char *lvl_clr = CLR_WHITE;
    switch (lvl) {
        case LOG_LVL_DEBUG: lvl_clr = CLR_DIM; break;
        case LOG_LVL_INFO:  lvl_clr = CLR_CYAN; break;
        case LOG_LVL_WARN:  lvl_clr = CLR_YELLOW; break;
        case LOG_LVL_ERROR: lvl_clr = CLR_RED CLR_BOLD; break;
    }

    /* Local wall-clock for console */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    char tmbuf[16];
    strftime(tmbuf, sizeof(tmbuf), "%H:%M:%S", tm);

    pthread_mutex_lock(&g_console_lock);
    printf("%s.%03d %s[%-5s]%s %s[+%6llums]%s %s\n",
           tmbuf, (int)(ts.tv_nsec / 1000000),
           lvl_clr, log_level_str(lvl), CLR_RESET,
           CLR_DIM, (unsigned long long)now, CLR_RESET, buf);
    fflush(stdout);
    pthread_mutex_unlock(&g_console_lock);
}

/* =========================================================================
 * DYNAMIC BUFFER
 * ========================================================================= */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} DynBuf;

static void db_init(DynBuf *b, size_t init_cap) {
    if (init_cap < 128) init_cap = 128;
    b->data = (char *)malloc(init_cap);
    b->len  = 0;
    b->cap  = init_cap;
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
    b->cap  = new_cap;
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
    if (b->data) { free(b->data); b->data = NULL; }
    b->len = 0;
    b->cap = 0;
}

/* =========================================================================
 * SHA-256 (Self-contained RFC 6234 / FIPS 180-2, Zero External Dependencies)
 * ========================================================================= */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} SHA256_CTX;

#define SHA256_ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define SHA256_CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x) (SHA256_ROTRIGHT(x,2) ^ SHA256_ROTRIGHT(x,13) ^ SHA256_ROTRIGHT(x,22))
#define SHA256_EP1(x) (SHA256_ROTRIGHT(x,6) ^ SHA256_ROTRIGHT(x,11) ^ SHA256_ROTRIGHT(x,25))
#define SHA256_SIG0(x) (SHA256_ROTRIGHT(x,7) ^ SHA256_ROTRIGHT(x,18) ^ ((x) >> 3))
#define SHA256_SIG1(x) (SHA256_ROTRIGHT(x,17) ^ SHA256_ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SHA256_SIG1(m[i - 2]) + m[i - 7] + SHA256_SIG0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + SHA256_EP1(e) + SHA256_CH(e,f,g) + sha256_k[i] + m[i];
        t2 = SHA256_EP0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->buffer[(ctx->count) % 64] = data[i];
        ctx->count++;
        if ((ctx->count % 64) == 0)
            sha256_transform(ctx, ctx->buffer);
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    uint32_t i = (uint32_t)(ctx->count % 64);
    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    } else {
        while (i < 56) ctx->buffer[i++] = 0x00;
    }
    uint64_t bits = ctx->count * 8;
    for (int k = 7; k >= 0; --k)
        ctx->buffer[56 + (7 - k)] = (uint8_t)(bits >> (k * 8));
    sha256_transform(ctx, ctx->buffer);
    for (int k = 0; k < 8; ++k) {
        hash[k * 4]     = (uint8_t)(ctx->state[k] >> 24);
        hash[k * 4 + 1] = (uint8_t)(ctx->state[k] >> 16);
        hash[k * 4 + 2] = (uint8_t)(ctx->state[k] >> 8);
        hash[k * 4 + 3] = (uint8_t)(ctx->state[k]);
    }
}

static bool compute_buffer_sha256(const unsigned char *data, size_t len, char *out_hex) {
    uint8_t hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)data, len);
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; ++i)
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    out_hex[64] = '\0';
    return true;
}

static bool compute_file_sha256(const char *path, char *out_hex, uint64_t *out_size, int *out_err) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { if (out_err) *out_err = errno; return false; }

    struct stat st;
    if (fstat(fd, &st) == 0 && out_size)
        *out_size = (uint64_t)st.st_size;

    SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t chunk[65536];
    ssize_t nr;
    while ((nr = read(fd, chunk, sizeof(chunk))) > 0)
        sha256_update(&ctx, chunk, (size_t)nr);

    close(fd);

    uint8_t hash[32];
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; ++i)
        snprintf(out_hex + (i * 2), 3, "%02x", hash[i]);
    out_hex[64] = '\0';
    return true;
}

/* HMAC-SHA256 over the embedded core. Returns hex in out_hex (65 bytes). */
static bool compute_hmac_sha256_hex(const unsigned char *key, size_t key_len,
                                    const unsigned char *data, size_t data_len,
                                    char *out_hex) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    SHA256_CTX ctx;
    uint8_t inner[32], outer[32];
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner);
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, outer);
    for (int i = 0; i < 32; ++i)
        snprintf(out_hex + (i * 2), 3, "%02x", outer[i]);
    out_hex[64] = '\0';
    return true;
}

static void sha256_raw(const unsigned char *data, size_t len, unsigned char out[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* 16 random bytes as 32 hex chars. /dev/urandom with a pid/time fallback. */
static bool gen_hex_nonce(char out[33]) {
    unsigned char raw[16];
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t got = (fd >= 0) ? read(fd, raw, sizeof(raw)) : -1;
    if (fd >= 0) close(fd);
    if (got != (ssize_t)sizeof(raw)) {
        uint64_t seed = (uint64_t)get_tick_ms() * 1000003ULL ^ ((uint64_t)getpid() << 32);
        for (int i = 0; i < 16; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            raw[i] = (unsigned char)(seed >> 33);
        }
    }
    for (int i = 0; i < 16; ++i)
        snprintf(out + (i * 2), 3, "%02x", raw[i]);
    out[32] = '\0';
    return true;
}

static bool valid_agent_id(const char *s) {
    if (!s || !s[0] || strlen(s) > 32 || !isalnum((unsigned char)s[0])) return false;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-') return false;
    return true;
}

static void default_agent_id(char out[64]) {
    char host[64] = "";
    if (gethostname(host, sizeof(host)) == 0 && host[0]) {
        size_t j = 0;
        for (size_t i = 0; host[i] && j < 32; ++i) {
            char c = host[i];
            out[j++] = (isalnum((unsigned char)c) || c == '_' || c == '-') ? c : '-';
        }
        out[j] = '\0';
        if (valid_agent_id(out)) return;
    }
    snprintf(out, 64, "agent-%lu", (unsigned long)getpid());
}

/* =========================================================================
 * BASE64
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
        out[j++] = b64_tbl[(t >>  6) & 0x3F];
        out[j++] = b64_tbl[ t        & 0x3F];
    }
    size_t mod = len % 3;
    if (mod == 1) { out[olen-1] = '='; out[olen-2] = '='; }
    else if (mod == 2) { out[olen-1] = '='; }
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

/* =========================================================================
 * JSON HELPERS
 * ========================================================================= */
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
                case '/':  db_append_char(&out, '/');  break;
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

static void build_error_response(DynBuf *resp, int64_t id, int code, const char *msg, int linux_err) {
    if (code == RPC_ERR_AUTH_FAILED || code == RPC_ERR_INTERNAL || code == RPC_ERR_UPDATE_FAILED) {
        agent_log(LOG_LVL_WARN, "RPC error %d: %s (errno=%d)", code, msg, linux_err);
    } else {
        agent_log(LOG_LVL_DEBUG, "RPC notice %d: %s (errno=%d)", code, msg, linux_err);
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"error\":{\"code\":");
    db_append_int64(resp, code);
    db_append_str(resp, ",\"message\":\"");
    db_append_json_escaped(resp, msg);
    db_append_str(resp, "\",\"linux_errno\":");
    db_append_int64(resp, linux_err);
    db_append_str(resp, "}}");
}

static const char *strcasestr_custom(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return haystack;
    size_t nlen = strlen(needle);
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            if (strncasecmp(haystack, needle, nlen) == 0) return haystack;
        }
    }
    return NULL;
}

/* =========================================================================
 * LINUX TELEMETRY: CPU via /proc/stat
 * ========================================================================= */
typedef struct {
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
} CpuStat;

static bool read_cpu_stat(CpuStat *out) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return false;
    int r = fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                   (unsigned long long *)&out->user, (unsigned long long *)&out->nice,
                   (unsigned long long *)&out->system, (unsigned long long *)&out->idle,
                   (unsigned long long *)&out->iowait, (unsigned long long *)&out->irq,
                   (unsigned long long *)&out->softirq, (unsigned long long *)&out->steal);
    fclose(f);
    return (r >= 4);
}

static double compute_cpu_pct(const CpuStat *prev, const CpuStat *cur) {
    uint64_t prev_idle = prev->idle + prev->iowait;
    uint64_t cur_idle  = cur->idle  + cur->iowait;
    uint64_t prev_tot  = prev->user + prev->nice + prev->system + prev->idle +
                         prev->iowait + prev->irq + prev->softirq + prev->steal;
    uint64_t cur_tot   = cur->user  + cur->nice  + cur->system  + cur->idle  +
                         cur->iowait  + cur->irq  + cur->softirq  + cur->steal;
    uint64_t d_idle = cur_idle - prev_idle;
    uint64_t d_tot  = cur_tot  - prev_tot;
    if (d_tot == 0) return 0.0;
    return 100.0 * (double)(d_tot - d_idle) / (double)d_tot;
}

/* =========================================================================
 * LINUX TELEMETRY: RAM via /proc/meminfo
 * ========================================================================= */
static bool read_mem_info(uint64_t *total, uint64_t *avail) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return false;
    char line[256];
    uint64_t mem_total = 0, mem_avail = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long v = 0;
        if (sscanf(line, "MemTotal: %llu kB", &v) == 1)  mem_total = v * 1024ULL;
        if (sscanf(line, "MemAvailable: %llu kB", &v) == 1) mem_avail = v * 1024ULL;
    }
    fclose(f);
    if (total)  *total  = mem_total;
    if (avail)  *avail  = mem_avail;
    return (mem_total > 0);
}

/* =========================================================================
 * LINUX GPU TELEMETRY: AMD via /sys/class/drm or hwmon
 * ========================================================================= */
typedef struct {
    float temp_c;
    int   engine_clock_mhz;
    int   memory_clock_mhz;
    int   activity_pct;
    int   vddc_mv;
} GpuTelemetry;

static char g_gpu_hwmon_path[256] = "";
static bool g_gpu_available = false;

static void init_gpu_telemetry(void) {
    /* Look for amdgpu hwmon: /sys/class/drm/card0/device/hwmon/hwmon*/
    DIR *d = opendir("/sys/class/drm");
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "card", 4) != 0) continue;
        char hwmon_base[512];
        snprintf(hwmon_base, sizeof(hwmon_base), "/sys/class/drm/%s/device/hwmon", e->d_name);
        DIR *d2 = opendir(hwmon_base);
        if (!d2) continue;
        struct dirent *e2;
        while ((e2 = readdir(d2)) != NULL) {
            if (strncmp(e2->d_name, "hwmon", 5) != 0) continue;
            char test[512];
            snprintf(test, sizeof(test), "%s/%s/temp1_input", hwmon_base, e2->d_name);
            if (access(test, R_OK) == 0) {
                snprintf(g_gpu_hwmon_path, sizeof(g_gpu_hwmon_path), "%s/%s", hwmon_base, e2->d_name);
                g_gpu_available = true;
            }
        }
        closedir(d2);
        if (g_gpu_available) break;
    }
    closedir(d);
    if (g_gpu_available)
        agent_log(LOG_LVL_INFO, "[GPU] AMD hwmon found: %s", g_gpu_hwmon_path);
    else
        agent_log(LOG_LVL_INFO, "[GPU] No AMD hwmon found (GPU telemetry N/A)");
}

static int read_sysfs_int(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int v = -1;
    fscanf(f, "%d", &v);
    fclose(f);
    return v;
}

static void query_gpu_telemetry(GpuTelemetry *out) {
    if (!out) return;
    out->temp_c          = -1.0f;
    out->engine_clock_mhz = -1;
    out->memory_clock_mhz = -1;
    out->activity_pct    = -1;
    out->vddc_mv         = -1;

    if (!g_gpu_available || !g_gpu_hwmon_path[0]) return;

    char p[512];
    /* Temperature: millidegrees */
    snprintf(p, sizeof(p), "%s/temp1_input", g_gpu_hwmon_path);
    int t = read_sysfs_int(p);
    if (t > 0) out->temp_c = (float)t / 1000.0f;

    /* Core clock MHz */
    snprintf(p, sizeof(p), "%s/../pp_dpm_sclk", g_gpu_hwmon_path);
    FILE *f = fopen(p, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f)) {
            /* Marked with '*' = current */
            if (strchr(line, '*')) {
                int mhz = 0;
                sscanf(line, "%*d: %dMhz *", &mhz);
                if (mhz > 0) out->engine_clock_mhz = mhz;
            }
        }
        fclose(f);
    }

    /* GPU activity */
    snprintf(p, sizeof(p), "%s/../gpu_busy_percent", g_gpu_hwmon_path);
    int act = read_sysfs_int(p);
    if (act >= 0) out->activity_pct = act;

    /* Voltage mV */
    snprintf(p, sizeof(p), "%s/in0_input", g_gpu_hwmon_path);
    int v = read_sysfs_int(p);
    if (v > 0) out->vddc_mv = v;
}

static float query_gpu_temperature(void) {
    GpuTelemetry gt;
    query_gpu_telemetry(&gt);
    return gt.temp_c;
}

static void cleanup_gpu_telemetry(void) {
    g_gpu_available = false;
}

/* =========================================================================
 * TELEMETRY RING BUFFER (60 samples, 1-hour rolling)
 * ========================================================================= */
#define TELEMETRY_HISTORY_SAMPLES 60

typedef struct {
    uint64_t timestamp_sec;
    uint32_t uptime_sec;
    float    cpu_pct;
    uint32_t ram_avail_mb;
    float    gpu_temp_c;
    int16_t  gpu_engine_mhz;
    int8_t   gpu_activity_pct;
} TelemetrySample;

typedef struct {
    TelemetrySample samples[TELEMETRY_HISTORY_SAMPLES];
    uint32_t head;
    uint32_t count;
    uint64_t total_recorded;
} TelemetryRingBuffer;

static TelemetryRingBuffer  g_telemetry_ring_buf;
static TelemetryRingBuffer *g_telemetry_ring = &g_telemetry_ring_buf;
static pthread_mutex_t      g_telemetry_ring_lock = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * DRIFT SENTINEL
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
static pthread_mutex_t    g_drift_sentinel_lock = PTHREAD_MUTEX_INITIALIZER;

static void evaluate_drift_sentinel(void) {
    pthread_mutex_lock(&g_telemetry_ring_lock);
    uint32_t total = g_telemetry_ring->count;
    uint32_t head  = g_telemetry_ring->head;
    if (total < 5) { pthread_mutex_unlock(&g_telemetry_ring_lock); return; }

    uint32_t n = (total > 30) ? 30 : total;
    uint32_t start_idx = (head + TELEMETRY_HISTORY_SAMPLES - n) % TELEMETRY_HISTORY_SAMPLES;

    double sum_x = 0.0, sum_y = 0.0, sum_xx = 0.0, sum_xy = 0.0, sum_yy = 0.0;
    int decreasing_steps = 0;
    float latest_ram = 0.0f, latest_gpu = -1.0f;
    int hot_samples = 0, cold_samples = 0;
    uint32_t thermal_window = (n >= 3) ? 3 : n;

    for (uint32_t i = 0; i < n; ++i) {
        uint32_t idx = (start_idx + i) % TELEMETRY_HISTORY_SAMPLES;
        TelemetrySample *s = &g_telemetry_ring->samples[idx];
        double x = (double)i, y = (double)s->ram_avail_mb;
        sum_x += x; sum_y += y; sum_xx += x * x; sum_xy += x * y; sum_yy += y * y;
        if (i > 0) {
            uint32_t prev = (start_idx + i - 1) % TELEMETRY_HISTORY_SAMPLES;
            if (s->ram_avail_mb <= g_telemetry_ring->samples[prev].ram_avail_mb) decreasing_steps++;
        }
        if (i == n - 1) { latest_ram = (float)s->ram_avail_mb; latest_gpu = s->gpu_temp_c; }
        if (i >= n - thermal_window) {
            if (s->gpu_temp_c >= 68.0f) hot_samples++;
            if (s->gpu_temp_c > 0.0f && s->gpu_temp_c <= 62.0f) cold_samples++;
        }
    }
    pthread_mutex_unlock(&g_telemetry_ring_lock);

    double dn = (double)n;
    double ss_xx = sum_xx - (sum_x * sum_x) / dn;
    double ss_xy = sum_xy - (sum_x * sum_y) / dn;
    double ss_yy = sum_yy - (sum_y * sum_y) / dn;
    double slope = (ss_xx > 1e-9) ? (ss_xy / ss_xx) : 0.0;
    double r2 = (ss_xx > 1e-9 && ss_yy > 1e-9) ? (ss_xy * ss_xy) / (ss_xx * ss_yy) : 0.0;
    float mono = (n > 1) ? ((float)decreasing_steps / (float)(n - 1)) : 0.0f;

    bool ram_drift = (latest_ram <= 45.0f && slope < -0.15 && r2 >= 0.50 && mono >= 0.65f);
    bool should_trim = false, should_throttle = false, should_unthrottle = false;
    uint64_t now_sec = (uint64_t)time(NULL);

    pthread_mutex_lock(&g_drift_sentinel_lock);
    g_drift_sentinel.samples_evaluated  = n;
    g_drift_sentinel.ram_slope_mb_min   = (float)slope;
    g_drift_sentinel.ram_r2             = (float)r2;
    g_drift_sentinel.ram_monotonicity   = mono;
    g_drift_sentinel.ram_drift_detected = ram_drift;
    g_drift_sentinel.gpu_temp_c         = latest_gpu;

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
    pthread_mutex_unlock(&g_drift_sentinel_lock);

    if (should_trim) {
        agent_log(LOG_LVL_WARN, "[SENTINEL] Memory drift detected (RAM: %.0fMB, slope: %.2f, R2: %.2f). Dropping caches...",
                  latest_ram, slope, r2);
        /* Linux: drop page cache via /proc/sys/vm/drop_caches (requires root) */
        int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
        if (fd >= 0) { write(fd, "1\n", 2); close(fd); }
    }
    if (should_throttle) {
        agent_log(LOG_LVL_WARN, "[SENTINEL] Thermal drift (GPU %.1fC >= 68C). Setting CPU governor to powersave...", latest_gpu);
        system("for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo powersave > $f 2>/dev/null; done");
    } else if (should_unthrottle) {
        agent_log(LOG_LVL_INFO, "[SENTINEL] Thermal normalized (GPU %.1fC <= 62C). Restoring ondemand governor...", latest_gpu);
        system("for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo ondemand > $f 2>/dev/null; done");
    }
}

/* =========================================================================
 * KIOSK SENTINEL (Linux: process existence check via /proc)
 * ========================================================================= */
typedef struct {
    bool     enabled;
    bool     is_running;
    bool     is_hung;
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
    .enabled               = true,
    .is_running            = false,
    .is_hung               = false,
    .auto_relaunch_on_crash = false,
    .restart_count_total   = 0,
    .restarts_in_window    = 0,
    .window_start_sec      = 0,
    .last_restart_sec      = 0,
    .backoff_sec           = 10,
    .circuit_breaker_tripped = false,
    .target_name           = "chromium",
    .last_action           = "INITIALIZED_MONITORING"
};
static pthread_mutex_t g_kiosk_sentinel_lock = PTHREAD_MUTEX_INITIALIZER;

/* Check if process name is running by scanning /proc/<pid>/comm */
static bool linux_is_process_running(const char *name) {
    DIR *d = opendir("/proc");
    if (!d) return false;
    bool found = false;
    struct dirent *e;
    while (!found && (e = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", e->d_name);
        FILE *f = fopen(comm_path, "r");
        if (!f) continue;
        char comm[64] = "";
        if (fgets(comm, sizeof(comm), f)) {
            size_t l = strlen(comm);
            while (l > 0 && (comm[l-1] == '\n' || comm[l-1] == '\r')) comm[--l] = '\0';
            if (_stricmp(comm, name) == 0) found = true;
        }
        fclose(f);
    }
    closedir(d);
    return found;
}

static void evaluate_kiosk_sentinel(void) {
    pthread_mutex_lock(&g_kiosk_sentinel_lock);
    if (!g_kiosk_sentinel.enabled) { pthread_mutex_unlock(&g_kiosk_sentinel_lock); return; }
    char target[64];
    strncpy(target, g_kiosk_sentinel.target_name, sizeof(target) - 1);
    pthread_mutex_unlock(&g_kiosk_sentinel_lock);

    bool found = linux_is_process_running(target);
    uint64_t now_sec = (uint64_t)time(NULL);
    static int s_consecutive_not_running = 0;

    pthread_mutex_lock(&g_kiosk_sentinel_lock);
    g_kiosk_sentinel.is_running = found;
    g_kiosk_sentinel.is_hung    = false; /* Linux: no IsHungAppWindow equiv, skip */

    if (g_kiosk_sentinel.window_start_sec == 0 ||
        (now_sec - g_kiosk_sentinel.window_start_sec > 3600)) {
        g_kiosk_sentinel.window_start_sec   = now_sec;
        g_kiosk_sentinel.restarts_in_window = 0;
        g_kiosk_sentinel.circuit_breaker_tripped = false;
    }
    if (g_kiosk_sentinel.backoff_sec > 10 &&
        (now_sec - g_kiosk_sentinel.last_restart_sec > 1800)) {
        g_kiosk_sentinel.backoff_sec = 10;
        g_kiosk_sentinel.circuit_breaker_tripped = false;
    }

    bool should_restart = false;
    if (found) {
        s_consecutive_not_running = 0;
    } else {
        s_consecutive_not_running++;
        if (g_kiosk_sentinel.auto_relaunch_on_crash && s_consecutive_not_running >= 3) {
            if (g_kiosk_sentinel.restarts_in_window >= 3) {
                g_kiosk_sentinel.circuit_breaker_tripped = true;
            } else if (now_sec - g_kiosk_sentinel.last_restart_sec >= g_kiosk_sentinel.backoff_sec) {
                should_restart = true;
                g_kiosk_sentinel.restart_count_total++;
                g_kiosk_sentinel.restarts_in_window++;
                g_kiosk_sentinel.last_restart_sec = now_sec;
                if (g_kiosk_sentinel.backoff_sec < 300) g_kiosk_sentinel.backoff_sec *= 2;
                s_consecutive_not_running = 0;
                snprintf(g_kiosk_sentinel.last_action, sizeof(g_kiosk_sentinel.last_action),
                         "RESTART_TRIGGERED (attempt %u)", g_kiosk_sentinel.restart_count_total);
            }
        }
    }
    pthread_mutex_unlock(&g_kiosk_sentinel_lock);

    if (should_restart) {
        agent_log(LOG_LVL_WARN, "[KIOSK-SENTINEL] %s not running. Auto-restart triggered.", target);
        /* User can configure the relaunch command via kiosk_configure */
        /* Default: try to re-exec the target by name */
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "nohup %s &", target);
        system(cmd);
    }
}

/* =========================================================================
 * HUD: VT100 terminal header (2 lines)
 * ========================================================================= */
static void hud_render(void) __attribute__((unused));
static void hud_render(void) {
    if (!g_vt_enabled) return;

    uint64_t ram_free_mb = g_ram_avail_bytes / (1024 * 1024);
    uint64_t ram_tot_mb  = g_ram_total_bytes / (1024 * 1024);
    const char *cpu_clr  = CLR_GREEN;
    if (g_cpu_load_pct > 80.0) cpu_clr = CLR_RED CLR_BOLD;
    else if (g_cpu_load_pct > 50.0) cpu_clr = CLR_YELLOW;

    const char *ram_clr = CLR_GREEN;
    if (ram_free_mb < 50) ram_clr = CLR_RED CLR_BOLD;
    else if (ram_free_mb < 75) ram_clr = CLR_YELLOW;

    float gpu_t = query_gpu_temperature();
    char gpu_str[32];
    const char *gpu_clr = CLR_GREEN;
    if (gpu_t < 0.0f) { snprintf(gpu_str, sizeof(gpu_str), "N/A"); gpu_clr = CLR_DIM; }
    else {
        snprintf(gpu_str, sizeof(gpu_str), "%.1f C", gpu_t);
        if (gpu_t >= 72.0f) gpu_clr = CLR_RED CLR_BOLD;
        else if (gpu_t >= 65.0f) gpu_clr = CLR_YELLOW;
    }

    pthread_mutex_lock(&g_kiosk_sentinel_lock);
    KioskSentinelState ks = g_kiosk_sentinel;
    pthread_mutex_unlock(&g_kiosk_sentinel_lock);

    const char *kiosk_status;
    if (!ks.enabled)               kiosk_status = CLR_DIM "OFF" CLR_RESET;
    else if (ks.circuit_breaker_tripped) kiosk_status = CLR_RED CLR_BOLD "BREAKER" CLR_RESET;
    else if (ks.is_running)        kiosk_status = CLR_GREEN CLR_BOLD "HEALTHY" CLR_RESET;
    else                           kiosk_status = CLR_YELLOW "STOPPED" CLR_RESET;

    uint64_t up_sec = (get_tick_ms() - g_ui_start_tick) / 1000ULL;
    char up_str[32];
    unsigned int h = (unsigned int)(up_sec / 3600);
    unsigned int m = (unsigned int)((up_sec % 3600) / 60);
    unsigned int s = (unsigned int)(up_sec % 60);
    if (h > 0) snprintf(up_str, sizeof(up_str), "%uh%02um%02us", h, m, s);
    else        snprintf(up_str, sizeof(up_str), "%02um%02us", m, s);

    pthread_mutex_lock(&g_console_lock);

    /* Disable auto-wrap (DECAWM off) so HUD lines never spill onto the next
     * row and trigger a scroll that would push window decorations off-screen.
     * Each line is terminated with \033[K (erase to EOL) and the cursor is
     * repositioned via absolute VT100 sequences instead of \n. */
    printf("\033[?7l");

    /* Line 1 */
    printf("\033[1;1H\033[48;5;236m" CLR_BOLD CLR_CYAN " [BRIDGE-LINUX v" BRIDGE_PROTOCOL_VERSION "] " CLR_RESET
           "\033[48;5;236m" CLR_DIM "PID:" CLR_RESET "\033[48;5;236m" CLR_YELLOW "%-6d " CLR_RESET
           "\033[48;5;236m" CLR_DIM "CPU:" CLR_RESET "\033[48;5;236m" "%s%5.1f%% " CLR_RESET
           "\033[48;5;236m" CLR_DIM "RAM:" CLR_RESET "\033[48;5;236m" "%s%lluMB" CLR_DIM "/%lluMB " CLR_RESET
           "\033[48;5;236m" CLR_DIM "GPU:" CLR_RESET "\033[48;5;236m" "%s%-8s " CLR_RESET
           "\033[48;5;236m" CLR_DIM "HOST:" CLR_RESET "\033[48;5;236m" CLR_WHITE "%s:%u \033[K" CLR_RESET,
           (int)getpid(), cpu_clr, g_cpu_load_pct, ram_clr,
           (unsigned long long)ram_free_mb, (unsigned long long)ram_tot_mb,
           gpu_clr, gpu_str, g_master_host, (unsigned int)g_master_port);

    /* Line 2 */
    printf("\033[2;1H\033[48;5;234m" CLR_BOLD CLR_BLUE " [NET/KIOSK]    " CLR_RESET
           "\033[48;5;234m" CLR_DIM "RX:" CLR_RESET "\033[48;5;234m" CLR_CYAN "%llu " CLR_RESET
           "\033[48;5;234m" CLR_DIM "TX:" CLR_RESET "\033[48;5;234m" CLR_GREEN "%llu " CLR_RESET
           "\033[48;5;234m" CLR_DIM "CALLS:" CLR_RESET "\033[48;5;234m" CLR_YELLOW "%-5llu " CLR_RESET
           "\033[48;5;234m" CLR_DIM "KIOSK:" CLR_RESET "\033[48;5;234m" "[%s" "\033[48;5;234m" "] " CLR_RESET
           "\033[48;5;234m" CLR_DIM "UP:" CLR_RESET "\033[48;5;234m" CLR_WHITE "%-8s \033[K" CLR_RESET,
           (unsigned long long)g_packets_rx, (unsigned long long)g_packets_tx,
           (unsigned long long)g_rpc_calls_total, kiosk_status, up_str);

    /* Re-enable auto-wrap and move cursor to line 3 for normal log output */
    printf("\033[?7h\033[3;1H");
    fflush(stdout);
    pthread_mutex_unlock(&g_console_lock);
}


/* =========================================================================
 * CONSOLE LOG PACKET RX/TX
 * ========================================================================= */
static void console_log_packet_rx(int64_t id, const char *method, const char *summary) {
    pthread_mutex_lock(&g_console_lock);
    g_packets_rx++;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    printf("%02d:%02d:%02d.%03d " CLR_CYAN CLR_BOLD "[RX >]" CLR_RESET
           " " CLR_YELLOW "#%-4lld" CLR_RESET
           " " CLR_WHITE CLR_BOLD "%-18s" CLR_RESET
           " " CLR_DIM "%s" CLR_RESET "\n",
           tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(ts.tv_nsec / 1000000),
           (long long)id, method ? method : "UNKNOWN", summary ? summary : "");
    fflush(stdout);
    pthread_mutex_unlock(&g_console_lock);
}

static void console_log_packet_tx(int64_t id, const char *method, int err_code,
                                  uint64_t duration_ms, size_t resp_bytes) {
    pthread_mutex_lock(&g_console_lock);
    g_packets_tx++;
    g_bytes_tx += resp_bytes;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    const char *dur_clr = CLR_GREEN;
    if (duration_ms > 100) dur_clr = CLR_MAGENTA;
    else if (duration_ms > 20) dur_clr = CLR_YELLOW;
    if (err_code == 0) {
        printf("%02d:%02d:%02d.%03d " CLR_GREEN CLR_BOLD "[TX <]" CLR_RESET
               " " CLR_YELLOW "#%-4lld" CLR_RESET
               " " CLR_WHITE "%-18s" CLR_RESET
               " " CLR_GREEN "OK" CLR_RESET
               "  " CLR_DIM "[" CLR_RESET "%s%3llums" CLR_RESET CLR_DIM "]" CLR_RESET "\n",
               tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(ts.tv_nsec / 1000000),
               (long long)id, method ? method : "UNKNOWN", dur_clr, (unsigned long long)duration_ms);
    } else {
        printf("%02d:%02d:%02d.%03d " CLR_RED CLR_BOLD "[TX < ERR]" CLR_RESET
               " " CLR_YELLOW "#%-4lld" CLR_RESET
               " " CLR_WHITE "%-18s" CLR_RESET
               " " CLR_RED CLR_BOLD "ERR %d" CLR_RESET
               "  " CLR_DIM "[" CLR_RESET "%s%3llums" CLR_RESET CLR_DIM "]" CLR_RESET "\n",
               tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(ts.tv_nsec / 1000000),
               (long long)id, method ? method : "UNKNOWN", err_code, dur_clr, (unsigned long long)duration_ms);
    }
    fflush(stdout);
    pthread_mutex_unlock(&g_console_lock);
}

__attribute__((unused)) static void format_bytes_human(uint64_t b, char *out, size_t sz) {
    if (b < 1024) snprintf(out, sz, "%llu B", (unsigned long long)b);
    else if (b < 1024*1024) snprintf(out, sz, "%.1f KB", (double)b/1024.0);
    else if (b < 1024*1024*1024) snprintf(out, sz, "%.1f MB", (double)b/(1024.0*1024.0));
    else snprintf(out, sz, "%.2f GB", (double)b/(1024.0*1024.0*1024.0));
}

/* =========================================================================
 * TELEMETRY THREAD (POSIX)
 * ========================================================================= */
static void *TelemetryThread(void *arg) {
    (void)arg;
    CpuStat prev_cpu;
    read_cpu_stat(&prev_cpu);

    uint32_t s_sample_sec_counter = 0;

    while (__atomic_load_n(&g_running, __ATOMIC_RELAXED)) {
        sleep_ms(1000);
        s_sample_sec_counter++;

        CpuStat cur_cpu;
        if (read_cpu_stat(&cur_cpu)) {
            double pct = compute_cpu_pct(&prev_cpu, &cur_cpu);
            prev_cpu = cur_cpu;

            uint64_t ram_total = 0, ram_avail = 0;
            read_mem_info(&ram_total, &ram_avail);

            pthread_mutex_lock(&g_telemetry_lock);
            g_cpu_load_pct      = pct;
            g_ram_avail_bytes   = ram_avail;
            g_ram_total_bytes   = ram_total;
            g_telemetry_last_tick = get_tick_ms();
            pthread_mutex_unlock(&g_telemetry_lock);

            /* Record ring sample */
            if (s_sample_sec_counter == 1 || s_sample_sec_counter % 60 == 0) {
                pthread_mutex_lock(&g_telemetry_ring_lock);
                TelemetrySample *s = &g_telemetry_ring->samples[g_telemetry_ring->head];
                s->timestamp_sec = (uint64_t)time(NULL);
                s->uptime_sec    = (uint32_t)(get_tick_ms() / 1000ULL);
                s->cpu_pct       = (float)pct;
                s->ram_avail_mb  = (uint32_t)(ram_avail / (1024 * 1024));

                GpuTelemetry gt;
                query_gpu_telemetry(&gt);
                s->gpu_temp_c       = gt.temp_c;
                s->gpu_engine_mhz   = (int16_t)gt.engine_clock_mhz;
                s->gpu_activity_pct = (int8_t)gt.activity_pct;

                g_telemetry_ring->head = (g_telemetry_ring->head + 1) % TELEMETRY_HISTORY_SAMPLES;
                if (g_telemetry_ring->count < TELEMETRY_HISTORY_SAMPLES) g_telemetry_ring->count++;
                g_telemetry_ring->total_recorded++;
                pthread_mutex_unlock(&g_telemetry_ring_lock);

                evaluate_drift_sentinel();
            }

            /* Kiosk sentinel every 3s */
            if (s_sample_sec_counter % 3 == 0) evaluate_kiosk_sentinel();

            /* orb HUD animates on its own thread (OrbThread) */
        }
    }
    return NULL;
}

/* =========================================================================
 * MODULE 1: COMMAND EXECUTION (fork/execvp + pipes)
 * ========================================================================= */
static int kill_process_tree(pid_t root_pid) {
    /* Send SIGKILL to process group */
    kill(-root_pid, SIGKILL);
    kill(root_pid, SIGKILL);
    return 1;
}

static void handle_exec_run(const char *req, int64_t id, DynBuf *resp) {
    char *cmd_b64   = json_get_string(req, "cmd_b64");
    char *plain_cmd = json_get_string(req, "command");
    if (!plain_cmd) plain_cmd = json_get_string(req, "cmd");
    char *shell    = json_get_string(req, "shell");
    char *cwd      = json_get_string(req, "cwd");
    int64_t timeout_ms = json_get_int64(req, "timeout_ms", 0);
    if (timeout_ms <= 0) timeout_ms = json_get_int64(req, "timeout_seconds", 0) * 1000;
    if (timeout_ms <= 0) timeout_ms = 120000;

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
        build_error_response(resp, id, RPC_ERR_EXEC_FAILED, "Missing command or cmd_b64", 0);
        return;
    }

    /* Build final command string */
    char full_cmd[65536];
    if (shell && _stricmp(shell, "bash") == 0) {
        snprintf(full_cmd, sizeof(full_cmd), "bash -c %s", raw_cmd);
    } else if (shell && _stricmp(shell, "direct") == 0) {
        snprintf(full_cmd, sizeof(full_cmd), "%s", raw_cmd);
    } else if (shell && _stricmp(shell, "powershell") == 0) {
        snprintf(full_cmd, sizeof(full_cmd), "pwsh -NonInteractive -Command %s", raw_cmd);
    } else {
        snprintf(full_cmd, sizeof(full_cmd), "sh -c '%s'", raw_cmd);
    }

    __atomic_store_n(&g_cmd_executing, 1, __ATOMIC_RELAXED);
    uint64_t start_tick = get_tick_ms();

    pthread_mutex_lock(&g_console_lock);
    printf("\n" CLR_CYAN "  +-- [RX: EXEC] ID #%lld " CLR_RESET "------------------------------------------\n", (long long)id);
    printf("  " CLR_DIM "|" CLR_RESET " " CLR_WHITE "%s" CLR_RESET "\n", raw_cmd);
    printf("  " CLR_DIM "|" CLR_RESET " Shell: " CLR_YELLOW "%s" CLR_RESET " | Timeout: " CLR_YELLOW "%lldms" CLR_RESET "\n",
           shell ? shell : "sh", (long long)timeout_ms);
    fflush(stdout);
    pthread_mutex_unlock(&g_console_lock);

    free(raw_cmd);
    free(shell);

    int out_fds[2], err_fds[2];
    if (pipe(out_fds) < 0 || pipe(err_fds) < 0) {
        free(cwd);
        __atomic_store_n(&g_cmd_executing, 0, __ATOMIC_RELAXED);
        build_error_response(resp, id, RPC_ERR_EXEC_FAILED, "pipe() failed", errno);
        return;
    }

    pid_t child = fork();
    if (child < 0) {
        close(out_fds[0]); close(out_fds[1]);
        close(err_fds[0]); close(err_fds[1]);
        free(cwd);
        __atomic_store_n(&g_cmd_executing, 0, __ATOMIC_RELAXED);
        build_error_response(resp, id, RPC_ERR_EXEC_FAILED, "fork() failed", errno);
        return;
    }

    if (child == 0) {
        /* Child process */
        setsid(); /* new session -> own process group for kill_process_tree */
        dup2(out_fds[1], STDOUT_FILENO);
        dup2(err_fds[1], STDERR_FILENO);
        close(out_fds[0]); close(out_fds[1]);
        close(err_fds[0]); close(err_fds[1]);
        if (cwd && strlen(cwd) > 0) chdir(cwd);
        execl("/bin/sh", "sh", "-c", full_cmd, NULL);
        _exit(127);
    }

    /* Parent */
    close(out_fds[1]);
    close(err_fds[1]);
    free(cwd);

    DynBuf out_buf, err_buf;
    db_init(&out_buf, 4096);
    db_init(&err_buf, 4096);

    /* Non-blocking drain with timeout */
    fcntl(out_fds[0], F_SETFL, O_NONBLOCK);
    fcntl(err_fds[0], F_SETFL, O_NONBLOCK);

    uint64_t deadline = get_tick_ms() + (uint64_t)timeout_ms;
    bool timed_out = false;
    int exit_code  = 0;
    bool child_done = false;

    while (!child_done) {
        struct pollfd pfd[2] = {
            { .fd = out_fds[0], .events = POLLIN },
            { .fd = err_fds[0], .events = POLLIN }
        };
        uint64_t now = get_tick_ms();
        if (now >= deadline) { timed_out = true; kill_process_tree(child); break; }
        int ms_left = (int)(deadline - now);
        if (ms_left > 200) ms_left = 200;
        int r = poll(pfd, 2, ms_left);

        char tmp[4096];
        if (r > 0) {
            ssize_t nr;
            if (pfd[0].revents & POLLIN) {
                nr = read(out_fds[0], tmp, sizeof(tmp));
                if (nr > 0 && out_buf.len < MAX_PIPE_BUFFER_BYTES) db_append_mem(&out_buf, tmp, (size_t)nr);
            }
            if (pfd[1].revents & POLLIN) {
                nr = read(err_fds[0], tmp, sizeof(tmp));
                if (nr > 0 && err_buf.len < MAX_PIPE_BUFFER_BYTES) db_append_mem(&err_buf, tmp, (size_t)nr);
            }
        }

        /* Check if child exited */
        int wstatus = 0;
        pid_t wp = waitpid(child, &wstatus, WNOHANG);
        if (wp == child) {
            exit_code  = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : 1;
            child_done = true;
            /* Drain remaining */
            ssize_t nr;
            while ((nr = read(out_fds[0], tmp, sizeof(tmp))) > 0) {
                if (out_buf.len < MAX_PIPE_BUFFER_BYTES) db_append_mem(&out_buf, tmp, (size_t)nr);
            }
            while ((nr = read(err_fds[0], tmp, sizeof(tmp))) > 0) {
                if (err_buf.len < MAX_PIPE_BUFFER_BYTES) db_append_mem(&err_buf, tmp, (size_t)nr);
            }
        }
    }

    if (timed_out) {
        /* Wait for killed child */
        int ws = 0;
        waitpid(child, &ws, 0);
        exit_code = 1;
    }

    close(out_fds[0]);
    close(err_fds[0]);

    uint64_t elapsed_ms = get_tick_ms() - start_tick;

    pthread_mutex_lock(&g_console_lock);
    const char *status_str = timed_out ? "TIMEOUT" : (exit_code == 0 ? "SUCCESS" : "EXIT_CODE");
    const char *status_clr = timed_out ? (CLR_RED CLR_BOLD) : (exit_code == 0 ? CLR_GREEN : CLR_YELLOW);
    printf("  " CLR_DIM "+--" CLR_RESET " " CLR_CYAN "[TX: DONE]" CLR_RESET " Status: %s%s%s (exit %d) | Time: " CLR_WHITE "%llums" CLR_RESET "\n",
           status_clr, status_str, CLR_RESET, exit_code, (unsigned long long)elapsed_ms);
    fflush(stdout);
    pthread_mutex_unlock(&g_console_lock);

    __atomic_store_n(&g_cmd_executing, 0, __ATOMIC_RELAXED);

    char *out_b64 = b64_encode((const unsigned char *)(out_buf.data ? out_buf.data : ""), out_buf.len, NULL);
    char *err_b64 = b64_encode((const unsigned char *)(err_buf.data ? err_buf.data : ""), err_buf.len, NULL);
    db_free(&out_buf);
    db_free(&err_buf);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":");
    db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"pid\":");
    db_append_uint64(resp, (uint64_t)child);
    db_append_str(resp, ",\"exit_code\":");
    db_append_int64(resp, exit_code);
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
 * MODULE 2: FILE SYSTEM
 * ========================================================================= */
static void handle_fs_hash(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) { build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0); return; }
    char sha_hex[65];
    uint64_t fsize = 0;
    int err = 0;
    bool ok = compute_file_sha256(path, sha_hex, &fsize, &err);
    free(path);
    if (!ok) { build_error_response(resp, id, RPC_ERR_FS_FAILED, "compute_file_sha256 failed", err); return; }
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
    if (!path) { build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0); return; }
    if (length <= 0 || length > (8 * 1024 * 1024)) length = MAX_IO_CHUNK_BYTES;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int e = errno; free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "open() failed", e); return;
    }
    struct stat st;
    fstat(fd, &st);
    int64_t fsize = (int64_t)st.st_size;

    if (lseek(fd, (off_t)offset, SEEK_SET) < 0) {
        int e = errno; close(fd); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "lseek() failed", e); return;
    }

    unsigned char *buf = (unsigned char *)malloc((size_t)length);
    if (!buf) { close(fd); free(path); build_error_response(resp, id, RPC_ERR_INTERNAL, "OOM", 0); return; }
    ssize_t bread = read(fd, buf, (size_t)length);
    int e = errno; close(fd); free(path);
    if (bread < 0) { free(buf); build_error_response(resp, id, RPC_ERR_FS_FAILED, "read() failed", e); return; }

    char chunk_sha[65] = "";
    compute_buffer_sha256(buf, (size_t)bread, chunk_sha);
    char *data_b64 = b64_encode(buf, (size_t)bread, NULL);
    free(buf);
    bool eof = ((offset + bread) >= fsize);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"total_size\":"); db_append_int64(resp, fsize);
    db_append_str(resp, ",\"offset\":"); db_append_int64(resp, offset);
    db_append_str(resp, ",\"bytes_read\":"); db_append_uint64(resp, (uint64_t)bread);
    db_append_str(resp, ",\"eof\":"); db_append_str(resp, eof ? "true" : "false");
    db_append_str(resp, ",\"chunk_sha256\":\""); db_append_str(resp, chunk_sha);
    db_append_str(resp, "\",\"data_b64\":\""); db_append_str(resp, data_b64 ? data_b64 : "");
    db_append_str(resp, "\"}}");
    free(data_b64);
}

static void handle_fs_write(const char *req, int64_t id, DynBuf *resp) {
    char *path     = json_get_string(req, "path");
    char *data_b64 = json_get_string(req, "data_b64");
    int64_t offset = json_get_int64(req, "offset", 0);
    bool truncate  = json_get_bool(req, "truncate", true);
    bool finalize  = json_get_bool(req, "finalize_hash", false);
    if (!path || !data_b64) {
        free(path); free(data_b64);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path or data_b64", 0); return;
    }
    size_t raw_len = 0;
    unsigned char *raw_data = b64_decode(data_b64, &raw_len);
    free(data_b64);
    if (!raw_data) { free(path); build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Invalid data_b64", 0); return; }

    int flags = O_WRONLY | O_CREAT;
    if (truncate && offset == 0) flags |= O_TRUNC;
    int fd = open(path, flags, 0644);
    if (fd < 0) {
        int e = errno; free(path); free(raw_data);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "open() for write failed", e); return;
    }
    if (offset > 0) lseek(fd, (off_t)offset, SEEK_SET);
    ssize_t written = write(fd, raw_data, raw_len);
    int e = errno; close(fd);

    char chunk_sha[65] = "";
    compute_buffer_sha256(raw_data, (size_t)(written > 0 ? written : 0), chunk_sha);
    free(raw_data);
    if (written < 0) { free(path); build_error_response(resp, id, RPC_ERR_FS_FAILED, "write() failed", e); return; }

    char file_sha[65] = "";
    uint64_t total_sz = 0;
    if (finalize) compute_file_sha256(path, file_sha, &total_sz, NULL);
    free(path);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"bytes_written\":"); db_append_uint64(resp, (uint64_t)written);
    db_append_str(resp, ",\"chunk_sha256\":\""); db_append_str(resp, chunk_sha);
    db_append_str(resp, "\",\"file_sha256\":\""); db_append_str(resp, file_sha);
    db_append_str(resp, "\"}}");
}

static void handle_fs_patch(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) path = json_get_string(req, "TargetFile");
    if (!path) path = json_get_string(req, "file_path");

    char *search_b64  = json_get_string(req, "search_b64");
    char *replace_b64 = json_get_string(req, "replace_b64");
    bool replace_all  = json_get_bool(req, "replace_all", false);

    if (!search_b64) {
        char *t = json_get_string(req, "target");
        if (!t) t = json_get_string(req, "TargetContent");
        if (!t) t = json_get_string(req, "search");
        if (t) { search_b64 = b64_encode((const unsigned char *)t, strlen(t), NULL); free(t); }
    }
    if (!replace_b64) {
        char *r = json_get_string(req, "replacement");
        if (!r) r = json_get_string(req, "ReplacementContent");
        if (!r) r = json_get_string(req, "replace");
        if (r) { replace_b64 = b64_encode((const unsigned char *)r, strlen(r), NULL); free(r); }
    }
    if (!path || !search_b64 || !replace_b64) {
        free(path); free(search_b64); free(replace_b64);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path/search/replace", 0); return;
    }

    size_t s_len = 0, r_len = 0;
    unsigned char *s_buf = b64_decode(search_b64, &s_len);
    unsigned char *r_buf = b64_decode(replace_b64, &r_len);
    free(search_b64); free(replace_b64);
    if (!s_buf || !r_buf || s_len == 0) {
        free(path); free(s_buf); free(r_buf);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Invalid patch payload", 0); return;
    }

    /* Read file */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        int e = errno; free(path); free(s_buf); free(r_buf);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Cannot open file for patch", e); return;
    }
    struct stat st; fstat(fd, &st);
    size_t orig_len = (size_t)st.st_size;
    unsigned char *orig = (unsigned char *)malloc(orig_len + 1);
    ssize_t nr = read(fd, orig, orig_len);
    close(fd);
    if (nr < 0) {
        free(path); free(s_buf); free(r_buf); free(orig);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "read() failed", errno); return;
    }
    orig_len = (size_t)nr;

    DynBuf patched; db_init(&patched, orig_len + 1024);
    size_t pos = 0; int replacements = 0;
    while (pos < orig_len) {
        if ((orig_len - pos) >= s_len && memcmp(orig + pos, s_buf, s_len) == 0 &&
            (replace_all || replacements == 0)) {
            db_append_mem(&patched, r_buf, r_len);
            pos += s_len; replacements++;
        } else {
            db_append_char(&patched, (char)orig[pos++]);
        }
    }
    free(orig); free(s_buf); free(r_buf);

    if (replacements == 0) {
        db_free(&patched); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Search pattern not found", 0); return;
    }

    /* Atomic write via temp + rename */
    char tmp_path[MAX_PATH + 16];
    snprintf(tmp_path, sizeof(tmp_path), "%s.bridge_tmp", path);
    int wfd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (wfd < 0) {
        int e = errno; db_free(&patched); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Temp file creation failed", e); return;
    }
    write(wfd, patched.data, patched.len);
    close(wfd);
    if (rename(tmp_path, path) < 0) {
        int e = errno; unlink(tmp_path); db_free(&patched); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "rename() failed", e); return;
    }

    char sha_hex[65] = "";
    compute_file_sha256(path, sha_hex, NULL, NULL);
    size_t final_len = patched.len;
    db_free(&patched); free(path);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"replacements\":"); db_append_int64(resp, replacements);
    db_append_str(resp, ",\"new_size\":"); db_append_uint64(resp, final_len);
    db_append_str(resp, ",\"sha256\":\""); db_append_str(resp, sha_hex);
    db_append_str(resp, "\"}}");
}

static void handle_fs_list(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) { build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0); return; }
    DIR *d = opendir(path);
    if (!d) {
        int e = errno; free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "opendir() failed", e); return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"entries\":[");
    bool first = true;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", path, e->d_name);
        struct stat st;
        if (stat(full, &st) < 0) continue;
        bool is_dir = S_ISDIR(st.st_mode);
        if (!first) db_append_char(resp, ',');
        first = false;
        db_append_str(resp, "{\"name\":\"");
        db_append_json_escaped(resp, e->d_name);
        db_append_str(resp, "\",\"is_dir\":");
        db_append_str(resp, is_dir ? "true" : "false");
        db_append_str(resp, ",\"size\":");
        db_append_uint64(resp, (uint64_t)st.st_size);
        db_append_str(resp, "}");
    }
    closedir(d); free(path);
    db_append_str(resp, "]}}");
}

static bool delete_dir_recursive(const char *dir_path, int *files_deleted, uint64_t *bytes_freed) {
    DIR *d = opendir(dir_path);
    if (!d) return false;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", dir_path, e->d_name);
        struct stat st;
        if (lstat(full, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            delete_dir_recursive(full, files_deleted, bytes_freed);
            rmdir(full);
        } else {
            if (bytes_freed) *bytes_freed += (uint64_t)st.st_size;
            if (unlink(full) == 0 && files_deleted) (*files_deleted)++;
        }
    }
    closedir(d);
    return true;
}

static void handle_fs_delete(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) { build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0); return; }
    struct stat st;
    if (lstat(path, &st) < 0) {
        int e = errno; free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "Path does not exist", e); return;
    }
    bool ok;
    if (S_ISDIR(st.st_mode)) {
        delete_dir_recursive(path, NULL, NULL);
        ok = (rmdir(path) == 0);
    } else {
        ok = (unlink(path) == 0);
    }
    int e = errno; free(path);
    if (!ok) { build_error_response(resp, id, RPC_ERR_FS_FAILED, "Delete failed", e); return; }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"deleted\":true}}");
}

static void handle_fs_mkdir(const char *req, int64_t id, DynBuf *resp) {
    char *path = json_get_string(req, "path");
    if (!path) { build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path", 0); return; }
    /* mkdir -p equivalent */
    char tmp[MAX_PATH];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    int r = mkdir(path, 0755);
    int e = errno; free(path);
    if (r < 0 && e != EEXIST) {
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "mkdir() failed", e); return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"created\":true}}");
}

/* fs_find recursive */
typedef struct {
    DynBuf     *resp;
    int         count;
    int         max_results;
    int         max_depth;
    const char *pattern;
} FindCtx;

static bool matches_simple_pattern(const char *name, const char *pat) {
    if (!pat || strcmp(pat, "*") == 0) return true;
    size_t nlen = strlen(name), plen = strlen(pat);
    if (pat[0] == '*' && plen > 1) {
        const char *sub = pat + 1;
        size_t slen = strlen(sub);
        if (slen > 0 && sub[slen-1] == '*') {
            char term[256]; strncpy(term, sub, slen-1); term[slen-1] = '\0';
            return (strcasestr_custom(name, term) != NULL);
        }
        if (nlen < slen) return false;
        return (_stricmp(name + nlen - slen, sub) == 0);
    }
    if (plen > 1 && pat[plen-1] == '*') return (strncasecmp(name, pat, plen-1) == 0);
    return (_stricmp(name, pat) == 0 || strcasestr_custom(name, pat) != NULL);
}

static void fs_find_recurse(const char *dir, int depth, FindCtx *ctx) {
    if (ctx->count >= ctx->max_results || depth > ctx->max_depth) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL && ctx->count < ctx->max_results) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(full, &st) < 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            if (depth < ctx->max_depth) fs_find_recurse(full, depth + 1, ctx);
        } else if (matches_simple_pattern(e->d_name, ctx->pattern)) {
            if (ctx->count > 0) db_append_char(ctx->resp, ',');
            db_append_str(ctx->resp, "{\"path\":\"");
            db_append_json_escaped(ctx->resp, full);
            db_append_str(ctx->resp, "\",\"size\":");
            db_append_uint64(ctx->resp, (uint64_t)st.st_size);
            db_append_str(ctx->resp, "}");
            ctx->count++;
        }
    }
    closedir(d);
}

static void handle_fs_find(const char *req, int64_t id, DynBuf *resp) {
    char *root    = json_get_string(req, "root");
    if (!root) root = json_get_string(req, "path");
    char *pattern = json_get_string(req, "pattern");
    if (!pattern) pattern = json_get_string(req, "filter");
    int64_t max_depth   = json_get_int64(req, "max_depth", 6);
    int64_t max_results = json_get_int64(req, "max_results", 50);

    const char *start_root = root    ? root    : "/";
    const char *start_pat  = pattern ? pattern : "*";

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"root\":\"");
    db_append_json_escaped(resp, start_root);
    db_append_str(resp, "\",\"pattern\":\"");
    db_append_json_escaped(resp, start_pat);
    db_append_str(resp, "\",\"matches\":[");

    FindCtx ctx = { resp, 0, (int)max_results, (int)max_depth, start_pat };
    uint64_t t0 = get_tick_ms();
    fs_find_recurse(start_root, 0, &ctx);
    uint64_t duration = get_tick_ms() - t0;

    db_append_str(resp, "],\"count\":"); db_append_int64(resp, ctx.count);
    db_append_str(resp, ",\"duration_ms\":"); db_append_uint64(resp, duration);
    db_append_str(resp, "}}");
    free(root); free(pattern);
}

/* =========================================================================
 * MODULE 3: SELF-UPDATE (ELF binary check + atomic rename + re-exec)
 * ========================================================================= */
static bool verify_elf_binary(const char *file_path) {
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) return false;
    uint8_t magic[4];
    ssize_t nr = read(fd, magic, 4);
    close(fd);
    /* ELF magic: 0x7F 'E' 'L' 'F' */
    return (nr == 4 && magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F');
}

static void handle_agent_update(const char *req, int64_t id, DynBuf *resp, bool *trigger_exit) {
    char *staging_path   = json_get_string(req, "staging_path");
    char *expected_sha256 = json_get_string(req, "expected_sha256");

    /* Self path via /proc/self/exe */
    char self_path[MAX_PATH];
    ssize_t r = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (r < 0) { free(staging_path); free(expected_sha256); build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "readlink /proc/self/exe failed", errno); return; }
    self_path[r] = '\0';

    char new_path[MAX_PATH + 16];
    if (staging_path && strlen(staging_path) > 0)
        snprintf(new_path, sizeof(new_path), "%s", staging_path);
    else
        snprintf(new_path, sizeof(new_path), "%s.new", self_path);
    free(staging_path);

    if (!verify_elf_binary(new_path)) {
        unlink(new_path); free(expected_sha256);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "Invalid ELF magic on staged binary", 0); return;
    }

    char actual_sha[65] = "";
    uint64_t fsize = 0;
    if (!compute_file_sha256(new_path, actual_sha, &fsize, NULL)) {
        unlink(new_path); free(expected_sha256);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "SHA-256 compute failed on staged binary", 0); return;
    }
    if (expected_sha256 && strlen(expected_sha256) == 64 && _stricmp(actual_sha, expected_sha256) != 0) {
        unlink(new_path); free(expected_sha256);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "SHA-256 mismatch", 0); return;
    }
    free(expected_sha256);

    /* Side-by-side selftest */
    char selftest_cmd[MAX_PATH + 32];
    snprintf(selftest_cmd, sizeof(selftest_cmd), "chmod +x %s && %s --selftest", new_path, new_path);
    int test_exit = system(selftest_cmd);
    if (test_exit != 0) {
        unlink(new_path);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "Selftest non-zero exit", test_exit); return;
    }

    /* Atomic swap */
    char old_path[MAX_PATH + 8];
    snprintf(old_path, sizeof(old_path), "%s.old", self_path);
    unlink(old_path);
    rename(self_path, old_path);
    chmod(new_path, 0755);
    if (rename(new_path, self_path) < 0) {
        int e = errno;
        rename(old_path, self_path);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "rename() failed; rolled back", e); return;
    }

    /* Spawn replacement */
    char cmd[MAX_PATH + 320];
    snprintf(cmd, sizeof(cmd), "nohup %s --host %s --port %u --token \"%s\" --agent-id \"%s\" --upgraded-from %d &",
             self_path, g_master_host, (unsigned int)g_master_port, g_psk_token, g_agent_id, (int)getpid());
    int spawn_r = system(cmd);

    if (spawn_r != 0) {
        rename(old_path, self_path);
        build_error_response(resp, id, RPC_ERR_UPDATE_FAILED, "Spawn of new agent failed; rolled back", 0); return;
    }

    agent_log(LOG_LVL_INFO, "Self-update succeeded! SHA256=%s", actual_sha);
    *trigger_exit = true;

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"updated\":true,\"sha256\":\"");
    db_append_str(resp, actual_sha);
    db_append_str(resp, "\"}}");
}

/* =========================================================================
 * MODULE 4: REGISTRY (NOT SUPPORTED on Linux -> stub)
 * ========================================================================= */
static void handle_reg_not_supported(int64_t id, DynBuf *resp) {
    build_error_response(resp, id, RPC_ERR_REG_FAILED, "Registry not supported on Linux", 0);
}

/* =========================================================================
 * MODULE 4b: SYSTEMD SERVICES (via systemctl)
 * ========================================================================= */
static void handle_svc_op(const char *req, int64_t id, DynBuf *resp) {
    char *name   = json_get_string(req, "service_name");
    char *action = json_get_string(req, "action");
    if (!name || !action) {
        free(name); free(action);
        build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing service_name or action", 0); return;
    }

    /* Sanitize name: no shell injection */
    for (char *p = name; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.') *p = '_';
    }

    char cmd[512];
    int exit_code = 0;
    char *start_type = json_get_string(req, "start_type");

    if (_stricmp(action, "start") == 0)
        snprintf(cmd, sizeof(cmd), "systemctl start %s 2>&1", name);
    else if (_stricmp(action, "stop") == 0)
        snprintf(cmd, sizeof(cmd), "systemctl stop %s 2>&1", name);
    else if (_stricmp(action, "status") == 0)
        snprintf(cmd, sizeof(cmd), "systemctl is-active %s 2>&1", name);
    else if (_stricmp(action, "set_start_type") == 0 && start_type) {
        if (_stricmp(start_type, "auto") == 0)
            snprintf(cmd, sizeof(cmd), "systemctl enable %s 2>&1", name);
        else if (_stricmp(start_type, "disabled") == 0)
            snprintf(cmd, sizeof(cmd), "systemctl disable %s 2>&1", name);
        else
            snprintf(cmd, sizeof(cmd), "systemctl disable %s 2>&1", name);
    } else {
        snprintf(cmd, sizeof(cmd), "systemctl %s %s 2>&1", action, name);
    }
    free(start_type);

    exit_code = system(cmd);
    free(name); free(action);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"exit_code\":"); db_append_int64(resp, exit_code);
    db_append_str(resp, "}}");
}

/* =========================================================================
 * MODULE 4c: PROCESS LIST (via /proc)
 * ========================================================================= */
static void handle_proc_list(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"processes\":[");

    DIR *d = opendir("/proc");
    if (!d) {
        build_error_response(resp, id, RPC_ERR_PROC_FAILED, "opendir /proc failed", errno); return;
    }

    bool first = true;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        pid_t pid = (pid_t)atoi(e->d_name);

        char comm_path[64], stat_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

        char comm[256] = "";
        FILE *f = fopen(comm_path, "r");
        if (f) { fgets(comm, sizeof(comm), f); fclose(f); }
        size_t cl = strlen(comm);
        while (cl > 0 && (comm[cl-1] == '\n' || comm[cl-1] == '\r')) comm[--cl] = '\0';

        /* ppid from /proc/pid/stat */
        pid_t ppid = 0;
        f = fopen(stat_path, "r");
        if (f) {
            char dummy[256]; int dummy_i;
            fscanf(f, "%d %s %c %d", &dummy_i, dummy, (char*)dummy, &ppid);
            fclose(f);
        }

        /* RSS memory from /proc/pid/status */
        uint64_t vmrss = 0;
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
        f = fopen(status_path, "r");
        if (f) {
            char line[128];
            while (fgets(line, sizeof(line), f)) {
                unsigned long long v = 0;
                if (sscanf(line, "VmRSS: %llu kB", &v) == 1) vmrss = v * 1024ULL;
            }
            fclose(f);
        }

        if (!first) db_append_char(resp, ',');
        first = false;
        db_append_str(resp, "{\"pid\":"); db_append_uint64(resp, (uint64_t)pid);
        db_append_str(resp, ",\"ppid\":"); db_append_uint64(resp, (uint64_t)ppid);
        db_append_str(resp, ",\"name\":\""); db_append_json_escaped(resp, comm);
        db_append_str(resp, "\",\"working_set_bytes\":"); db_append_uint64(resp, vmrss);
        db_append_str(resp, "}");
    }
    closedir(d);
    db_append_str(resp, "]}}");
}

static void handle_proc_kill(const char *req, int64_t id, DynBuf *resp) {
    int64_t pid  = json_get_int64(req, "pid", -1);
    bool tree    = json_get_bool(req, "kill_tree", true);
    if (pid <= 0) { build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Invalid pid", 0); return; }
    int count = 0;
    if (tree) { kill(-(pid_t)pid, SIGKILL); kill((pid_t)pid, SIGKILL); count = 1; }
    else { if (kill((pid_t)pid, SIGKILL) == 0) count = 1; }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"terminated_count\":"); db_append_int64(resp, count);
    db_append_str(resp, "}}");
}

static void handle_proc_priority(const char *req, int64_t id, DynBuf *resp) {
    int64_t pid = json_get_int64(req, "pid", -1);
    char *prio  = json_get_string(req, "priority");
    if (pid <= 0 || !prio) { free(prio); build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing pid or priority", 0); return; }
    int nice_val = 0;
    if (_stricmp(prio, "idle") == 0)         nice_val = 19;
    else if (_stricmp(prio, "below_normal") == 0) nice_val = 10;
    else if (_stricmp(prio, "above_normal") == 0) nice_val = -5;
    else if (_stricmp(prio, "high") == 0)    nice_val = -10;
    else if (_stricmp(prio, "realtime") == 0) nice_val = -20;
    free(prio);
    if (setpriority(PRIO_PROCESS, (id_t)pid, nice_val) < 0) {
        build_error_response(resp, id, RPC_ERR_PROC_FAILED, "setpriority() failed", errno); return;
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"updated\":true}}");
}

/* =========================================================================
 * MODULE 5: DIAGNOSTICS
 * ========================================================================= */
static void handle_sys_diag(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    pthread_mutex_lock(&g_telemetry_lock);
    double cpu_pct = g_cpu_load_pct;
    pthread_mutex_unlock(&g_telemetry_lock);

    uint64_t ram_total = 0, ram_avail = 0;
    read_mem_info(&ram_total, &ram_avail);

    char hostname[256] = "";
    gethostname(hostname, sizeof(hostname));

    /* CPU cores */
    long ncores = sysconf(_SC_NPROCESSORS_ONLN);

    /* Agent RSS */
    uint64_t agent_rss = 0;
    {
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[128];
            while (fgets(line, sizeof(line), f)) {
                unsigned long long v = 0;
                if (sscanf(line, "VmRSS: %llu kB", &v) == 1) agent_rss = v * 1024ULL;
            }
            fclose(f);
        }
    }

    /* Uptime from /proc/uptime */
    uint64_t uptime_sec = 0;
    {
        FILE *f = fopen("/proc/uptime", "r");
        if (f) { double u = 0; fscanf(f, "%lf", &u); uptime_sec = (uint64_t)u; fclose(f); }
    }

    /* Disk mounts from /proc/mounts */
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"hostname\":\""); db_append_json_escaped(resp, hostname);
    db_append_str(resp, "\",\"version\":\"" BRIDGE_PROTOCOL_VERSION "\"");
    db_append_str(resp, ",\"architecture\":\"x86_64 (64-bit)\"");
    db_append_str(resp, ",\"os_build\":0");
    db_append_str(resp, ",\"cpu_cores\":"); db_append_int64(resp, ncores);
    char cpu_str[32]; snprintf(cpu_str, sizeof(cpu_str), "%.2f", cpu_pct);
    db_append_str(resp, ",\"cpu_load_percent\":"); db_append_str(resp, cpu_str);
    db_append_str(resp, ",\"ram_total_bytes\":"); db_append_uint64(resp, ram_total);
    db_append_str(resp, ",\"ram_avail_bytes\":"); db_append_uint64(resp, ram_avail);
    db_append_str(resp, ",\"agent_working_set_bytes\":"); db_append_uint64(resp, agent_rss);
    db_append_str(resp, ",\"uptime_seconds\":"); db_append_uint64(resp, uptime_sec);
    db_append_str(resp, ",\"agent_pid\":"); db_append_uint64(resp, (uint64_t)getpid());
    db_append_str(resp, ",\"disks\":[");

    /* Enumerate mounted filesystems */
    {
        FILE *f = fopen("/proc/mounts", "r");
        bool first = true;
        if (f) {
            char line[512], dev[128], mp[256], fstype[64];
            while (fgets(line, sizeof(line), f)) {
                if (sscanf(line, "%127s %255s %63s", dev, mp, fstype) != 3) continue;
                if (strcmp(fstype, "ext4") != 0 && strcmp(fstype, "ext3") != 0 &&
                    strcmp(fstype, "ext2") != 0 && strcmp(fstype, "btrfs") != 0 &&
                    strcmp(fstype, "xfs") != 0  && strcmp(fstype, "f2fs") != 0) continue;
                struct statvfs vfs;
                if (statvfs(mp, &vfs) < 0) continue;
                uint64_t total = (uint64_t)vfs.f_blocks * vfs.f_frsize;
                uint64_t free_b = (uint64_t)vfs.f_bfree * vfs.f_frsize;
                if (!first) db_append_char(resp, ',');
                first = false;
                db_append_str(resp, "{\"mount\":\""); db_append_json_escaped(resp, mp);
                db_append_str(resp, "\",\"total_bytes\":"); db_append_uint64(resp, total);
                db_append_str(resp, ",\"free_bytes\":"); db_append_uint64(resp, free_b);
                db_append_str(resp, "}");
            }
            fclose(f);
        }
    }
    db_append_str(resp, "]");

    GpuTelemetry gpu; query_gpu_telemetry(&gpu);
    if (gpu.temp_c >= 0.0f) {
        char gbuf[32]; snprintf(gbuf, sizeof(gbuf), "%.1f", gpu.temp_c);
        db_append_str(resp, ",\"gpu_temp_c\":"); db_append_str(resp, gbuf);
    }
    if (gpu.engine_clock_mhz > 0) {
        db_append_str(resp, ",\"gpu_engine_clock_mhz\":"); db_append_uint64(resp, (uint64_t)gpu.engine_clock_mhz);
    }
    if (gpu.activity_pct >= 0) {
        db_append_str(resp, ",\"gpu_activity_pct\":"); db_append_uint64(resp, (uint64_t)gpu.activity_pct);
    }
    db_append_str(resp, "}}");
}

static void handle_sys_telemetry_history(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"interval_sec\":60,\"capacity\":60,\"count\":");
    pthread_mutex_lock(&g_telemetry_ring_lock);
    uint32_t count = g_telemetry_ring->count;
    uint32_t head  = g_telemetry_ring->head;
    uint64_t total = g_telemetry_ring->total_recorded;
    db_append_uint64(resp, count);
    db_append_str(resp, ",\"total_recorded\":"); db_append_uint64(resp, total);
    db_append_str(resp, ",\"samples\":[");
    if (count > 0) {
        uint32_t start_idx = (head + TELEMETRY_HISTORY_SAMPLES - count) % TELEMETRY_HISTORY_SAMPLES;
        char num_buf[32];
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t idx = (start_idx + i) % TELEMETRY_HISTORY_SAMPLES;
            TelemetrySample *s = &g_telemetry_ring->samples[idx];
            if (i > 0) db_append_char(resp, ',');
            db_append_str(resp, "{\"ts\":"); db_append_uint64(resp, s->timestamp_sec);
            db_append_str(resp, ",\"uptime_s\":"); db_append_uint64(resp, s->uptime_sec);
            db_append_str(resp, ",\"cpu_pct\":"); snprintf(num_buf, sizeof(num_buf), "%.1f", s->cpu_pct); db_append_str(resp, num_buf);
            db_append_str(resp, ",\"ram_avail_mb\":"); db_append_uint64(resp, s->ram_avail_mb);
            db_append_str(resp, ",\"gpu_temp_c\":");
            if (s->gpu_temp_c >= 0.0f) { snprintf(num_buf, sizeof(num_buf), "%.1f", s->gpu_temp_c); db_append_str(resp, num_buf); }
            else db_append_str(resp, "null");
            if (s->gpu_engine_mhz > 0) { db_append_str(resp, ",\"gpu_clock_mhz\":"); db_append_int64(resp, s->gpu_engine_mhz); }
            if (s->gpu_activity_pct >= 0) { db_append_str(resp, ",\"gpu_activity_pct\":"); db_append_int64(resp, s->gpu_activity_pct); }
            db_append_str(resp, "}");
        }
    }
    pthread_mutex_unlock(&g_telemetry_ring_lock);
    db_append_str(resp, "]}}");
}

static void handle_sys_drift_status(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    pthread_mutex_lock(&g_drift_sentinel_lock);
    DriftSentinelState st = g_drift_sentinel;
    pthread_mutex_unlock(&g_drift_sentinel_lock);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"samples_evaluated\":"); db_append_uint64(resp, st.samples_evaluated);
    char num[256];
    snprintf(num, sizeof(num), ",\"ram_slope_mb_min\":%.3f,\"ram_r2\":%.3f,\"ram_monotonicity\":%.3f", st.ram_slope_mb_min, st.ram_r2, st.ram_monotonicity);
    db_append_str(resp, num);
    db_append_str(resp, ",\"ram_drift_detected\":"); db_append_str(resp, st.ram_drift_detected ? "true" : "false");
    db_append_str(resp, ",\"ram_trims_triggered\":"); db_append_uint64(resp, st.ram_trims_triggered);
    db_append_str(resp, ",\"last_ram_trim_sec\":"); db_append_uint64(resp, st.last_ram_trim_sec);
    snprintf(num, sizeof(num), ",\"gpu_temp_c\":%.1f", st.gpu_temp_c); db_append_str(resp, num);
    db_append_str(resp, ",\"thermal_drift_detected\":"); db_append_str(resp, st.thermal_drift_detected ? "true" : "false");
    db_append_str(resp, ",\"thermal_throttled\":"); db_append_str(resp, st.thermal_throttled ? "true" : "false");
    db_append_str(resp, ",\"thermal_throttle_count\":"); db_append_uint64(resp, st.thermal_throttle_count);
    db_append_str(resp, ",\"cpu_governor_mode\":"); db_append_str(resp, st.thermal_throttled ? "\"powersave\"" : "\"ondemand\"");
    db_append_str(resp, "}}");
}

static void handle_sys_hardware(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    char hostname[256] = ""; gethostname(hostname, sizeof(hostname));
    char username[128] = "";
    {
        FILE *f = popen("whoami 2>/dev/null", "r");
        if (f) { fgets(username, sizeof(username), f); pclose(f); }
        size_t l = strlen(username);
        while (l > 0 && (username[l-1] == '\n' || username[l-1] == '\r')) username[--l] = '\0';
    }
    char cpu_brand[256] = "Unknown";
    {
        FILE *f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "model name", 10) == 0) {
                    char *p = strchr(line, ':');
                    if (p) { p++; while (*p == ' ') p++; strncpy(cpu_brand, p, sizeof(cpu_brand)-1); cpu_brand[sizeof(cpu_brand)-1] = '\0'; size_t l = strlen(cpu_brand); while (l > 0 && (cpu_brand[l-1] == '\n' || cpu_brand[l-1] == '\r')) cpu_brand[--l] = '\0'; break; }
                }
            }
            fclose(f);
        }
    }
    long ncores = sysconf(_SC_NPROCESSORS_ONLN);
    uint64_t ram_total = 0, ram_avail = 0;
    read_mem_info(&ram_total, &ram_avail);
    uint64_t uptime_sec = 0;
    { FILE *f = fopen("/proc/uptime", "r"); if (f) { double u = 0; fscanf(f, "%lf", &u); uptime_sec = (uint64_t)u; fclose(f); } }

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"computer_name\":\""); db_append_json_escaped(resp, hostname);
    db_append_str(resp, "\",\"username\":\""); db_append_json_escaped(resp, username);
    db_append_str(resp, "\",\"cpu_brand\":\""); db_append_json_escaped(resp, cpu_brand);
    db_append_str(resp, "\",\"cpu_cores\":"); db_append_int64(resp, ncores);
    db_append_str(resp, ",\"ram_total_mb\":"); db_append_uint64(resp, ram_total / (1024*1024));
    db_append_str(resp, ",\"ram_avail_mb\":"); db_append_uint64(resp, ram_avail / (1024*1024));
    db_append_str(resp, ",\"ram_load_pct\":"); db_append_uint64(resp, ram_total > 0 ? (100*(ram_total-ram_avail)/ram_total) : 0);
    db_append_str(resp, ",\"uptime_sec\":"); db_append_uint64(resp, uptime_sec);
    db_append_str(resp, ",\"ac_online\":true,\"battery_pct\":-1");
    db_append_str(resp, "}}");
}

static void handle_log_get(const char *req, int64_t id, DynBuf *resp) {
    uint64_t since_seq = (uint64_t)json_get_int64(req, "since_seq", 0);
    char *min_lvl_str  = json_get_string(req, "min_level");
    bool clear_logs    = json_get_bool(req, "clear", false);
    int32_t min_lvl    = parse_log_level(min_lvl_str);
    free(min_lvl_str);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"logs\":[");

    pthread_mutex_lock(&g_log_lock);
    size_t start_idx = (g_log_head + LOG_RING_CAPACITY - g_log_count) % LOG_RING_CAPACITY;
    bool first = true;
    for (size_t i = 0; i < g_log_count; ++i) {
        size_t idx = (start_idx + i) % LOG_RING_CAPACITY;
        LogEntry *e = &g_log_ring[idx];
        if (e->seq > since_seq && e->level >= min_lvl) {
            if (!first) db_append_char(resp, ',');
            first = false;
            db_append_str(resp, "{\"seq\":"); db_append_uint64(resp, e->seq);
            db_append_str(resp, ",\"uptime_ms\":"); db_append_uint64(resp, e->uptime_ms);
            db_append_str(resp, ",\"level\":\""); db_append_str(resp, log_level_str(e->level));
            db_append_str(resp, "\",\"message\":\""); db_append_json_escaped(resp, e->msg);
            db_append_str(resp, "\"}");
        }
    }
    if (clear_logs) { g_log_head = 0; g_log_count = 0; }
    pthread_mutex_unlock(&g_log_lock);
    db_append_str(resp, "]}}");
}

static void handle_log_clear(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    pthread_mutex_lock(&g_log_lock);
    g_log_head = 0; g_log_count = 0;
    pthread_mutex_unlock(&g_log_lock);
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"cleared\":true}}");
}

static void handle_sys_trim(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    /* Linux: drop page cache */
    int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    bool ok = false;
    if (fd >= 0) { ok = (write(fd, "1\n", 2) == 2); close(fd); }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"trimmed\":"); db_append_str(resp, ok ? "true" : "false");
    db_append_str(resp, ",\"note\":\"Linux: drop_caches page cache flush\"}}");
}

/* =========================================================================
 * MODULE 6: GUI (screenshot via scrot/import, input via xdotool)
 * ========================================================================= */
static void handle_gui_screenshot(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    const char *tmp_file = "/tmp/bridge_screenshot.png";
    char cmd[512];

    /* Try scrot first, then import (ImageMagick), then xwd */
    snprintf(cmd, sizeof(cmd), "scrot %s 2>/dev/null || import -window root %s 2>/dev/null || xwd -root -silent | convert xwd:- %s 2>/dev/null", tmp_file, tmp_file, tmp_file);
    int r = system(cmd);
    if (r != 0 || access(tmp_file, R_OK) != 0) {
        build_error_response(resp, id, RPC_ERR_GUI_FAILED, "Screenshot failed (install scrot or imagemagick)", errno);
        return;
    }

    /* Read the file */
    int fd = open(tmp_file, O_RDONLY);
    if (fd < 0) { unlink(tmp_file); build_error_response(resp, id, RPC_ERR_GUI_FAILED, "Cannot read screenshot file", errno); return; }
    struct stat st; fstat(fd, &st);
    size_t sz = (size_t)st.st_size;
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) { close(fd); unlink(tmp_file); build_error_response(resp, id, RPC_ERR_GUI_FAILED, "OOM", 0); return; }
    read(fd, buf, sz);
    close(fd);
    unlink(tmp_file);

    char *b64 = b64_encode(buf, sz, NULL);
    free(buf);

    /* Best-effort get resolution */
    int w = 0, h = 0;
    {
        FILE *f = popen("xdpyinfo 2>/dev/null | grep dimensions | awk '{print $2}'", "r");
        if (f) { fscanf(f, "%dx%d", &w, &h); pclose(f); }
    }
    if (w <= 0) w = 1920;
    if (h <= 0) h = 1080;

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"width\":"); db_append_int64(resp, w);
    db_append_str(resp, ",\"height\":"); db_append_int64(resp, h);
    db_append_str(resp, ",\"format\":\"png\",\"image_b64\":\"");
    db_append_str(resp, b64 ? b64 : "");
    db_append_str(resp, "\"}}");
    free(b64);
}

static void handle_gui_input(const char *req, int64_t id, DynBuf *resp) {
    char *type   = json_get_string(req, "input_type");
    int64_t x    = json_get_int64(req, "x", 0);
    int64_t y    = json_get_int64(req, "y", 0);
    char *button = json_get_string(req, "button");
    char *text   = json_get_string(req, "text");

    if (!type) { free(button); free(text); build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing input_type", 0); return; }

    char cmd[1024] = "";
    if (_stricmp(type, "mouse_move") == 0) {
        snprintf(cmd, sizeof(cmd), "xdotool mousemove %lld %lld", (long long)x, (long long)y);
    } else if (_stricmp(type, "mouse_click") == 0) {
        const char *btn_s = (button && _stricmp(button, "right") == 0) ? "3" : "1";
        snprintf(cmd, sizeof(cmd), "xdotool mousemove %lld %lld click %s", (long long)x, (long long)y, btn_s);
    } else if (_stricmp(type, "key_vk") == 0) {
        int64_t vk = json_get_int64(req, "vk", 0);
        snprintf(cmd, sizeof(cmd), "xdotool key %lld", (long long)vk);
    } else if (_stricmp(type, "text") == 0 && text) {
        snprintf(cmd, sizeof(cmd), "xdotool type --clearmodifiers '%s'", text);
    }
    free(type); free(button); free(text);

    if (cmd[0]) system(cmd);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"injected\":true}}");
}

/* Linux optimization: clean /tmp, /var/cache/apt, etc. */
static void handle_opt_run(const char *req, int64_t id, DynBuf *resp) {
    bool cleanup_disk = json_get_bool(req, "cleanup_disk", true);
    int files_del = 0; uint64_t bytes_freed = 0;
    if (cleanup_disk) {
        delete_dir_recursive("/tmp", &files_del, &bytes_freed);
        /* apt cache - only if root */
        if (getuid() == 0) system("apt-get clean -q 2>/dev/null || true");
    }
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"services_adjusted\":0,\"registry_keys_updated\":0");
    db_append_str(resp, ",\"temp_files_deleted\":"); db_append_int64(resp, files_del);
    db_append_str(resp, ",\"disk_bytes_freed\":"); db_append_uint64(resp, bytes_freed);
    db_append_str(resp, "}}");
}

/* Kiosk handlers */
static void handle_kiosk_status(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    pthread_mutex_lock(&g_kiosk_sentinel_lock);
    KioskSentinelState st = g_kiosk_sentinel;
    pthread_mutex_unlock(&g_kiosk_sentinel_lock);
    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"enabled\":"); db_append_str(resp, st.enabled ? "true" : "false");
    db_append_str(resp, ",\"target_name\":\""); db_append_json_escaped(resp, st.target_name);
    db_append_str(resp, "\",\"is_running\":"); db_append_str(resp, st.is_running ? "true" : "false");
    db_append_str(resp, ",\"is_hung\":"); db_append_str(resp, st.is_hung ? "true" : "false");
    db_append_str(resp, ",\"auto_relaunch_on_crash\":"); db_append_str(resp, st.auto_relaunch_on_crash ? "true" : "false");
    db_append_str(resp, ",\"restart_count_total\":"); db_append_uint64(resp, st.restart_count_total);
    db_append_str(resp, ",\"restarts_in_window\":"); db_append_uint64(resp, st.restarts_in_window);
    db_append_str(resp, ",\"circuit_breaker_tripped\":"); db_append_str(resp, st.circuit_breaker_tripped ? "true" : "false");
    db_append_str(resp, ",\"backoff_sec\":"); db_append_uint64(resp, st.backoff_sec);
    db_append_str(resp, ",\"last_action\":\""); db_append_json_escaped(resp, st.last_action);
    db_append_str(resp, "\"}}");
}

static void handle_kiosk_restart(const char *req, int64_t id, DynBuf *resp) {
    char *custom_target = json_get_string(req, "target");
    pthread_mutex_lock(&g_kiosk_sentinel_lock);
    if (custom_target && strlen(custom_target) > 0) {
        strncpy(g_kiosk_sentinel.target_name, custom_target, sizeof(g_kiosk_sentinel.target_name) - 1);
    }
    g_kiosk_sentinel.restart_count_total++;
    g_kiosk_sentinel.last_restart_sec = (uint64_t)time(NULL);
    snprintf(g_kiosk_sentinel.last_action, sizeof(g_kiosk_sentinel.last_action), "MANUAL_RESTART_FORCED");
    char target[64]; strncpy(target, g_kiosk_sentinel.target_name, sizeof(target) - 1);
    pthread_mutex_unlock(&g_kiosk_sentinel_lock);
    free(custom_target);

    char kill_cmd[128], launch_cmd[256];
    snprintf(kill_cmd, sizeof(kill_cmd), "pkill -f %s 2>/dev/null", target);
    system(kill_cmd);
    sleep_ms(1500);
    snprintf(launch_cmd, sizeof(launch_cmd), "nohup %s &", target);
    int r = system(launch_cmd);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"success\":"); db_append_str(resp, (r == 0) ? "true" : "false");
    db_append_str(resp, ",\"action\":\"restarted\",\"target\":\"");
    db_append_json_escaped(resp, target);
    db_append_str(resp, "\"}}");
}

static void handle_kiosk_configure(const char *req, int64_t id, DynBuf *resp) {
    bool enabled      = json_get_bool(req, "enabled", true);
    bool auto_relaunch = json_get_bool(req, "auto_relaunch_on_crash", false);
    char *target = json_get_string(req, "target");
    pthread_mutex_lock(&g_kiosk_sentinel_lock);
    g_kiosk_sentinel.enabled = enabled;
    g_kiosk_sentinel.auto_relaunch_on_crash = auto_relaunch;
    if (target && strlen(target) > 0)
        strncpy(g_kiosk_sentinel.target_name, target, sizeof(g_kiosk_sentinel.target_name) - 1);
    pthread_mutex_unlock(&g_kiosk_sentinel_lock);
    free(target);
    handle_kiosk_status(req, id, resp);
}

/* =========================================================================
 * NETWORK FRAMING
 * ========================================================================= */
static bool send_all(int s, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(s, buf + total, len - total, MSG_NOSIGNAL);
        if (n <= 0) return false;
        total += (size_t)n;
    }
    return true;
}

static bool recv_all(int s, char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(s, buf + total, len - total, 0);
        if (n <= 0) return false;
        total += (size_t)n;
    }
    return true;
}

static bool send_frame(int s, const char *json_str) {
    uint32_t len = (uint32_t)strlen(json_str);
    uint32_t net_len = htonl(len);
    pthread_mutex_lock(&g_send_lock);
    bool ok = send_all(s, (const char *)&net_len, 4) && send_all(s, json_str, len);
    pthread_mutex_unlock(&g_send_lock);
    return ok;
}

/* v4 reply path: {"v":4,"body_b64":...,"mac":HMAC(sesskey, body_b64)}. */
static bool send_envelope(int s, const char *inner_json) {
    size_t b64_len = 0;
    char *b64 = b64_encode((const unsigned char *)inner_json, strlen(inner_json), &b64_len);
    if (!b64) return false;
    char mac[65];
    bool ok = compute_hmac_sha256_hex(g_sesskey, 32, (const unsigned char *)b64, b64_len, mac);
    bool sent = false;
    if (ok) {
        size_t cap = b64_len + 128;
        char *env = (char *)malloc(cap);
        if (env) {
            snprintf(env, cap, "{\"v\":4,\"body_b64\":\"%s\",\"mac\":\"%s\"}", b64, mac);
            sent = send_frame(s, env);
            free(env);
        }
    }
    free(b64);
    return sent;
}

static char *recv_frame(int s) {
    uint32_t net_len = 0;
    if (!recv_all(s, (char *)&net_len, 4)) return NULL;
    uint32_t len = ntohl(net_len);
    if (len == 0 || len > MAX_FRAME_SIZE) return NULL;
    char *buf = (char *)malloc(len + 1);
    if (!buf) return NULL;
    if (!recv_all(s, buf, len)) { free(buf); return NULL; }
    buf[len] = '\0';
    return buf;
}

/* =========================================================================
 * CRC32 (Slicing-by-4) - same as Windows version
 * ========================================================================= */
static uint32_t g_crc32_table[4][256];
static volatile int g_crc32_initialized = 0;

static void crc32_init(void) {
    if (__atomic_exchange_n(&g_crc32_initialized, 1, __ATOMIC_SEQ_CST) == 0) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t crc = i;
            for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ ((crc & 1) ? 0xEDB88320U : 0);
            g_crc32_table[0][i] = crc;
        }
        for (uint32_t i = 0; i < 256; i++)
            for (int sl = 1; sl < 4; sl++)
                g_crc32_table[sl][i] = (g_crc32_table[sl-1][i] >> 8) ^ g_crc32_table[0][g_crc32_table[sl-1][i] & 0xFF];
    }
}

static uint32_t crc32_compute(const void *buf, size_t len, uint32_t init) {
    if (!g_crc32_initialized) crc32_init();
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t crc = init ^ 0xFFFFFFFFU;
    while (len >= 4) {
        uint32_t w = *(const uint32_t *)p ^ crc;
        crc = g_crc32_table[3][w & 0xFF] ^ g_crc32_table[2][(w>>8)&0xFF] ^ g_crc32_table[1][(w>>16)&0xFF] ^ g_crc32_table[0][(w>>24)&0xFF];
        p += 4; len -= 4;
    }
    while (len > 0) { crc = (crc >> 8) ^ g_crc32_table[0][(crc ^ *p) & 0xFF]; p++; len--; }
    return crc ^ 0xFFFFFFFFU;
}

/* =========================================================================
 * BINARY TRANSFER SESSION (POSIX fd version)
 * ========================================================================= */
typedef struct {
    volatile int is_active;
    uint32_t file_id;
    int      fd;
    char     file_path[MAX_PATH];
    uint64_t total_written;
    uint64_t expected_size;
    uint64_t start_tick;
    uint64_t last_activity_tick;

    /* Embedded SHA-256 streaming */
    SHA256_CTX *sha256_ctx;
    char        final_sha256[65];
    bool        hash_finalized;

    pthread_mutex_t lock;
} BinaryTransferSession;

static BinaryTransferSession g_bin_session;
static uint8_t g_bin_chunk_buf[BRIDGE_BIN_MAX_CHUNK_SIZE];

static void bin_session_abort_locked(void) {
    if (g_bin_session.sha256_ctx) {
        free(g_bin_session.sha256_ctx);
        g_bin_session.sha256_ctx = NULL;
    }
    if (g_bin_session.fd >= 0) { close(g_bin_session.fd); g_bin_session.fd = -1; }
    g_bin_session.is_active = 0;
}

static bool send_bin_ack(int s, uint32_t file_id, uint32_t status, uint64_t offset, uint32_t bytes_written, uint32_t chunk_crc32) {
    BridgeBinaryFrameTag tag = { BRIDGE_BIN_MAGIC, BIN_FRAME_TYPE_ACK, BRIDGE_BIN_VERSION, 0 };
    BridgeBinaryChunkAck ack = { file_id, status, offset, bytes_written, chunk_crc32 };
    pthread_mutex_lock(&g_send_lock);
    bool ok = send_all(s, (const char *)&tag, sizeof(tag)) && send_all(s, (const char *)&ack, sizeof(ack));
    pthread_mutex_unlock(&g_send_lock);
    if (ok) hud_flow_push(1, "chunk.ack", (uint64_t)(sizeof(tag) + sizeof(ack)));
    if (ok) { pthread_mutex_lock(&g_telemetry_lock); g_bytes_tx += sizeof(tag)+sizeof(ack); g_packets_tx++; pthread_mutex_unlock(&g_telemetry_lock); }
    return ok;
}

static bool handle_bin_chunk(int s, const uint8_t *prefix) {
    if (!prefix) return false;
    const BridgeBinaryFrameTag *tag = (const BridgeBinaryFrameTag *)prefix;
    if (tag->magic != BRIDGE_BIN_MAGIC) { agent_log(LOG_LVL_ERROR, "[BIN] Invalid magic: 0x%02X", tag->magic); return false; }

    if (tag->frame_type == BIN_FRAME_TYPE_ABORT) {
        pthread_mutex_lock(&g_bin_session.lock);
        bin_session_abort_locked();
        pthread_mutex_unlock(&g_bin_session.lock);
        agent_log(LOG_LVL_WARN, "[BIN] Master aborted transfer");
        return true;
    }

    BridgeBinaryChunkHeader hdr;
    if (!recv_all(s, (char *)&hdr, sizeof(BridgeBinaryChunkHeader))) return false;
    if (hdr.length > BRIDGE_BIN_MAX_CHUNK_SIZE) { send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_SIZE, hdr.offset, 0, 0); return false; }
    if (hdr.length > 0 && !recv_all(s, (char *)g_bin_chunk_buf, hdr.length)) return false;

    pthread_mutex_lock(&g_telemetry_lock);
    g_bytes_rx += sizeof(BridgeBinaryChunkHeader) + hdr.length;
    hud_flow_push(0, "file.chunk", (uint64_t)hdr.length);
    g_packets_rx++;
    pthread_mutex_unlock(&g_telemetry_lock);

    uint32_t calc_crc = crc32_compute(g_bin_chunk_buf, hdr.length, 0);
    if (calc_crc != hdr.crc32) {
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_CRC, hdr.offset, 0, calc_crc);
        return true;
    }

    pthread_mutex_lock(&g_bin_session.lock);
    if (!g_bin_session.is_active || g_bin_session.file_id != hdr.file_id || g_bin_session.fd < 0) {
        pthread_mutex_unlock(&g_bin_session.lock);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_SESSION, hdr.offset, 0, calc_crc);
        return true;
    }

    if (lseek(g_bin_session.fd, (off_t)hdr.offset, SEEK_SET) < 0) {
        int e = errno; pthread_mutex_unlock(&g_bin_session.lock);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_IO, hdr.offset, 0, (uint32_t)e);
        return true;
    }

    ssize_t written = 0;
    if (hdr.length > 0) written = write(g_bin_session.fd, g_bin_chunk_buf, hdr.length);
    if (written < 0 || (uint32_t)written != hdr.length) {
        int e = errno; pthread_mutex_unlock(&g_bin_session.lock);
        send_bin_ack(s, hdr.file_id, BIN_ACK_ERR_IO, hdr.offset, (uint32_t)(written > 0 ? written : 0), (uint32_t)e);
        return true;
    }

    if (g_bin_session.sha256_ctx && written > 0)
        sha256_update(g_bin_session.sha256_ctx, g_bin_chunk_buf, (size_t)written);

    g_bin_session.total_written += (uint64_t)written;
    g_bin_session.last_activity_tick = get_tick_ms();

    if (hdr.flags & BIN_FLAG_SYNC) fsync(g_bin_session.fd);

    if (hdr.flags & BIN_FLAG_EOF) {
        if (g_bin_session.sha256_ctx) {
            uint8_t hash[32];
            sha256_final(g_bin_session.sha256_ctx, hash);
            free(g_bin_session.sha256_ctx);
            g_bin_session.sha256_ctx = NULL;
            for (int i = 0; i < 32; ++i) snprintf(g_bin_session.final_sha256 + (i*2), 3, "%02x", hash[i]);
            g_bin_session.final_sha256[64] = '\0';
            g_bin_session.hash_finalized = true;
        }
        close(g_bin_session.fd); g_bin_session.fd = -1;
        agent_log(LOG_LVL_INFO, CLR_GREEN "[BIN] Transfer complete: file_id=%u total=%llu SHA256=%s" CLR_RESET,
                  hdr.file_id, (unsigned long long)g_bin_session.total_written, g_bin_session.final_sha256);
    }
    pthread_mutex_unlock(&g_bin_session.lock);
    return send_bin_ack(s, hdr.file_id, BIN_ACK_OK, hdr.offset, (uint32_t)written, calc_crc);
}

static void handle_fs_bin_open(const char *req, int64_t id, DynBuf *resp) {
    char *path    = json_get_string(req, "path");
    uint32_t file_id = (uint32_t)json_get_int64(req, "file_id", 0);
    bool truncate = json_get_bool(req, "truncate", true);
    int64_t expected_size = json_get_int64(req, "size", 0);
    if (!path || file_id == 0) { free(path); build_error_response(resp, id, RPC_ERR_INVALID_PARAMS, "Missing path or file_id", 0); return; }

    pthread_mutex_lock(&g_bin_session.lock);
    if (g_bin_session.is_active) bin_session_abort_locked();

    int flags = O_WRONLY | O_CREAT | (truncate ? O_TRUNC : 0);
    int fd = open(path, flags, 0644);
    if (fd < 0) {
        int e = errno; pthread_mutex_unlock(&g_bin_session.lock); free(path);
        build_error_response(resp, id, RPC_ERR_FS_FAILED, "open() for binary write failed", e); return;
    }

    SHA256_CTX *ctx = (SHA256_CTX *)malloc(sizeof(SHA256_CTX));
    if (ctx) sha256_init(ctx);

    g_bin_session.is_active = 1;
    g_bin_session.file_id   = file_id;
    g_bin_session.fd        = fd;
    strncpy(g_bin_session.file_path, path, sizeof(g_bin_session.file_path) - 1);
    g_bin_session.total_written   = 0;
    g_bin_session.expected_size   = (uint64_t)expected_size;
    g_bin_session.start_tick      = get_tick_ms();
    g_bin_session.last_activity_tick = g_bin_session.start_tick;
    g_bin_session.sha256_ctx      = ctx;
    g_bin_session.final_sha256[0] = '\0';
    g_bin_session.hash_finalized  = false;
    pthread_mutex_unlock(&g_bin_session.lock);
    free(path);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"status\":\"ready\",\"file_id\":"); db_append_uint64(resp, file_id);
    db_append_str(resp, ",\"chunk_size\":"); db_append_uint64(resp, BRIDGE_BIN_MAX_CHUNK_SIZE);
    db_append_str(resp, "}}");
}

static void handle_fs_bin_status(const char *req, int64_t id, DynBuf *resp) {
    (void)req;
    pthread_mutex_lock(&g_bin_session.lock);
    bool active    = (g_bin_session.is_active != 0);
    uint32_t fid   = g_bin_session.file_id;
    uint64_t total = g_bin_session.total_written;
    bool finalized = g_bin_session.hash_finalized;
    char sha[65];   strncpy(sha, g_bin_session.final_sha256, sizeof(sha));
    pthread_mutex_unlock(&g_bin_session.lock);

    db_append_str(resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(resp, id);
    db_append_str(resp, ",\"result\":{\"active\":"); db_append_str(resp, active ? "true" : "false");
    db_append_str(resp, ",\"file_id\":"); db_append_uint64(resp, fid);
    db_append_str(resp, ",\"total_written\":"); db_append_uint64(resp, total);
    db_append_str(resp, ",\"hash_finalized\":"); db_append_str(resp, finalized ? "true" : "false");
    db_append_str(resp, ",\"sha256\":\""); db_append_str(resp, sha);
    db_append_str(resp, "\"}}");
}

/* =========================================================================
 * RPC DISPATCHER
 * ========================================================================= */
static void dispatch_rpc(const char *req, int sock) {
    /* v4: authentication is session-level (mutual handshake + per-frame HMAC).
       By the time dispatch runs, the envelope MAC is already verified. */
    char *method = json_get_string(req, "method");
    int64_t id   = json_get_int64(req, "id", 0);

    DynBuf resp;
    db_init(&resp, 4096);

    g_rpc_calls_total++;
    uint64_t t0 = get_tick_ms();

    console_log_packet_rx(id, method, "");
    hud_flow_push(0, method ? method : "?", (uint64_t)strlen(req));

    bool trigger_exit = false;

    const char *params = json_find_key(req, "params");
    const char *rpc_req = params ? params : req;

    if (!method) {
        build_error_response(&resp, id, RPC_ERR_INVALID_REQ, "Missing method", 0);
    } else if (strcmp(method, "exec.run") == 0) {
        handle_exec_run(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.hash") == 0) {
        handle_fs_hash(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.read") == 0) {
        handle_fs_read(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.write") == 0) {
        handle_fs_write(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.patch") == 0) {
        handle_fs_patch(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.list") == 0) {
        handle_fs_list(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.delete") == 0) {
        handle_fs_delete(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.mkdir") == 0) {
        handle_fs_mkdir(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.find") == 0) {
        handle_fs_find(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.bin_open") == 0) {
        handle_fs_bin_open(rpc_req, id, &resp);
    } else if (strcmp(method, "fs.bin_status") == 0) {
        handle_fs_bin_status(rpc_req, id, &resp);
    } else if (strcmp(method, "agent.update") == 0) {
        handle_agent_update(rpc_req, id, &resp, &trigger_exit);
    } else if (strcmp(method, "reg.read") == 0 ||
               strcmp(method, "reg.write") == 0 ||
               strcmp(method, "reg.delete") == 0) {
        handle_reg_not_supported(id, &resp);
    } else if (strcmp(method, "svc.op") == 0) {
        handle_svc_op(rpc_req, id, &resp);
    } else if (strcmp(method, "proc.list") == 0) {
        handle_proc_list(rpc_req, id, &resp);
    } else if (strcmp(method, "proc.kill") == 0) {
        handle_proc_kill(rpc_req, id, &resp);
    } else if (strcmp(method, "proc.priority") == 0) {
        handle_proc_priority(rpc_req, id, &resp);
    } else if (strcmp(method, "sys.diag") == 0) {
        handle_sys_diag(rpc_req, id, &resp);
    } else if (strcmp(method, "sys.telemetry_history") == 0) {
        handle_sys_telemetry_history(rpc_req, id, &resp);
    } else if (strcmp(method, "sys.drift_status") == 0) {
        handle_sys_drift_status(rpc_req, id, &resp);
    } else if (strcmp(method, "sys.hardware") == 0) {
        handle_sys_hardware(rpc_req, id, &resp);
    } else if (strcmp(method, "sys.trim") == 0) {
        handle_sys_trim(rpc_req, id, &resp);
    } else if (strcmp(method, "log.get") == 0) {
        handle_log_get(rpc_req, id, &resp);
    } else if (strcmp(method, "log.clear") == 0) {
        handle_log_clear(rpc_req, id, &resp);
    } else if (strcmp(method, "gui.screenshot") == 0) {
        handle_gui_screenshot(rpc_req, id, &resp);
    } else if (strcmp(method, "gui.input") == 0) {
        handle_gui_input(rpc_req, id, &resp);
    } else if (strcmp(method, "opt.run") == 0) {
        handle_opt_run(rpc_req, id, &resp);
    } else if (strcmp(method, "kiosk.status") == 0) {
        handle_kiosk_status(rpc_req, id, &resp);
    } else if (strcmp(method, "kiosk.restart") == 0) {
        handle_kiosk_restart(rpc_req, id, &resp);
    } else if (strcmp(method, "kiosk.configure") == 0) {
        handle_kiosk_configure(rpc_req, id, &resp);
    } else if (strcmp(method, "agent.ping") == 0) {
        db_append_str(&resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(&resp, id);
        db_append_str(&resp, ",\"result\":{\"pong\":true,\"platform\":\"linux\",\"version\":\"" BRIDGE_PROTOCOL_VERSION "\"}}");
    } else if (strcmp(method, "sys.ping") == 0) {
        db_append_str(&resp, "{\"jsonrpc\":\"2.0\",\"id\":"); db_append_int64(&resp, id);
        db_append_str(&resp, ",\"result\":{\"pong\":true,\"version\":\"" BRIDGE_PROTOCOL_VERSION "\",\"uptime_ms\":");
        db_append_uint64(&resp, get_tick_ms() - g_ui_start_tick);
        db_append_str(&resp, "}}");
    } else {
        build_error_response(&resp, id, RPC_ERR_METHOD_NOT_FOUND, "Method not found", 0);
    }

    uint64_t elapsed = get_tick_ms() - t0;
    int err_code = (strstr(resp.data, "\"error\"") != NULL) ? -1 : 0;
    console_log_packet_tx(id, method, err_code, elapsed, resp.len);
    hud_flow_push(1, method ? method : "?", (uint64_t)resp.len);
    free(method);

    send_envelope(sock, resp.data);
    db_free(&resp);

    if (trigger_exit) {
        agent_log(LOG_LVL_INFO, "Self-update complete. Exiting current process...");
        sleep_ms(200);
        __atomic_store_n(&g_running, 0, __ATOMIC_RELAXED);
    }
}

/* =========================================================================
 * v4 HANDSHAKE (mutual HMAC) + CONNECTION LOOP (session-MAC envelopes)
 * ========================================================================= */
static bool is_hex_str(const char *s, size_t len) {
    if (!s) return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return s[len] == '\0';
}

static bool do_handshake(int sock) {
    char agent_nonce[33];
    if (!gen_hex_nonce(agent_nonce)) return false;
    char hello[1024];
    snprintf(hello, sizeof(hello),
             "{\"jsonrpc\":\"2.0\",\"method\":\"agent.hello\",\"params\":{"
             "\"version\":\"" BRIDGE_PROTOCOL_VERSION "\",\"arch\":\"" AGENT_ARCH "\","
             "\"os\":\"" AGENT_OS "\",\"pid\":%lu,\"agent_id\":\"%s\",\"agent_nonce\":\"%s\"}}",
             (unsigned long)getpid(), g_agent_id, agent_nonce);
    if (!send_frame(sock, hello)) return false;
    hud_flow_push(1, "agent.hello", strlen(hello));

    char *ch = recv_frame(sock);
    if (!ch) return false;
    hud_flow_push(0, "auth.challenge", strlen(ch));
    char *ch_method = json_get_string(ch, "method");
    const char *params = json_find_key(ch, "params");
    char *master_nonce = params ? json_get_string(params, "master_nonce") : NULL;
    char *echo_id = params ? json_get_string(params, "agent_id") : NULL;
    bool ok = ch_method && strcmp(ch_method, "auth.challenge") == 0
        && is_hex_str(master_nonce, 32) && echo_id && strcmp(echo_id, g_agent_id) == 0;
    free(ch_method);
    if (!ok) { free(master_nonce); free(echo_id); free(ch); return false; }

    char rab[32 + 32 + 64 + 1], rh[65];
    snprintf(rab, sizeof(rab), "%s%s%s", agent_nonce, master_nonce, g_agent_id);
    ok = compute_hmac_sha256_hex((const unsigned char *)g_psk_token, strlen(g_psk_token),
                                 (const unsigned char *)rab, strlen(rab), rh);
    char aresp[512];
    if (ok) {
        snprintf(aresp, sizeof(aresp),
                 "{\"jsonrpc\":\"2.0\",\"method\":\"auth.response\",\"params\":{"
                 "\"agent_id\":\"%s\",\"hmac\":\"%s\"}}", g_agent_id, rh);
        ok = send_frame(sock, aresp);
        if (ok) hud_flow_push(1, "auth.response", strlen(aresp));
    }
    if (!ok) { free(master_nonce); free(echo_id); free(ch); return false; }

    char *cf = recv_frame(sock);
    if (cf) hud_flow_push(0, "auth.confirm", strlen(cf));
    free(echo_id);
    free(ch);
    if (!cf) { free(master_nonce); return false; }
    char *cf_method = json_get_string(cf, "method");
    char *peer_h = json_get_string(cf, "hmac");
    char rab2[32 + 32 + 64 + 1], expect[65];
    snprintf(rab2, sizeof(rab2), "%s%s%s", master_nonce, agent_nonce, g_agent_id);
    ok = cf_method && strcmp(cf_method, "auth.confirm") == 0 && is_hex_str(peer_h, 64)
        && compute_hmac_sha256_hex((const unsigned char *)g_psk_token, strlen(g_psk_token),
                                   (const unsigned char *)rab2, strlen(rab2), expect)
        && constant_time_eq(peer_h, expect);
    free(cf_method);
    free(peer_h);
    free(cf);
    if (!ok) { free(master_nonce); return false; }

    /* sesskey = SHA256(psk || agent_nonce || master_nonce) */
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (const unsigned char *)g_psk_token, strlen(g_psk_token));
    sha256_update(&ctx, (const unsigned char *)agent_nonce, 32);
    sha256_update(&ctx, (const unsigned char *)master_nonce, 32);
    sha256_final(&ctx, g_sesskey);
    free(master_nonce);
    g_have_sess = true;
    agent_log(LOG_LVL_INFO, "Mutual auth complete as '%s'; session key derived.", g_agent_id);
    return true;
}

static void connection_loop(int sock) {
    agent_log(LOG_LVL_INFO, CLR_GREEN "Connected to master %s:%u" CLR_RESET, g_master_host, g_master_port);
    g_have_sess = false;
    if (!do_handshake(sock)) {
        agent_log(LOG_LVL_ERROR, "v4 handshake failed; dropping connection.");
        return;
    }

    while (__atomic_load_n(&g_running, __ATOMIC_RELAXED)) {
        /* Peek first 4 bytes to distinguish JSON-RPC vs Binary frame */
        uint8_t prefix[4];
        ssize_t pn = recv(sock, prefix, 4, MSG_PEEK);
        if (pn < 4) break;

        if (prefix[0] == BRIDGE_BIN_MAGIC) {
            /* Binary chunk frame: read 4 tag bytes then handle */
            uint8_t tag_buf[4];
            if (recv_all(sock, (char *)tag_buf, 4)) {
                g_bytes_rx += 4;
                handle_bin_chunk(sock, tag_buf);
            } else {
                break;
            }
        } else {
            /* v4 envelope: {"v":4,"body_b64":"...","mac":"..."} */
            char *frame = recv_frame(sock);
            if (!frame) break;
            g_bytes_rx += strlen(frame) + 4;
            bool good = false;
            char *inner = NULL;
            if (json_get_int64(frame, "v", 0) == 4) {
                char *b64 = json_get_string(frame, "body_b64");
                char *mac = json_get_string(frame, "mac");
                char expect[65];
                if (b64 && is_hex_str(mac, 64)
                    && compute_hmac_sha256_hex(g_sesskey, 32,
                                               (const unsigned char *)b64, strlen(b64), expect)
                    && constant_time_eq(mac, expect)) {
                    size_t inner_len = 0;
                    unsigned char *raw = b64_decode(b64, &inner_len);
                    if (raw && inner_len > 0 && inner_len <= MAX_FRAME_SIZE) {
                        inner = (char *)malloc(inner_len + 1);
                        if (inner) {
                            memcpy(inner, raw, inner_len);
                            inner[inner_len] = '\0';
                            good = true;
                        }
                    }
                    free(raw);
                } else {
                    agent_log(LOG_LVL_ERROR, "Bad session MAC; dropping connection.");
                }
                free(b64);
                free(mac);
            }
            free(frame);
            if (!good) { free(inner); break; }
            dispatch_rpc(inner, sock);
            free(inner);
        }
    }
    g_have_sess = false;
}

/* =========================================================================
 * CONNECT TO MASTER (reconnect loop)
 * ========================================================================= */
static int connect_to_master(void) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned int)g_master_port);

    if (getaddrinfo(g_master_host, port_str, &hints, &res) != 0) {
        agent_log(LOG_LVL_ERROR, "getaddrinfo failed for %s", g_master_host);
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, 0);
    if (sock < 0) { freeaddrinfo(res); return -1; }

    /* TCP keepalive */
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
    int keepidle = 30, keepintvl = 5, keepcnt = 3;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE,  &keepidle,  sizeof(keepidle));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT,   &keepcnt,   sizeof(keepcnt));
    /* TCP_NODELAY */
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        close(sock);
        return -1;
    }
    freeaddrinfo(res);
    return sock;
}

/* =========================================================================
 * SELFTEST
 * ========================================================================= */
static int run_selftest(void) {
    /* MUST match the Windows agent byte-for-byte (cross-platform crypto proof) */
    char test_hex[65] = "";
    if (!compute_buffer_sha256((const unsigned char *)"selftest", 8, test_hex)) {
        printf("[SELFTEST] FAIL - SHA256 error\n");
        return 102;
    }
    /* RFC 4231 test case 1: HMAC-SHA256(key=0x0b*20, "Hi There") */
    unsigned char rfc_key[20];
    memset(rfc_key, 0x0b, sizeof(rfc_key));
    char hmac_hex[65] = "";
    if (!compute_hmac_sha256_hex(rfc_key, sizeof(rfc_key),
                                 (const unsigned char *)"Hi There", 8, hmac_hex)
        || strcmp(hmac_hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") != 0) {
        printf("[SELFTEST] FAIL - HMAC-SHA256 vector mismatch: %s\n", hmac_hex);
        return 103;
    }
    /* Base64 round-trip */
    size_t b64_len = 0;
    char *enc = b64_encode((const unsigned char *)"Hello", 5, &b64_len);
    if (!enc || strcmp(enc, "SGVsbG8=") != 0) { free(enc); return 1; }
    free(enc);
    printf("[SELFTEST] OK - SHA256=%s HMAC=%s\n", test_hex, hmac_hex);
    return 0;
}

/* =========================================================================
 * SIGNAL HANDLER
 * ========================================================================= */
static void signal_handler(int sig) {
    (void)sig;
    __atomic_store_n(&g_running, 0, __ATOMIC_RELAXED);
}

/* =========================================================================
 * MAIN
 * ========================================================================= */

/* =========================================================================
 * LIVE HUD (TTY only): the shared voice orb + live data flows in a band at
 * the top of the terminal, logs scroll underneath. Outgoing messages leave
 * the sphere as amber comets towards the edges, incoming ones fly in as
 * emerald comets, each with a short label. Keys: F view flows, R reconnect.
 * ========================================================================= */
#define ORB_HUD_ROWS  12
#define ORB_HUD_TOP    1
#define ORB_LOG_TOP   (ORB_HUD_TOP + ORB_HUD_ROWS + 1)   /* first log line */
#define HUD_FLOW_OUT  1
#define HUD_FLOW_IN   0

typedef struct { uint64_t seq; int dir; uint64_t bytes; char label[40]; } HudFlow;
#define HUD_FLOW_CAP 128
static HudFlow g_hud_flows[HUD_FLOW_CAP];
static uint64_t g_hud_flow_seq = 0;
static pthread_mutex_t g_hud_flow_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_session_fd = -1;
static volatile int g_hud_show_flows = 1;
static struct termios g_hud_tio_saved;
static volatile int g_hud_tio_raw = 0;

static void hud_flow_push(int dir, const char *label, uint64_t bytes) {
    pthread_mutex_lock(&g_hud_flow_lock);
    uint64_t sq = ++g_hud_flow_seq;
    HudFlow *f = &g_hud_flows[sq % HUD_FLOW_CAP];
    f->seq = sq; f->dir = dir; f->bytes = bytes;
    snprintf(f->label, sizeof(f->label), "%s", label ? label : "?");
    pthread_mutex_unlock(&g_hud_flow_lock);
}

typedef struct { int alive, dir, labeled; float t, life, size, ax, ay, bx, by, cx, cy; float tr[10][2]; int tn; char label[48]; } HudComet;
#define HUD_PMAX 40
static HudComet g_hcom[HUD_PMAX];
static hud_canvas_t g_hud;
static uint64_t g_hud_seen = 0, g_hud_msgs[2], g_hud_rate_acc[2];
static double g_hud_rate[2];
static float g_hud_act[2];
static uint64_t g_orb_prev_rpc = 0;
static char g_hud_toast[64]; static uint64_t g_hud_toast_until = 0;

static float hud_frand(void) { return (float)rand() / (float)RAND_MAX; }
static void hud_fmt_bytes(uint64_t n, char *o, size_t c) {
    if (n < 1024) { snprintf(o, c, "%lluB", (unsigned long long)n); return; }
    double v = n / 1024.0; const char *u = "KB";
    if (v >= 1024) { v /= 1024; u = "MB"; }
    snprintf(o, c, v < 10 ? "%.1f%s" : "%.0f%s", v, u);
}

static void hud_spawn(int dir, const char *label, uint64_t bytes, int W, int H, float ocx, float ocy, float R, int *budget) {
    g_hud_msgs[dir]++; g_hud_rate_acc[dir] += bytes;
    g_hud_act[dir] = fminf(1.f, g_hud_act[dir] + 0.35f);
    orb_bump(&g_orb, dir == HUD_FLOW_OUT ? 0.30f : 0.20f);
    if (!g_hud_show_flows || *budget <= 0) return;
    (*budget)--;
    HudComet *c = NULL; int labeled = 0;
    for (int i = 0; i < HUD_PMAX; i++) { if (g_hcom[i].alive && g_hcom[i].labeled) labeled++; if (!c && !g_hcom[i].alive) c = &g_hcom[i]; }
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->alive = 1; c->dir = dir;
    float ang = hud_frand() * 6.2831853f, ux = cosf(ang), uy = sinf(ang);
    /* distance to leave the band in that direction, plus a margin */
    float tx = ux > 0 ? (W + 3 - ocx) / ux : ux < 0 ? (-3 - ocx) / ux : 1e9f;
    float ty = uy > 0 ? (H + 3 - ocy) / uy : uy < 0 ? (-3 - ocy) / uy : 1e9f;
    float reach = fminf(tx, ty);
    float sx = ocx + ux * R, sy = ocy + uy * R, ox = ocx + ux * reach, oy = ocy + uy * reach;
    if (dir == HUD_FLOW_OUT) { c->ax = sx; c->ay = sy; c->bx = ox; c->by = oy; } else { c->ax = ox; c->ay = oy; c->bx = sx; c->by = sy; }
    float dx = c->bx - c->ax, dy = c->by - c->ay, L = sqrtf(dx * dx + dy * dy) + 1e-3f;
    float bend = (0.08f + 0.12f * hud_frand()) * L * (dir == HUD_FLOW_OUT ? 1.f : -1.f);
    c->cx = (c->ax + c->bx) * 0.5f - dy / L * bend; c->cy = (c->ay + c->by) * 0.5f + dx / L * bend;
    c->life = fminf(2.6f, fmaxf(0.9f, L / 55.f)) + hud_frand() * 0.3f;
    c->labeled = labeled < 5 && hud_frand() < 0.85f;
    c->size = c->labeled ? 0.9f : 0.6f;
    if (c->labeled) {
        char sz[16] = ""; if (bytes) hud_fmt_bytes(bytes, sz, sizeof(sz));
        snprintf(c->label, sizeof(c->label), "%s %.20s%s%s", dir == HUD_FLOW_OUT ? "\xE2\x86\x91" : "\xE2\x86\x93",
                 label ? label : "?", sz[0] ? " " : "", sz);
    }
}

static void hud_comets_step_draw(orb_surface *s, float dt) {
    for (int i = 0; i < HUD_PMAX; i++) {
        HudComet *c = &g_hcom[i];
        if (!c->alive) continue;
        c->t += dt / c->life;
        if (c->t >= 1.f) { if (c->dir == HUD_FLOW_IN) orb_bump(&g_orb, 0.45f); c->alive = 0; continue; }
        float u = c->dir == HUD_FLOW_OUT ? powf(c->t, 1.5f) : 1.f - powf(1.f - c->t, 1.6f);
        float a = (1 - u) * (1 - u), b = 2 * (1 - u) * u, d = u * u;
        float x = a * c->ax + b * c->cx + d * c->bx, y = a * c->ay + b * c->cy + d * c->by;
        int n = c->tn < 10 ? c->tn + 1 : 10;
        for (int k = n - 1; k > 0; k--) { c->tr[k][0] = c->tr[k - 1][0]; c->tr[k][1] = c->tr[k - 1][1]; }
        c->tr[0][0] = x; c->tr[0][1] = y; c->tn = n;
        float col[3], hot[3];
        if (c->dir == HUD_FLOW_OUT) { col[0] = 255; col[1] = 176; col[2] = 64; } else { col[0] = 52; col[1] = 255; col[2] = 170; }
        for (int k = 0; k < 3; k++) hot[k] = col[k] + (255.f - col[k]) * 0.6f;
        float fade = fminf(1.f, c->t / 0.08f) * fminf(1.f, (1.f - c->t) / 0.12f);
        for (int k = c->tn - 1; k >= 1; k--) {
            float x0 = c->tr[k][0], y0 = c->tr[k][1], x1 = c->tr[k - 1][0], y1 = c->tr[k - 1][1];
            int steps = (int)(sqrtf((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0)) / 0.8f) + 1;
            if (steps > 30) steps = 30;
            for (int j = 0; j < steps; j++) {
                float uu = (float)j / steps, f = 1.f - ((float)k - uu) / 10.f;
                orb__splat(s, x0 + (x1 - x0) * uu, y0 + (y1 - y0) * uu, 0.5f, col, 0.30f * f * f * fade);
            }
        }
        orb__splat(s, x, y, 1.6f, col, 0.30f * fade);
        orb__splat(s, x, y, c->size, hot, 0.95f * fade);
    }
}

static void hud_labels(float ocx, float ocy, float R) {
    for (int i = 0; i < HUD_PMAX; i++) {
        HudComet *c = &g_hcom[i];
        if (!c->alive || !c->labeled || c->tn < 2) continue;
        float x = c->tr[0][0], y = c->tr[0][1];
        if ((x - ocx) * (x - ocx) + (y - ocy) * (y - ocy) < (R * 1.9f) * (R * 1.9f)) continue;
        float vis = c->dir == HUD_FLOW_IN ? fminf(1.f, (1.f - c->t) / 0.35f) : fminf(1.f, (1.f - c->t) / 0.4f);
        if (vis < 0.35f) continue;
        int row = (int)(y / 2.f), col = (int)x + 2, len = hud_strcells(c->label);
        if (!hud_free(&g_hud, row, col - 1, len + 3)) col = (int)x - len - 2;     /* keep a blank cell on both sides */
        if (!hud_free(&g_hud, row, col - 1, len + 3)) continue;
        hud_text(&g_hud, row, col, c->label, c->dir == HUD_FLOW_OUT ? 0xFFC46Bu : 0x5CFFC0u, 0x0A0D1Au, 0);
    }
}

static void hud_render_tty(float dt) {
    if (!g_vt_enabled) return;
    static char out[400000];
    static uint64_t last_full = 0;
    struct winsize ws; int cols = 100;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 20) cols = ws.ws_col;
    if (cols > HUD_MAX_COLS) cols = HUD_MAX_COLS;
    int connected = __atomic_load_n(&g_link_connected, __ATOMIC_RELAXED), live = connected && g_have_sess;

    hud_begin(&g_hud, cols, ORB_HUD_ROWS);
    int W = cols, H = ORB_HUD_ROWS * 2;
    float ocx = 15.f, ocy = H * 0.5f, R = 7.6f;

    /* drain flows -> comets */
    int budget = 4;
    HudFlow batch[HUD_FLOW_CAP]; int nb = 0;
    pthread_mutex_lock(&g_hud_flow_lock);
    uint64_t first = g_hud_seen + 1;
    if (g_hud_flow_seq >= HUD_FLOW_CAP && first < g_hud_flow_seq - HUD_FLOW_CAP + 1) first = g_hud_flow_seq - HUD_FLOW_CAP + 1;
    for (uint64_t q = first; q <= g_hud_flow_seq; q++) { HudFlow *f = &g_hud_flows[q % HUD_FLOW_CAP]; if (f->seq == q) batch[nb++] = *f; }
    g_hud_seen = g_hud_flow_seq;
    pthread_mutex_unlock(&g_hud_flow_lock);
    for (int i = 0; i < nb; i++) hud_spawn(batch[i].dir, batch[i].label, batch[i].bytes, W, H, ocx, ocy, R, &budget);

    static uint64_t rate_t = 0; uint64_t now = get_tick_ms();
    if (!rate_t) rate_t = now;
    if (now - rate_t >= 500) {
        double k = 1000.0 / (double)(now - rate_t);
        for (int d = 0; d < 2; d++) { g_hud_rate[d] = g_hud_rate[d] * 0.4 + g_hud_rate_acc[d] * k * 0.6; g_hud_rate_acc[d] = 0; }
        rate_t = now;
    }
    for (int d = 0; d < 2; d++) g_hud_act[d] *= powf(0.25f, dt);
    if (g_orb_prev_rpc && g_rpc_calls_total > g_orb_prev_rpc) orb_bump(&g_orb, 0.4f);
    g_orb_prev_rpc = g_rpc_calls_total;

    int out_b = g_hud_act[HUD_FLOW_OUT] > 0.2f, in_b = g_hud_act[HUD_FLOW_IN] > 0.2f;
    int mood = !connected ? ORB_OFFLINE : !live ? ORB_THINK : out_b ? ORB_SPEAK : in_b ? ORB_LISTEN : ORB_IDLE;
    const char *word = !connected ? "OFFLINE" : !live ? "CONNECTING" : (out_b && in_b) ? "EXCHANGING" : out_b ? "SENDING" : in_b ? "RECEIVING" : "LINKED";
    uint32_t wcol = !connected ? 0x8A94B6u : !live ? 0xB388FFu : out_b ? 0xFFB040u : in_b ? 0x34FFAAu : 0x00E5FFu;
    if (g_orb.state != mood && (mood == ORB_OFFLINE || mood == ORB_THINK || g_orb.state == ORB_OFFLINE || g_orb.state == ORB_THINK)) orb_set_state(&g_orb, mood);
    else g_orb.state = mood;
    float lvl = fmaxf(g_hud_act[0], g_hud_act[1]);
    if (lvl > 0.02f) orb_level(&g_orb, lvl * 0.85f);
    orb_step(&g_orb, dt);

    orb_surface s = hud_surface(&g_hud);
    orb_render(&g_orb, &s, ocx, ocy, R, 1.0f);
    hud_comets_step_draw(&s, dt);

    /* text panel */
    int px = 32;
    char line[200], up[24], rx[16], tx[16], ro[16], ri[16];
    uint64_t upt = (now - g_ui_start_tick) / 1000ULL;
    if (upt < 5400) snprintf(up, sizeof(up), "%llum%02llus", (unsigned long long)(upt / 60), (unsigned long long)(upt % 60));
    else snprintf(up, sizeof(up), "%lluh%02llum", (unsigned long long)(upt / 3600), (unsigned long long)((upt / 60) % 60));
    hud_text(&g_hud, 1, px, "BRIDGE AGENT", 0x00E5FFu, 0, 1);
    snprintf(line, sizeof(line), "v%s \xC2\xB7 %s \xC2\xB7 Linux", BRIDGE_PROTOCOL_VERSION, AGENT_ARCH);
    hud_text(&g_hud, 1, px + 14, line, 0x8A94B6u, 0, 0);
    snprintf(line, sizeof(line), "\xE2\x97\x8F %s", word);
    hud_text(&g_hud, 2, px, line, wcol, 0, 1);
    snprintf(line, sizeof(line), "%s:%u", g_master_host, (unsigned)g_master_port);
    hud_text(&g_hud, 2, px + hud_strcells(word) + 4, line, 0x8A94B6u, 0, 0);
    snprintf(line, sizeof(line), "agent  %s", g_agent_id);                     hud_text(&g_hud, 4, px, line, 0xECF0FFu, 0, 0);
    snprintf(line, sizeof(line), "uptime %s   rpc %llu", up, (unsigned long long)g_rpc_calls_total);
    hud_text(&g_hud, 5, px, line, 0xECF0FFu, 0, 0);
    hud_fmt_bytes(g_bytes_rx, rx, sizeof(rx)); hud_fmt_bytes(g_bytes_tx, tx, sizeof(tx));
    snprintf(line, sizeof(line), "net    \xE2\x86\x93 %s  \xE2\x86\x91 %s   cpu %.0f%%  ram %lluMB", rx, tx, g_cpu_load_pct,
             (unsigned long long)(g_ram_avail_bytes / (1024 * 1024)));
    hud_text(&g_hud, 6, px, line, 0xECF0FFu, 0, 0);
    hud_fmt_bytes((uint64_t)g_hud_rate[HUD_FLOW_OUT], ro, sizeof(ro)); hud_fmt_bytes((uint64_t)g_hud_rate[HUD_FLOW_IN], ri, sizeof(ri));
    snprintf(line, sizeof(line), " \xE2\x86\x91 OUT %llu msgs \xC2\xB7 %s/s ", (unsigned long long)g_hud_msgs[HUD_FLOW_OUT], ro);
    hud_text(&g_hud, 8, px, line, 0xFFB040u, 0x2A1C08u, 1);
    int ow = hud_strcells(line) + 1;
    snprintf(line, sizeof(line), " \xE2\x86\x93 IN %llu msgs \xC2\xB7 %s/s ", (unsigned long long)g_hud_msgs[HUD_FLOW_IN], ri);
    hud_text(&g_hud, 8, px + ow, line, 0x34FFAAu, 0x06261Au, 1);
    /* key caps */
    hud_text(&g_hud, 10, px, " F ", 0x05070Fu, g_hud_show_flows ? 0xFFB040u : 0x8A94B6u, 1);
    hud_text(&g_hud, 10, px + 4, g_hud_show_flows ? "View flows: on " : "View flows: off", g_hud_show_flows ? 0xFFC46Bu : 0x8A94B6u, 0, 0);
    hud_text(&g_hud, 10, px + 21, " R ", 0x05070Fu, 0x00E5FFu, 1);
    hud_text(&g_hud, 10, px + 25, "Reconnect", 0x9BE9FFu, 0, 0);
    hud_text(&g_hud, 10, px + 36, " Ctrl+C ", 0x05070Fu, 0xFF8A8Au, 1);
    hud_text(&g_hud, 10, px + 45, "Quit", 0xFFB3B3u, 0, 0);
    if (now < g_hud_toast_until) hud_text(&g_hud, 11, px, g_hud_toast, 0xECF0FFu, 0, 0);
    hud_labels(ocx, ocy, R);

    int force = (now - last_full) > 5000;          /* repaint everything now and then (Ctrl+L, resizes) */
    if (force) last_full = now;
    size_t n = hud_flush(&g_hud, out, sizeof(out), ORB_HUD_TOP, 1, force);
    if (!n) return;
    pthread_mutex_lock(&g_console_lock);
    fputs("\0337", stdout);                        /* save cursor (DECSC) */
    fwrite(out, 1, n, stdout);
    fputs("\0338", stdout);                        /* restore -> back inside the log scroll region */
    fflush(stdout);
    pthread_mutex_unlock(&g_console_lock);
}

static void hud_toast(const char *msg) { snprintf(g_hud_toast, sizeof(g_hud_toast), "%s", msg); g_hud_toast_until = get_tick_ms() + 2500; }

static void hud_tty_restore(void) {
    if (g_hud_tio_raw) { tcsetattr(STDIN_FILENO, TCSANOW, &g_hud_tio_saved); g_hud_tio_raw = 0; }
}

/* keys: F toggles the flow view, R drops the session (the reconnect loop dials again) */
static void *HudKeysThread(void *arg) {
    (void)arg;
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &g_hud_tio_saved) != 0) return NULL;
    struct termios raw = g_hud_tio_saved;
    raw.c_lflag &= (tcflag_t)~(ICANON | ECHO);      /* ISIG kept: Ctrl+C still stops the agent */
    raw.c_cc[VMIN] = 0; raw.c_cc[VTIME] = 2;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return NULL;
    g_hud_tio_raw = 1;
    atexit(hud_tty_restore);
    while (__atomic_load_n(&g_running, __ATOMIC_RELAXED)) {
        char ch;
        if (read(STDIN_FILENO, &ch, 1) != 1) continue;
        if (ch == 'f' || ch == 'F') {
            g_hud_show_flows = !g_hud_show_flows;
            if (!g_hud_show_flows) for (int i = 0; i < HUD_PMAX; i++) g_hcom[i].alive = 0;
            hud_toast(g_hud_show_flows ? "Flows visible" : "Flows hidden");
        } else if (ch == 'r' || ch == 'R') {
            int fd = __atomic_load_n(&g_session_fd, __ATOMIC_RELAXED);
            if (fd >= 0) { shutdown(fd, SHUT_RDWR); hud_toast("Reconnecting..."); agent_log(LOG_LVL_INFO, "Reconnect requested from the HUD."); }
            else hud_toast("Not connected");
        }
    }
    hud_tty_restore();
    return NULL;
}

static void *OrbThread(void *arg) {
    (void)arg;
    srand((unsigned)get_tick_ms());
    orb_init(&g_orb);
    g_orb.particle_gain = 0.20f; g_orb.glow_gain = 0.55f;   /* ~800 particles in a 15-px sphere: keep it from saturating */
    uint64_t last = get_tick_ms();
    while (__atomic_load_n(&g_running, __ATOMIC_RELAXED)) {
        uint64_t now = get_tick_ms();
        float dt = (now - last) / 1000.f; last = now;
        if (dt > 0.1f) dt = 0.1f;
        hud_render_tty(dt);
        sleep_ms(80);
    }
    return NULL;
}

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
    char path[4096];
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (n > 0) {
        path[n] = '\0';
        char *sep = strrchr(path, '/');
        if (sep) {
            *sep = '\0';
            char full[4224];
            snprintf(full, sizeof(full), "%s/agent.provision", path);
            if (provision__load_file(full)) return;
        }
    }
    provision__load_file("agent.provision"); /* cwd fallback */
}

int main(int argc, char *argv[]) {
    provision_load(); /* zero-config sidecar first; CLI/env override below */
    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i + 1 < argc)
            strncpy(g_master_host, argv[++i], sizeof(g_master_host) - 1);
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            g_master_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--token") == 0 && i + 1 < argc)
            strncpy(g_psk_token, argv[++i], sizeof(g_psk_token) - 1);
        else if (strcmp(argv[i], "--agent-id") == 0 && i + 1 < argc)
            strncpy(g_agent_id, argv[++i], sizeof(g_agent_id) - 1);
        else if (strcmp(argv[i], "--headless") == 0 || strcmp(argv[i], "--no-gui") == 0)
            ; /* accepted for CLI parity with the Windows agent (linux is always headless) */
        else if (strcmp(argv[i], "--upgraded-from") == 0 && i + 1 < argc)
            g_upgraded_from_pid = (pid_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--selftest") == 0) {
            int r = run_selftest();
            return r;
        }
    }

    if (!g_psk_token[0]) {
        const char *env = getenv("BRIDGE_PSK");
        if (env) strncpy(g_psk_token, env, sizeof(g_psk_token) - 1);
    }
    if (!g_psk_token[0]) {
        fprintf(stderr, "agent: PSK required (--token <psk>, BRIDGE_PSK env or agent.provision sidecar). Refusing to run unauthenticated.\n");
        return 2;
    }
    if (!g_agent_id[0]) {
        default_agent_id(g_agent_id);
    }
    if (!valid_agent_id(g_agent_id)) {
        fprintf(stderr, "agent: bad --agent-id (1-32 chars: A-Za-z0-9_-, starts alnum).\n");
        return 2;
    }

    /* Signal handlers */
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* VT100 terminal setup */
    if (isatty(STDOUT_FILENO)) {
        g_vt_enabled = true;
        printf("\033[2J\033[H"); /* clear */
        printf("\033[%d;999r", ORB_LOG_TOP); /* logs scroll below the orb HUD */
        printf("\033[%d;1H", ORB_LOG_TOP);
        fflush(stdout);
    } else {
        g_vt_enabled = false;
    }

    g_ui_start_tick = get_tick_ms();

    /* Init subsystems */
    crc32_init();
    init_gpu_telemetry();
    memset(g_telemetry_ring, 0, sizeof(*g_telemetry_ring));
    g_bin_session.fd = -1;
    pthread_mutex_init(&g_bin_session.lock, NULL);

    /* Start telemetry thread */
    pthread_t telemetry_thread;
    pthread_create(&telemetry_thread, NULL, TelemetryThread, NULL);
    pthread_detach(telemetry_thread);

    if (g_vt_enabled) {
        pthread_t orb_thread, keys_thread;
        if (pthread_create(&orb_thread, NULL, OrbThread, NULL) == 0) pthread_detach(orb_thread);
        if (pthread_create(&keys_thread, NULL, HudKeysThread, NULL) == 0) pthread_detach(keys_thread);
    }

    agent_log(LOG_LVL_INFO, CLR_CYAN "BridgeLinux Agent v" BRIDGE_PROTOCOL_VERSION CLR_RESET
              " \xE2\x80\x94 PID %d \xE2\x80\x94 target %s:%u", (int)getpid(), g_master_host, g_master_port);
    if (g_upgraded_from_pid > 0)
        agent_log(LOG_LVL_INFO, "Upgraded from PID %d", (int)g_upgraded_from_pid);

    /* Reconnect loop */
    int backoff_ms = 1000;
    while (__atomic_load_n(&g_running, __ATOMIC_RELAXED)) {
        agent_log(LOG_LVL_INFO, "Connecting to %s:%u...", g_master_host, g_master_port);
        int sock = connect_to_master();
        if (sock < 0) {
            agent_log(LOG_LVL_WARN, "Connection failed. Retry in %dms...", backoff_ms);
            sleep_ms(backoff_ms);
            if (backoff_ms < 30000) backoff_ms = (backoff_ms * 3) / 2;
            continue;
        }
        backoff_ms = 1000;
        __atomic_store_n(&g_link_connected, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&g_session_fd, sock, __ATOMIC_RELAXED);
        connection_loop(sock);
        __atomic_store_n(&g_session_fd, -1, __ATOMIC_RELAXED);
        __atomic_store_n(&g_link_connected, 0, __ATOMIC_RELAXED);
        close(sock);
        if (__atomic_load_n(&g_running, __ATOMIC_RELAXED))
            agent_log(LOG_LVL_WARN, "Disconnected. Retrying in %dms...", backoff_ms);
    }

    /* Cleanup */
    cleanup_gpu_telemetry();
    hud_tty_restore();
    if (g_vt_enabled) { printf("\033[r\033[0m\033[2J\033[H\033[?25h"); fflush(stdout); }
    agent_log(LOG_LVL_INFO, "Agent stopped.");
    return 0;
}
