/* v4 client core: framing, mutual handshake, session-MAC envelopes, serve loop.
 * Minimal hand-rolled JSON for the fixed v4 shapes (writer + key scanner). */
#include "obproto.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- tiny JSON helpers ---------- */

static void json_escape(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (; *in && o + 6 < cap; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n') {
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c == '\r') {
            out[o++] = '\\';
            out[o++] = 'r';
        } else if (c == '\t') {
            out[o++] = '\\';
            out[o++] = 't';
        } else if (c < 0x20) {
            o += (size_t)snprintf(out + o, cap - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = 0;
}

/* Find "key" at any depth, return pointer to value start (past ':' + spaces). */
static const char *json_find(const char *js, const char *key) {
    char pat[64];
    const char *p;
    size_t kl = strlen(key);
    if (kl + 3 >= sizeof(pat))
        return NULL;
    pat[0] = '"';
    memcpy(pat + 1, key, kl);
    pat[kl + 1] = '"';
    pat[kl + 2] = 0;
    p = strstr(js, pat);
    if (!p)
        return NULL;
    p += kl + 2;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    if (*p != ':')
        return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return p;
}

/* Parse a JSON string value with escapes into out. Returns 0 on success. */
static int json_string(const char *v, char *out, size_t cap) {
    size_t o = 0;
    if (*v != '"')
        return -1;
    v++;
    while (*v && *v != '"' && o + 1 < cap) {
        if (*v == '\\') {
            v++;
            if (*v == 'n') out[o++] = '\n';
            else if (*v == 'r') out[o++] = '\r';
            else if (*v == 't') out[o++] = '\t';
            else if (*v == 'u') {
                /* \uXXXX: keep ASCII subset, else '?' */
                unsigned u = 0;
                int k;
                for (k = 0; k < 4; k++) {
                    char c = v[1 + k];
                    unsigned d;
                    if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
                    else break;
                    u = (u << 4) | d;
                }
                if (k == 4) {
                    out[o++] = (u < 128) ? (char)u : '?';
                    v += 4;
                } else if (*v) {
                    out[o++] = *v;
                }
            } else if (*v) {
                out[o++] = *v;
            }
            if (*v)
                v++;
        } else {
            out[o++] = *v++;
        }
    }
    if (*v != '"')
        return -1;
    out[o] = 0;
    return 0;
}

static int json_get_str(const char *js, const char *key, char *out, size_t cap) {
    const char *v = json_find(js, key);
    if (!v)
        return -1;
    return json_string(v, out, cap);
}

/* Copy a raw JSON scalar token (number/literal) for id passthrough. */
static int json_get_raw(const char *js, const char *key, char *out, size_t cap) {
    const char *v = json_find(js, key);
    size_t o = 0;
    if (!v)
        return -1;
    if (*v == '"')
        return json_string(v, out, cap) == 0 ? 1 : -1; /* 1 = was string */
    while (*v && *v != ',' && *v != '}' && *v != ']' && *v != ' ' && *v != '\t' &&
           *v != '\r' && *v != '\n' && o + 1 < cap)
        out[o++] = *v++;
    out[o] = 0;
    return o ? 0 : -1;
}

/* ---------- framing ---------- */

static int read_full(ob_agent_t *a, unsigned char *buf, int len, int timeout_ms) {
    int got = 0;
    while (got < len) {
        int n = a->read(a->ctx, buf + got, len - got, timeout_ms);
        if (n < 0)
            return -1;
        if (n == 0)
            return -2; /* timeout */
        got += n;
    }
    return got;
}

static int write_full(ob_agent_t *a, const unsigned char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = a->write(a->ctx, buf + sent, len - sent);
        if (n <= 0)
            return -1;
        sent += n;
    }
    return sent;
}

static int send_obj(ob_agent_t *a, const char *json) {
    size_t len = strlen(json);
    unsigned char hdr[4];
    if (len == 0 || len > OB_FRAME_MAX)
        return -1;
    hdr[0] = (unsigned char)((len >> 24) & 255);
    hdr[1] = (unsigned char)((len >> 16) & 255);
    hdr[2] = (unsigned char)((len >> 8) & 255);
    hdr[3] = (unsigned char)(len & 255);
    if (write_full(a, hdr, 4) < 0)
        return -1;
    return write_full(a, (const unsigned char *)json, (int)len) < 0 ? -1 : 0;
}

static int recv_obj(ob_agent_t *a, char *out, size_t cap, int timeout_ms) {
    unsigned char hdr[4];
    unsigned len;
    int r = read_full(a, hdr, 4, timeout_ms);
    if (r < 0)
        return r;
    len = ((unsigned)hdr[0] << 24) | ((unsigned)hdr[1] << 16) |
          ((unsigned)hdr[2] << 8) | hdr[3];
    if (len == 0 || len > OB_FRAME_MAX || len + 1 > cap)
        return -1;
    r = read_full(a, (unsigned char *)out, (int)len, timeout_ms);
    if (r < 0)
        return r;
    out[len] = 0;
    return 0;
}

/* ---------- crypto helpers ---------- */

static void hmac_parts_hex(const char *psk, const char **parts, int n, char out[65]) {
    const unsigned char *pp[8];
    size_t pl[8];
    int i;
    for (i = 0; i < n && i < 8; i++) {
        pp[i] = (const unsigned char *)parts[i];
        pl[i] = strlen(parts[i]);
    }
    ob_hmac_sha256_hex((const unsigned char *)psk, strlen(psk), pp, pl, n < 8 ? n : 8, out);
}

static int hexeq(const char *a, const char *b) {
    size_t i, n = strlen(a);
    unsigned diff = 0;
    if (n != strlen(b))
        return 0;
    for (i = 0; i < n; i++)
        diff |= (unsigned)(a[i] ^ b[i]);
    return diff == 0;
}

/* ---------- handshake ---------- */

int ob_handshake(ob_agent_t *a, const char *agent_id, const char *psk) {
    char frame[OB_JSON_MAX], tmp[OB_JSON_MAX], esc[128];
    char master_nonce[128], peer_hmac[128], my_hmac[65];
    const char *cp[3];
    unsigned char *skp[3];
    size_t skpl[3];
    unsigned char sess[32];
    if (!agent_id || strlen(agent_id) == 0 || strlen(agent_id) > OB_AGENT_ID_MAX)
        return -1;
    strcpy(a->agent_id, agent_id);
    strncpy(a->psk, psk ? psk : "", sizeof(a->psk) - 1);
    a->psk[sizeof(a->psk) - 1] = 0;
    a->nonce(a->ctx, a->agent_nonce);
    a->start_ms = a->millis(a->ctx);

    json_escape(a->agent_id, esc, sizeof(esc));
    snprintf(frame, sizeof(frame),
             "{\"jsonrpc\":\"2.0\",\"method\":\"agent.hello\",\"params\":{"
             "\"version\":\"4.0.0\",\"arch\":\"xtensa-esp32\",\"pid\":1,"
             "\"agent_id\":\"%s\",\"agent_nonce\":\"%s\"}}",
             esc, a->agent_nonce);
    if (send_obj(a, frame) < 0)
        return -2;
    if (recv_obj(a, frame, sizeof(frame), 10000) < 0)
        return -3;
    if (json_get_str(frame, "method", tmp, sizeof(tmp)) < 0 ||
        strcmp(tmp, "auth.challenge") != 0)
        return -4;
    if (json_get_str(frame, "master_nonce", master_nonce, sizeof(master_nonce)) < 0)
        return -5;

    cp[0] = a->agent_nonce;
    cp[1] = master_nonce;
    cp[2] = a->agent_id;
    hmac_parts_hex(a->psk, cp, 3, my_hmac);
    snprintf(frame, sizeof(frame),
             "{\"jsonrpc\":\"2.0\",\"method\":\"auth.response\",\"params\":{"
             "\"agent_id\":\"%s\",\"hmac\":\"%s\"}}",
             esc, my_hmac);
    if (send_obj(a, frame) < 0)
        return -6;
    if (recv_obj(a, frame, sizeof(frame), 10000) < 0)
        return -7;
    if (json_get_str(frame, "method", tmp, sizeof(tmp)) < 0 ||
        strcmp(tmp, "auth.confirm") != 0)
        return -8;
    if (json_get_str(frame, "hmac", peer_hmac, sizeof(peer_hmac)) < 0)
        return -9;
    cp[0] = master_nonce;
    cp[1] = a->agent_nonce;
    cp[2] = a->agent_id;
    hmac_parts_hex(a->psk, cp, 3, my_hmac);
    if (!hexeq(peer_hmac, my_hmac))
        return -10;
    /* sesskey = sha256(psk || agent_nonce || master_nonce) */
    {
        ob_sha256_t c;
        ob_sha256_init(&c);
        ob_sha256_update(&c, (const unsigned char *)a->psk, strlen(a->psk));
        ob_sha256_update(&c, (const unsigned char *)a->agent_nonce, strlen(a->agent_nonce));
        ob_sha256_update(&c, (const unsigned char *)master_nonce, strlen(master_nonce));
        ob_sha256_final(&c, sess);
    }
    (void)skp;
    (void)skpl;
    memcpy(a->sesskey, sess, 32);
    return 0;
}

/* ---------- session envelopes ---------- */

static int send_wrapped(ob_agent_t *a, const char *inner) {
    /* body_b64 over the inner JSON; server uses compact sort_keys, but it
     * verifies OUR mac with OUR bytes, so any stable encoding works. */
    static char b64[OB_JSON_MAX * 2];
    static char frame[OB_JSON_MAX * 2 + 128];
    char mac[65];
    const unsigned char *pp[1];
    size_t pl[1], n;
    n = ob_b64_encode((const unsigned char *)inner, strlen(inner), b64, sizeof(b64) - 1);
    if (n == (size_t)-1)
        return -1;
    b64[n] = 0;
    pp[0] = (const unsigned char *)b64;
    pl[0] = n;
    ob_hmac_sha256_hex(a->sesskey, 32, pp, pl, 1, mac);
    if (getenv("OB_DEBUG"))
        fprintf(stderr, "B64: %s\nMAC: %s\n", b64, mac);
    snprintf(frame, sizeof(frame), "{\"v\":4,\"body_b64\":\"%s\",\"mac\":\"%s\"}", b64, mac);
    return send_obj(a, frame);
}

static int recv_wrapped(ob_agent_t *a, char *inner, size_t cap, int timeout_ms) {
    static char frame[OB_JSON_MAX * 2 + 128];
    char b64[OB_JSON_MAX * 2], mac[128], expect[65];
    const unsigned char *pp[1];
    size_t pl[1], n;
    if (recv_obj(a, frame, sizeof(frame), timeout_ms) < 0)
        return -1;
    if (json_get_str(frame, "body_b64", b64, sizeof(b64)) < 0)
        return -2;
    if (json_get_str(frame, "mac", mac, sizeof(mac)) < 0)
        return -3;
    pp[0] = (const unsigned char *)b64;
    pl[0] = strlen(b64);
    ob_hmac_sha256_hex(a->sesskey, 32, pp, pl, 1, expect);
    if (!hexeq(mac, expect))
        return -4;
    n = ob_b64_decode(b64, strlen(b64), (unsigned char *)inner, cap - 1);
    if (n == (size_t)-1)
        return -5;
    inner[n] = 0;
    return 0;
}

/* ---------- serve loop ---------- */

static unsigned long g_uptime_base = 0;

int ob_serve(ob_agent_t *a, int max_requests) {
    char inner[OB_JSON_MAX], reply[OB_JSON_MAX], cmd[512], idraw[64];
    char method[64], esc[256], outb[1024], s64[1024];
    int served = 0, id_was_str;
    (void)g_uptime_base;
    while (served < max_requests) {
        unsigned long up;
        if (recv_wrapped(a, inner, sizeof(inner), 15000) < 0)
            return served > 0 ? served : -1;
        if (json_get_str(inner, "method", method, sizeof(method)) < 0)
            return served > 0 ? served : -2;
        id_was_str = json_get_raw(inner, "id", idraw, sizeof(idraw));
        if (id_was_str < 0) {
            strcpy(idraw, "0");
            id_was_str = 0;
        }
        up = a->millis(a->ctx) - a->start_ms;
        if (strcmp(method, "sys.ping") == 0) {
            snprintf(reply, sizeof(reply),
                     "{\"jsonrpc\":\"2.0\",\"id\":%s%s%s,\"result\":{"
                     "\"pong\":true,\"version\":\"4.0.0\",\"uptime_ms\":%lu}}",
                     id_was_str ? "\"" : "", idraw, id_was_str ? "\"" : "", up);
        } else if (strcmp(method, "sys.diag") == 0 || strcmp(method, "sys.telemetry") == 0) {
            json_escape(a->agent_id, esc, sizeof(esc));
            snprintf(reply, sizeof(reply),
                     "{\"jsonrpc\":\"2.0\",\"id\":%s%s%s,\"result\":{"
                     "\"hostname\":\"%s\",\"version\":\"4.0.0\","
                     "\"architecture\":\"xtensa-esp32\",\"cpu_cores\":2,"
                     "\"ram_total_bytes\":327680,\"ram_avail_bytes\":200000}}",
                     id_was_str ? "\"" : "", idraw, id_was_str ? "\"" : "", esc);
        } else if (strcmp(method, "exec.run") == 0) {
            int code = 0;
            const char *note = "";
            cmd[0] = 0;
            if (json_get_str(inner, "cmd_b64", s64, sizeof(s64)) == 0) {
                size_t n = ob_b64_decode(s64, strlen(s64), (unsigned char *)outb, sizeof(outb) - 1);
                if (n == (size_t)-1) {
                    code = 1;
                    note = "bad cmd_b64";
                } else {
                    outb[n] = 0;
                    strncpy(cmd, outb, sizeof(cmd) - 1);
                }
            } else if (json_get_str(inner, "command", cmd, sizeof(cmd)) < 0 &&
                       json_get_str(inner, "cmd", cmd, sizeof(cmd)) < 0) {
                code = 1;
                note = "Missing command or cmd_b64";
            }
            if (code == 0) {
                if (strncmp(cmd, "screen.text ", 12) == 0 || strcmp(cmd, "led on") == 0 ||
                    strcmp(cmd, "led off") == 0) {
                    code = 0;
                    note = cmd;
                } else {
                    code = 1;
                    note = "rejected by ESP32 allowlist";
                }
            }
            {
                size_t n = ob_b64_encode((const unsigned char *)note, strlen(note), s64, sizeof(s64) - 1);
                if (n == (size_t)-1)
                    return served > 0 ? served : -3;
                s64[n] = 0;
            }
            snprintf(reply, sizeof(reply),
                     "{\"jsonrpc\":\"2.0\",\"id\":%s%s%s,\"result\":{"
                     "\"pid\":0,\"exit_code\":%d,\"timed_out\":false,"
                     "\"stdout_b64\":\"%s\",\"stderr_b64\":\"%s\"}}",
                     id_was_str ? "\"" : "", idraw, id_was_str ? "\"" : "",
                     code, code == 0 ? s64 : "", code == 0 ? "" : s64);
        } else {
            snprintf(reply, sizeof(reply),
                     "{\"jsonrpc\":\"2.0\",\"id\":%s%s%s,"
                     "\"error\":{\"code\":-32601,\"message\":\"unsupported on ESP32\"}}",
                     id_was_str ? "\"" : "", idraw, id_was_str ? "\"" : "");
        }
        if (getenv("OB_DEBUG")) {
            char sk[65];
            fprintf(stderr, "REQ: %s\n", inner);
            fprintf(stderr, "REP: %s\n", reply);
            ob_hex32(a->sesskey, sk);
            fprintf(stderr, "SESSKEY: %s\n", sk);
        }
        if (send_wrapped(a, reply) < 0)
            return served > 0 ? served : -5;
        served++;
    }
    return served;
}

/* ---------- selftest ---------- */

int ob_selftest(ob_emit_fn emit, void *ctx) {
    /* SHA-256("abc") FIPS 180-4 */
    static const char *ABC = "abc";
    /* RFC 4231 case 2: key "Jefe", data "what do ya want for nothing?" */
    static const char *KEY = "Jefe";
    static const char *DATA = "what do ya want for nothing?";
    unsigned char h[32];
    char hex[65], line[96];
    const unsigned char *pp[1];
    size_t pl[1];
    ob_sha256_once((const unsigned char *)ABC, 3, h);
    ob_hex32(h, hex);
    snprintf(line, sizeof(line), "SHA256_OK %s", hex);
    emit(ctx, line);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0)
        return 1;
    pp[0] = (const unsigned char *)DATA;
    pl[0] = strlen(DATA);
    ob_hmac_sha256_hex((const unsigned char *)KEY, strlen(KEY), pp, pl, 1, hex);
    snprintf(line, sizeof(line), "HMAC_OK %s", hex);
    emit(ctx, line);
    if (strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") != 0)
        return 2;
    /* framing round-trip: b64(enc(b64)) stability */
    {
        static const char * programs[] = {"agent.hello", "sys.ping", "exec.run"};
        char b1[256], b2[256];
        unsigned char raw[256];
        size_t n1, n2, i;
        for (i = 0; i < 3; i++) {
            n1 = ob_b64_encode((const unsigned char *)programs[i], strlen(programs[i]), b1, sizeof(b1) - 1);
            if (n1 == (size_t)-1)
                return 3;
            b1[n1] = 0;
            n2 = ob_b64_decode(b1, n1, raw, sizeof(raw) - 1);
            if (n2 == (size_t)-1 || n2 != strlen(programs[i]) ||
                memcmp(raw, programs[i], n2) != 0)
                return 4;
            (void)b2;
        }
    }
    /* Long-message HMAC (188 bytes, multi-block): regression for pad overflow. */
    {
        unsigned char key[32], msg[188];
        int i;
        for (i = 0; i < 32; i++)
            key[i] = (unsigned char)i;
        memset(msg, 'A', sizeof(msg));
        pp[0] = msg;
        pl[0] = sizeof(msg);
        ob_hmac_sha256_hex(key, sizeof(key), pp, pl, 1, hex);
        snprintf(line, sizeof(line), "LONGMAC_OK %s", hex);
        emit(ctx, line);
        if (strcmp(hex, "b86f60810b32c7b3d804680554b863d3a6d7d8a6e50574ae4651e6b15072799e") != 0)
            return 5;
    }
    emit(ctx, "FRAMING_OK");
    return 0;
}
