#include "obproto.h"
#include "obsha256.h"
#include "obminijson.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

size_t ob_b64enc(const unsigned char *in, size_t len, char *out, size_t outsize) {
    static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0, i = 0;
    if (outsize < 4 * ((len + 2) / 3) + 1) return (size_t)-1; /* (size_t)-1 = error; 0 = valid empty */
    while (i < len) {
        unsigned n = 0, pad = 0;
        unsigned a = in[i++]; n |= a << 16;
        if (i < len) n |= (unsigned)in[i++] << 8; else pad++;
        if (i < len) n |= in[i++]; else pad++;
        out[o++] = A[(n >> 18) & 63]; out[o++] = A[(n >> 12) & 63];
        out[o++] = pad >= 2 ? '=' : A[(n >> 6) & 63];
        out[o++] = pad >= 1 ? '=' : A[n & 63];
    }
    out[o] = 0;
    return o;
}

size_t ob_b64dec(const char *in, size_t len, unsigned char *out, size_t outsize) {
    static signed char T[256]; static int init = 0;
    size_t o = 0, i = 0;
    if (!init) {
        size_t k; const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        memset(T, -1, sizeof(T));
        for (k = 0; k < 64; ++k) T[(unsigned char)A[k]] = (signed char)k;
        init = 1;
    }
    if (len % 4) return 0;
    while (i < len) {
        unsigned n = 0; int pad = 0, k;
        for (k = 0; k < 4; ++k) {
            char ch = in[i++];
            n <<= 6;
            if (ch == '=') pad++;
            else {
                if (pad) return 0; /* data after pad: malformed */
                if (T[(unsigned char)ch] < 0) return 0;
                n |= (unsigned)T[(unsigned char)ch];
            }
        }
        if (pad > 2 || (pad && i < len)) return 0; /* pad only at very end */
        if (o + 3 - (size_t)pad > outsize) return 0;
        out[o++] = (unsigned char)(n >> 16);
        if (pad < 2) out[o++] = (unsigned char)(n >> 8);
        if (pad < 1) out[o++] = (unsigned char)n;
    }
    return o;
}

void ob_nonce_hex(char out33[OB_NONCE_HEX]) {
    static const char *H = "0123456789abcdef";
    int i;
    for (i = 0; i < 16; ++i) {
        unsigned v = (unsigned)(rand() & 0xFF) ^ (unsigned)((rand() >> 3) & 0xFF);
        out33[2*i] = H[v >> 4]; out33[2*i+1] = H[v & 15];
    }
    out33[32] = 0;
}

static int send_frame(ob_agent *a, const char *json, size_t len) {
    unsigned char hdr[4];
    hdr[0]=(unsigned char)(len>>24); hdr[1]=(unsigned char)(len>>16);
    hdr[2]=(unsigned char)(len>>8); hdr[3]=(unsigned char)len;
    if (a->send_all(a->io_ctx, hdr, 4)) return -1;
    return a->send_all(a->io_ctx, json, len);
}

static int recv_frame(ob_agent *a, char *buf, size_t cap, size_t *outlen) {
    unsigned char hdr[4];
    size_t len;
    { int _r = a->recv_all(a->io_ctx, hdr, 4); if (_r == -2) return -2; if (_r) return -1; }
    len = ((size_t)hdr[0]<<24)|((size_t)hdr[1]<<16)|((size_t)hdr[2]<<8)|hdr[3];
    if (len == 0 || len >= cap || len > OB_FRAME_MAX) return -1;
    { int _r = a->recv_all(a->io_ctx, buf, len); if (_r == -2) return -2; if (_r) return -1; }
    buf[len] = 0;
    *outlen = len;
    return 0;
}

static void hmac_hex(const char *key, size_t keylen, const char *a, const char *b, const char *c, char out65[65]) {
    /* HMAC over a||b||c (same as three update() calls on the bridge side). */
    char msg[256];
    unsigned char mac[32];
    size_t n = 0;
    n += strlen(a); n += strlen(b); n += strlen(c);
    if (n >= sizeof(msg)) { memset(out65, '0', 64); out65[64] = 0; return; }
    msg[0] = 0; strcat(msg, a); strcat(msg, b); strcat(msg, c);
    ob_hmac_sha256(key, keylen, msg, strlen(msg), mac);
    ob_hex(mac, 32, out65);
}

static int consttime_eq(const char *a, const char *b, size_t n) {
    unsigned d = 0; size_t i;
    for (i = 0; i < n; ++i) d |= (unsigned)(a[i] ^ b[i]);
    return d == 0;
}

int ob_handshake(ob_agent *a, const char *agent_nonce_hex) {
    char hello[512], resp[512], frame[2048], mnonce[65], expect[65];
    char pskhex[65];
    size_t flen;
    oj_pool pool;
    int root, ps, mn, hm;
    (void)pskhex;
    if (snprintf(hello, sizeof(hello),
            "{\"jsonrpc\":\"2.0\",\"method\":\"agent.hello\",\"params\":"
            "{\"version\":\"4.0.0\",\"arch\":\"%s\",\"pid\":1,\"agent_id\":\"%s\",\"agent_nonce\":\"%s\"}}",
            a->arch, a->agent_id, agent_nonce_hex) >= (int)sizeof(hello)) return -1;
    a->hs_stage = 1;
    if (send_frame(a, hello, strlen(hello))) return -1;
    a->hs_stage = 2;
    { int _r = recv_frame(a, frame, sizeof(frame), &flen); if (_r) { a->hs_err = _r; return -1; } }
    a->hs_stage = 3;
    root = oj_parse(&pool, frame, flen);
    if (root < 0) return -1;
    { int m = oj_get(&pool, root, "method");
      if (m < 0 || pool.n[m].t != OJ_STR || strcmp(pool.n[m].str, "auth.challenge")) return -1; }
    ps = oj_get(&pool, root, "params");
    if (ps < 0) return -1;
    mn = oj_get(&pool, ps, "master_nonce");
    if (mn < 0 || pool.n[mn].t != OJ_STR || strlen(pool.n[mn].str) != 32) return -1;
    strcpy(mnonce, pool.n[mn].str);
    hmac_hex(a->psk, strlen(a->psk), agent_nonce_hex, mnonce, a->agent_id, expect);
    if (snprintf(resp, sizeof(resp),
            "{\"jsonrpc\":\"2.0\",\"method\":\"auth.response\",\"params\":"
            "{\"agent_id\":\"%s\",\"hmac\":\"%s\"}}", a->agent_id, expect) >= (int)sizeof(resp)) return -1;
    a->hs_stage = 4;
    if (send_frame(a, resp, strlen(resp))) return -1;
    a->hs_stage = 5;
    { int _r = recv_frame(a, frame, sizeof(frame), &flen); if (_r) { a->hs_err = _r; return -1; } }
    a->hs_stage = 6;
    root = oj_parse(&pool, frame, flen);
    if (root < 0) return -1;
    { int m = oj_get(&pool, root, "method");
      if (m < 0 || pool.n[m].t != OJ_STR || strcmp(pool.n[m].str, "auth.confirm")) return -1; }
    ps = oj_get(&pool, root, "params");
    if (ps < 0) return -1;
    hm = oj_get(&pool, ps, "hmac");
    if (hm < 0 || pool.n[hm].t != OJ_STR || strlen(pool.n[hm].str) != 64) return -1;
    hmac_hex(a->psk, strlen(a->psk), mnonce, agent_nonce_hex, a->agent_id, expect);
    if (!consttime_eq(pool.n[hm].str, expect, 64)) return -1;
    { /* sesskey = SHA256(psk || agent_nonce || master_nonce), all ASCII */
      char cat[256];
      if (strlen(a->psk) + 64 >= sizeof(cat)) return -1;
      strcpy(cat, a->psk); strcat(cat, agent_nonce_hex); strcat(cat, mnonce);
      ob_sha256_once(cat, strlen(cat), a->sesskey);
    }
    a->authed = 1;
    a->hs_stage = 7;
    return 0;
}

static int send_wrapped(ob_agent *a, const char *inner, size_t innerlen) {
    static char b64[OB_FRAME_MAX], mac[65], frame[OB_FRAME_MAX + 128];
    unsigned char raw[32];
    size_t blen;
    int flen;
    if (innerlen > 48000) return -1;
    blen = ob_b64enc((const unsigned char*)inner, innerlen, b64, sizeof(b64));
    if (blen == (size_t)-1) return -1;
    ob_hmac_sha256(a->sesskey, 32, b64, blen, raw);
    ob_hex(raw, 32, mac);
    flen = snprintf(frame, sizeof(frame), "{\"v\":4,\"body_b64\":\"%s\",\"mac\":\"%s\"}", b64, mac);
    if (flen <= 0 || (size_t)flen >= sizeof(frame)) return -1;
    return send_frame(a, frame, (size_t)flen);
}

static int recv_wrapped(ob_agent *a, char *inner, size_t cap, size_t *outlen) {
    static char frame[OB_FRAME_MAX + 128], b64[OB_FRAME_MAX];
    unsigned char raw[32];
    char mac[65];
    size_t flen, blen, ilen;
    oj_pool pool;
    int root, vb, mb, bb;
    { int _r = recv_frame(a, frame, sizeof(frame), &flen); if (_r == -2) return -2; if (_r) return -1; }
    root = oj_parse(&pool, frame, flen);
    if (root < 0) return -1;
    vb = oj_get(&pool, root, "v");
    bb = oj_get(&pool, root, "body_b64");
    mb = oj_get(&pool, root, "mac");
    if (vb < 0 || pool.n[vb].t != OJ_NUM || pool.n[vb].num != 4) return -1;
    if (bb < 0 || pool.n[bb].t != OJ_STR || mb < 0 || pool.n[mb].t != OJ_STR) return -1;
    if (strlen(pool.n[mb].str) != 64) return -1;
    blen = strlen(pool.n[bb].str);
    if (blen >= sizeof(b64)) return -1;
    strcpy(b64, pool.n[bb].str);
    ob_hmac_sha256(a->sesskey, 32, b64, blen, raw);
    ob_hex(raw, 32, mac);
    if (!consttime_eq(pool.n[mb].str, mac, 64)) return -1;
    ilen = ob_b64dec(b64, blen, (unsigned char*)inner, cap - 1);
    if (!ilen && blen) return -1;
    inner[ilen] = 0;
    *outlen = ilen;
    return 0;
}

int ob_notify(ob_agent *a, const char *method, const char *params_json) {
    char inner[2048];
    int n = snprintf(inner, sizeof(inner),
        "{\"jsonrpc\":\"2.0\",\"method\":\"%s\",\"params\":%s}", method, params_json ? params_json : "{}");
    if (n <= 0 || (size_t)n >= sizeof(inner)) return -1;
    a->notif_count++;
    return send_wrapped(a, inner, (size_t)n);
}

/* --- RPC dispatch ------------------------------------------------------ */

static int reply_result(ob_agent *a, long id, int has_id, const char *result_json) {
    char inner[8192];
    int n;
    if (has_id) n = snprintf(inner, sizeof(inner), "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"result\":%s}", id, result_json);
    else n = snprintf(inner, sizeof(inner), "{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":%s}", result_json);
    if (n <= 0 || (size_t)n >= sizeof(inner)) return -1;
    return send_wrapped(a, inner, (size_t)n);
}

static int reply_error(ob_agent *a, long id, int has_id, int code, const char *msg) {
    char inner[512], em[256];
    int n;
    oj_escape(msg, em, sizeof(em));
    if (has_id) n = snprintf(inner, sizeof(inner),
        "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"error\":{\"code\":%d,\"message\":\"%s\"}}", id, code, em);
    else n = snprintf(inner, sizeof(inner),
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":%d,\"message\":\"%s\"}}", code, em);
    if (n <= 0 || (size_t)n >= sizeof(inner)) return -1;
    return send_wrapped(a, inner, (size_t)n);
}

static int dispatch(ob_agent *a, oj_pool *pool, int root) {
    int m = oj_get(pool, root, "method");
    int idn = oj_get(pool, root, "id");
    int ps = oj_get(pool, root, "params");
    long id = 0; int has_id = 0;
    const char *method;
    if (m < 0 || pool->n[m].t != OJ_STR) return 0;   /* response echo; ignore */
    method = pool->n[m].str;
    if (idn >= 0 && pool->n[idn].t == OJ_NUM) { id = pool->n[idn].num; has_id = 1; }
    a->rpc_count++;
    if (!strcmp(method, "sys.ping")) {
        return reply_result(a, id, has_id, "{\"pong\":true}");
    }
    if (!strcmp(method, "sys.diag")) {
        char r[512], esc[64];
        oj_escape(a->agent_id, esc, sizeof(esc));
        snprintf(r, sizeof(r), "{\"hostname\":\"%s\",\"arch\":\"%s\",\"rpc\":%lu,\"notif\":%lu}",
                 esc, a->arch, a->rpc_count, a->notif_count);
        return reply_result(a, id, has_id, r);
    }
    if (!strcmp(method, "exec.run")) {
        /* Playdate allowlist: ping | beep | list_controls | screen.text <msg> */
        char cmd[1024], out[1024], outb64[1400], errb64[64], r[4096], esc[1100];
        const char *command = "";
        int exit_code = 0;
        if (ps >= 0) {
            int cn = oj_get(pool, ps, "command");
            if (cn >= 0 && pool->n[cn].t == OJ_STR) command = pool->n[cn].str;
        }
        strncpy(cmd, command, sizeof(cmd) - 1); cmd[sizeof(cmd)-1] = 0;
        out[0] = 0;
        if (!strcmp(cmd, "ping")) strcpy(out, "pong");
        else if (!strcmp(cmd, "beep") || !strcmp(cmd, "list_controls")) {
            if (a->action) { if (a->action(a->action_ctx, cmd, "", out, sizeof(out))) exit_code = 1; }
            else strcpy(out, cmd);
        }
        else if (!strncmp(cmd, "screen.text ", 12)) {
            if (a->action) { if (a->action(a->action_ctx, "screen.text", cmd + 12, out, sizeof(out))) exit_code = 1; }
            else strcpy(out, "shown");
        }
        else exit_code = 3;
        if (ob_b64enc((const unsigned char*)out, strlen(out), outb64, sizeof(outb64)) == (size_t)-1) return -1;
        errb64[0] = 0;
        if (exit_code) {
            if (ob_b64enc((const unsigned char*)"not allowed", 11, errb64, sizeof(errb64)) == (size_t)-1) return -1;
        }
        oj_escape(out, esc, sizeof(esc));
        snprintf(r, sizeof(r), "{\"exit_code\":%d,\"stdout_b64\":\"%s\",\"stderr_b64\":\"%s\",\"echo\":\"%s\"}",
                 exit_code, outb64, errb64, esc);
        return reply_result(a, id, has_id, r);
    }
    return reply_error(a, id, has_id, -32601, "method not found");
}

int ob_poll(ob_agent *a) {
    static char inner[OB_FRAME_MAX];
    size_t ilen;
    oj_pool pool;
    int root, r;
    r = recv_wrapped(a, inner, sizeof(inner), &ilen);
    if (r == -2) return 0; /* idle: no data before the io timeout */
    if (r) return -1;
    root = oj_parse(&pool, inner, ilen);
    if (root < 0) return -1;
    if (dispatch(a, &pool, root)) return -1;
    return 1;
}

int ob_serve(ob_agent *a, int max_rpc) {
    int served = 0;
    for (;;) {
        int r;
        if (max_rpc > 0 && served >= max_rpc) return 0;
        r = ob_poll(a);
        if (r <= 0) return (served > 0 || a->notif_count > 0) ? 0 : -1;
        served++;
    }
}

