/* FIPS 180-4 SHA-256 + HMAC + base64. No dependencies, C++03 clean. */
#include "sha256.h"

#include <string.h>

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t K[64] = {
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

static void block(ob_sha256_t *c, const unsigned char *p) {
    uint32_t w[64];
    uint32_t a, b, cc, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

void ob_sha256_init(ob_sha256_t *c) {
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85; c->h[2] = 0x3c6ef372;
    c->h[3] = 0xa54ff53a; c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->len = 0;
    c->buflen = 0;
}

void ob_sha256_update(ob_sha256_t *c, const unsigned char *data, size_t len) {
    size_t i = 0;
    c->len += (uint64_t)len;
    if (c->buflen) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        i += take;
        if (c->buflen == 64) {
            block(c, c->buf);
            c->buflen = 0;
        }
    }
    for (; i + 64 <= len; i += 64)
        block(c, data + i);
    if (i < len) {
        c->buflen = len - i;
        memcpy(c->buf, data + i, c->buflen);
    }
}

void ob_sha256_final(ob_sha256_t *c, unsigned char out[32]) {
    unsigned char pad[128];
    uint64_t bitlen = c->len * 8;
    size_t i, padlen;
    pad[0] = 0x80;
    memset(pad + 1, 0, sizeof(pad) - 1);
    padlen = (c->buflen < 56) ? (64 - c->buflen) : (128 - c->buflen);
    /* length-in-bits, big-endian, in the last 8 bytes */
    for (i = 0; i < 8; i++)
        pad[padlen - 8 + i] = (unsigned char)(bitlen >> (56 - 8 * i));
    /* feed padding without touching c->len accounting twice: do it manually */
    {
        size_t total = c->buflen + padlen;
        unsigned char tmp[128];
        memcpy(tmp, c->buf, c->buflen);
        memcpy(tmp + c->buflen, pad, padlen);
        for (i = 0; i < total; i += 64)
            block(c, tmp + i);
    }
    for (i = 0; i < 8; i++) {
        out[4 * i] = (unsigned char)(c->h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(c->h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(c->h[i] >> 8);
        out[4 * i + 3] = (unsigned char)c->h[i];
    }
}

void ob_sha256_once(const unsigned char *data, size_t len, unsigned char out[32]) {
    ob_sha256_t c;
    ob_sha256_init(&c);
    ob_sha256_update(&c, data, len);
    ob_sha256_final(&c, out);
}

void ob_hex32(const unsigned char h[32], char out65[65]) {
    static const char *xd = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) {
        out65[2 * i] = xd[h[i] >> 4];
        out65[2 * i + 1] = xd[h[i] & 15];
    }
    out65[64] = 0;
}

void ob_hmac_sha256_hex(const unsigned char *key, size_t keylen,
                        const unsigned char **parts, const size_t *partlens,
                        int nparts, char out_hex[65]) {
    unsigned char kb[64], ipad[64], opad[64], inner[32], outer[32];
    ob_sha256_t c;
    int i, j;
    if (keylen > 64) {
        ob_sha256_once(key, keylen, kb);
        memset(kb + 32, 0, 32);
    } else {
        memcpy(kb, key, keylen);
        memset(kb + keylen, 0, 64 - keylen);
    }
    for (i = 0; i < 64; i++) {
        ipad[i] = kb[i] ^ 0x36;
        opad[i] = kb[i] ^ 0x5c;
    }
    ob_sha256_init(&c);
    ob_sha256_update(&c, ipad, 64);
    for (j = 0; j < nparts; j++)
        ob_sha256_update(&c, parts[j], partlens[j]);
    ob_sha256_final(&c, inner);
    ob_sha256_init(&c);
    ob_sha256_update(&c, opad, 64);
    ob_sha256_update(&c, inner, 32);
    ob_sha256_final(&c, outer);
    ob_hex32(outer, out_hex);
}

size_t ob_b64_encode(const unsigned char *in, size_t inlen, char *out, size_t outcap) {
    static const char *ab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0, i = 0;
    while (i < inlen) {
        unsigned char b[3] = {0, 0, 0};
        size_t n = 0;
        for (n = 0; n < 3 && i + n < inlen; n++)
            b[n] = in[i + n];
        if (o + 4 > outcap)
            return (size_t)-1;
        out[o++] = ab[b[0] >> 2];
        out[o++] = ab[((b[0] & 3) << 4) | (b[1] >> 4)];
        out[o++] = (n > 1) ? ab[((b[1] & 15) << 2) | (b[2] >> 6)] : '=';
        out[o++] = (n > 2) ? ab[b[2] & 63] : '=';
        i += n;
    }
    return o;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t ob_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t outcap) {
    size_t o = 0, i = 0;
    while (i < inlen) {
        int v[4], n = 0, pad = 0;
        int k;
        for (k = 0; k < 4 && i < inlen; k++, i++) {
            if (in[i] == '=') {
                v[k] = 0;
                pad++;
            } else {
                v[k] = b64val(in[i]);
                if (v[k] < 0)
                    return (size_t)-1;
            }
            n++;
        }
        if (n < 4)
            return (size_t)-1;
        if (o + 3 - (size_t)pad > outcap)
            return (size_t)-1;
        out[o++] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        if (pad < 2) out[o++] = (unsigned char)(((v[1] & 15) << 4) | (v[2] >> 2));
        if (pad < 1) out[o++] = (unsigned char)(((v[2] & 3) << 6) | v[3]);
        if (pad)
            break;
    }
    return o;
}
