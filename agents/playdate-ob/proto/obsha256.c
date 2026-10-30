#include "obsha256.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g) (((e)&(f))^((~(e))&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define S0(a) (ROR(a,2)^ROR(a,13)^ROR(a,22))
#define S1(e) (ROR(e,6)^ROR(e,11)^ROR(e,25))
#define s0(w) (ROR(w,7)^ROR(w,18)^((w)>>3))
#define s1(w) (ROR(w,17)^ROR(w,19)^((w)>>10))

static void block(ob_sha256 *s, const unsigned char *p) {
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; ++i)
        w[i] = ((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|p[4*i+3];
    for (; i < 64; ++i) w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];hh=s->h[7];
    for (i = 0; i < 64; ++i) {
        t1 = hh + S1(e) + CH(e,f,g) + K[i] + w[i];
        t2 = S0(a) + MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=hh;
}

void ob_sha256_init(ob_sha256 *s) {
    s->h[0]=0x6a09e667;s->h[1]=0xbb67ae85;s->h[2]=0x3c6ef372;s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f;s->h[5]=0x9b05688c;s->h[6]=0x1f83d9ab;s->h[7]=0x5be0cd19;
    s->total = 0; s->buflen = 0;
}

void ob_sha256_update(ob_sha256 *s, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char*)data;
    s->total += len;
    while (len > 0) {
        size_t take = 64 - s->buflen;
        if (take > len) take = len;
        memcpy(s->buf + s->buflen, p, take);
        s->buflen += take; p += take; len -= take;
        if (s->buflen == 64) { block(s, s->buf); s->buflen = 0; }
    }
}

void ob_sha256_final(ob_sha256 *s, unsigned char out32[32]) {
    unsigned char lenbe[8];
    uint64_t bits = s->total * 8;
    int i;
    unsigned char pad = 0x80;
    ob_sha256_update(s, &pad, 1);
    pad = 0;
    while (s->buflen != 56) ob_sha256_update(s, &pad, 1);
    for (i = 0; i < 8; ++i) lenbe[i] = (unsigned char)(bits >> (56 - 8*i));
    memcpy(s->buf + 56, lenbe, 8);
    block(s, s->buf);
    for (i = 0; i < 8; ++i) {
        out32[4*i]=(unsigned char)(s->h[i]>>24); out32[4*i+1]=(unsigned char)(s->h[i]>>16);
        out32[4*i+2]=(unsigned char)(s->h[i]>>8); out32[4*i+3]=(unsigned char)s->h[i];
    }
}

void ob_sha256_once(const void *data, size_t len, unsigned char out32[32]) {
    ob_sha256 s; ob_sha256_init(&s); ob_sha256_update(&s, data, len); ob_sha256_final(&s, out32);
}

void ob_hmac_sha256(const void *key, size_t keylen, const void *data, size_t len, unsigned char out32[32]) {
    unsigned char k0[64], ik[64], ok[64], inner[32];
    size_t i;
    if (keylen > 64) { ob_sha256_once(key, keylen, k0); memset(k0 + 32, 0, 32); }
    else { memcpy(k0, key, keylen); memset(k0 + keylen, 0, 64 - keylen); }
    for (i = 0; i < 64; ++i) { ik[i] = k0[i] ^ 0x36; ok[i] = k0[i] ^ 0x5c; }
    { ob_sha256 s; ob_sha256_init(&s); ob_sha256_update(&s, ik, 64); ob_sha256_update(&s, data, len); ob_sha256_final(&s, inner); }
    { ob_sha256 s; ob_sha256_init(&s); ob_sha256_update(&s, ok, 64); ob_sha256_update(&s, inner, 32); ob_sha256_final(&s, out32); }
}

void ob_hex(const unsigned char *in, size_t len, char *out) {
    static const char *H = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; ++i) { out[2*i] = H[in[i]>>4]; out[2*i+1] = H[in[i]&15]; }
    out[2*len] = 0;
}
