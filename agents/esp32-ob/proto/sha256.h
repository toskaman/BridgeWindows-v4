/* OpenBridge ESP32 agent: dependency-free SHA-256 / HMAC-SHA-256 / base64.
 * Shared by the Arduino firmware and the host protocol test (same code).
 * FIPS 180-4. Verified against hashlib + RFC 4231 vectors in test_esp32_proto.py
 * and by the firmware --selftest over UART. */
#ifndef OB_SHA256_H
#define OB_SHA256_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t h[8];
    uint64_t len;
    unsigned char buf[64];
    size_t buflen;
} ob_sha256_t;

void ob_sha256_init(ob_sha256_t *c);
void ob_sha256_update(ob_sha256_t *c, const unsigned char *data, size_t len);
void ob_sha256_final(ob_sha256_t *c, unsigned char out[32]);

void ob_sha256_once(const unsigned char *data, size_t len, unsigned char out[32]);

/* HMAC-SHA-256. out_hex must hold 65 bytes (64 hex + NUL). */
void ob_hmac_sha256_hex(const unsigned char *key, size_t keylen,
                        const unsigned char **parts, const size_t *partlens,
                        int nparts, char out_hex[65]);

/* Base64. Returns output length (no NUL written) or (size_t)-1 on overflow. */
size_t ob_b64_encode(const unsigned char *in, size_t inlen, char *out, size_t outcap);
size_t ob_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t outcap);

void ob_hex32(const unsigned char h[32], char out65[65]);

#ifdef __cplusplus
}
#endif

#endif
