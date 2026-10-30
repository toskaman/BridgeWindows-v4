/* obsha256: public-domain-style SHA-256 + HMAC-SHA256 (FIPS 180-4 / RFC 4231).
 * C99, no dependencies. Shared by the Playdate agent and the host harness. */
#ifndef OBSHA256_H
#define OBSHA256_H
#include <stddef.h>
#include <stdint.h>

typedef struct { uint32_t h[8]; uint64_t total; unsigned char buf[64]; size_t buflen; } ob_sha256;

void ob_sha256_init(ob_sha256 *s);
void ob_sha256_update(ob_sha256 *s, const void *data, size_t len);
void ob_sha256_final(ob_sha256 *s, unsigned char out32[32]);
void ob_sha256_once(const void *data, size_t len, unsigned char out32[32]);
void ob_hmac_sha256(const void *key, size_t keylen, const void *data, size_t len, unsigned char out32[32]);
void ob_hex(const unsigned char *in, size_t len, char *out); /* out needs 2*len+1 */

#endif
