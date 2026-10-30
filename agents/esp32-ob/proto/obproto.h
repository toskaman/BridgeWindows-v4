/* OpenBridge ESP32 agent: v4 wire-protocol client core.
 * Transport-agnostic (TCP on WiFi/host, Serial via gateway): dependency-free C++.
 * Same code compiles for ESP32 (Arduino) and the host protocol test. */
#ifndef OBPROTO_H
#define OBPROTO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OB_AGENT_ID_MAX 32
#define OB_NONCE_HEX 32
#define OB_FRAME_MAX (16 * 1024)
#define OB_JSON_MAX (12 * 1024)

/* Transport callbacks. read: bytes read, 0 = timeout, <0 = error. */
typedef int (*ob_read_fn)(void *ctx, unsigned char *buf, int len, int timeout_ms);
typedef int (*ob_write_fn)(void *ctx, const unsigned char *buf, int len);
typedef unsigned long (*ob_millis_fn)(void *ctx);
typedef void (*ob_nonce_fn)(void *ctx, char out32[33]);

typedef struct {
    ob_read_fn read;
    ob_write_fn write;
    ob_millis_fn millis;
    ob_nonce_fn nonce;
    void *ctx;
    char agent_id[OB_AGENT_ID_MAX + 1];
    char psk[129];
    unsigned char sesskey[32];
    char agent_nonce[33];
    unsigned long start_ms;
} ob_agent_t;

/* Full mutual handshake. Returns 0 on AUTH_OK, nonzero on failure. */
int ob_handshake(ob_agent_t *a, const char *agent_id, const char *psk);

/* Serve up to max_requests RPCs (sys.ping, sys.diag, exec.run allowlist).
 * Returns requests served, or <0 on transport/mac error. */
int ob_serve(ob_agent_t *a, int max_requests);

/* Self-test: prints SHA256_OK/HMAC_OK/FRAMING_OK lines via emit(). 0 = pass. */
typedef void (*ob_emit_fn)(void *ctx, const char *line);
int ob_selftest(ob_emit_fn emit, void *ctx);

#ifdef __cplusplus
}
#endif

#endif
