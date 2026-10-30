/* obproto: OpenBridge v4 agent protocol core. C99, transport-agnostic.
 *
 * The host harness (BSD/Winsock TCP) and the Playdate agent (pd TCP client)
 * share this file: handshake, session MAC, RPC dispatch, notifications.
 * Device actions (screen/sound) are callbacks so the host build stays headless.
 */
#ifndef OBPROTO_H
#define OBPROTO_H
#include <stddef.h>

#define OB_FRAME_MAX 65536
#define OB_ID_MAX 33
#define OB_NONCE_HEX 33

/* Transport: send/recv of exactly len bytes. 0 ok, -1 fail, -2 idle timeout
 * (recv only: no data within io_timeout_ms; the caller retries or exits). */
typedef int (*ob_send_fn)(void *ctx, const void *buf, size_t len);
typedef int (*ob_recv_fn)(void *ctx, void *buf, size_t len);

/* Device actions; return 0 on success and write a short stdout line. */
typedef int (*ob_action_fn)(void *ctx, const char *command, const char *arg,
                            char *out, size_t outsize);

typedef struct {
    char agent_id[OB_ID_MAX];
    char psk[129];
    unsigned char sesskey[32];
    int authed;
    ob_send_fn send_all;
    ob_recv_fn recv_all;
    void *io_ctx;
    int io_timeout_ms;    /* recv idle budget; 0 = wait forever (host default) */
    int io_blocking;      /* recv waits up to io_timeout_ms for the first byte (handshake); 0 = instant -2 (serve poll) */
    int hs_stage;         /* handshake diagnostics: last stage reached (0..7) */
    int hs_err;           /* last handshake recv error (-2 timeout, -1 error) */
    ob_action_fn action;
    void *action_ctx;
    char arch[16];          /* "playdate" on device, "host-test" in harness */
    /* stats for diag */
    unsigned long rpc_count;
    unsigned long notif_count;
} ob_agent;

/* base64 (standard alphabet, padded). enc returns out length, (size_t)-1 on
 * overflow (0 is a valid empty encoding). dec returns out length, 0 on error. */
size_t ob_b64enc(const unsigned char *in, size_t len, char *out, size_t outsize);
size_t ob_b64dec(const char *in, size_t len, unsigned char *out, size_t outsize);

/* One handshake over the configured transport. Returns 0 + authed=1 on success. */
int ob_handshake(ob_agent *a, const char *agent_nonce_hex);

/* Serve loop: answer up to max_rpc requests (0 = forever). Returns 0 when
 * max_rpc is reached or when the transport idles/closes after >=1 served RPC
 * or >=1 sent notification; -1 only when nothing was served (early failure). */
/* One serve iteration: 1 = served one RPC, 0 = idle (io timeout, retry),
 * -1 = fatal (MAC failure, close, corrupt frame). Frame-driven transports
 * (Playdate update loop) call this every tick; it never blocks past
 * io_timeout_ms when the transport honors it. */
int ob_poll(ob_agent *a);

/* Serve loop: answer up to max_rpc requests (0 = forever). Returns 0 when
 * max_rpc is reached or when the transport idles/closes after >=1 served RPC
 * or >=1 sent notification; -1 only when nothing was served (early failure). */
int ob_serve(ob_agent *a, int max_rpc);

/* Send one agent-initiated notification {method, params_json}. */
int ob_notify(ob_agent *a, const char *method, const char *params_json);

/* Random-ish hex nonce (caller seeds however the platform allows). */
void ob_nonce_hex(char out33[OB_NONCE_HEX]);

#endif
