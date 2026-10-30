/* pd_main: OpenBridge agent for Playdate (C, same obproto core as the host).
 * LINK: tcp->requestAccess (owner consent) -> open -> ob_handshake.
 * SERVE: ob_poll() every update() tick; buttons/crank send pd.button/pd.crank
 * notifications; exec.run screen.text <msg> displays <msg> on the orb screen.
 * Config comes from Source/obconfig.txt (host/port/psk/agent_id lines).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pd_api.h"
#include "obproto.h"
#include "obsha256.h"

static PlaydateAPI *pd;
static const struct playdate_tcp *tcp;
static TCPConnection *conn;
static ob_agent agent;

static char cfg_host[64] = "127.0.0.1";
static int cfg_port = 19991;
static char cfg_psk[129] = "";
static char cfg_id[OB_ID_MAX] = "PD-SIM";

static char display_msg[96] = "";
static int beep_flash = 0;
static int selftest_ok = -1;      /* -1 not run, 0 fail, 1 ok */
static int access_granted = 0;    /* owner allowed this host:port */
static int access_waiting = 0;
static int tcp_open = 0;
static int tcp_err = 0;
static int tcp_opens = 0;
static int tcp_drops = 0;
static int hs_tries = 0;
static unsigned last_open_ms = 0;
static unsigned long ob_wbytes = 0;
static unsigned long ob_rbytes = 0;
static int last_send_err = 0;
static int last_recv_err = 0;

/* --- transport glue: never blocks a frame when idle ---------------------- */

static int pd_send(void *ctx, const void *buf, size_t len) {
    size_t o = 0;
    unsigned start = pd->system->getCurrentTimeMilliseconds();
    (void)ctx;
    while (o < len) {
        int n = tcp->write(conn, (const char *)buf + o, len - o);
        if (n == NET_WRITE_BUSY || n == 0) {
            if ((int)(pd->system->getCurrentTimeMilliseconds() - start) > 250) { last_send_err = n; return -1; }
            continue;
        }
        if (n < 0) { last_send_err = n; return -1; }
        o += (size_t)n;
    }
    ob_wbytes += (unsigned long)len;
    return 0;
}

static int pd_recv(void *ctx, void *buf, size_t len) {
    size_t o = 0;
    unsigned start = pd->system->getCurrentTimeMilliseconds();
    (void)ctx;
    while (o < len) {
        size_t avail = tcp->getBytesAvailable(conn);
        size_t want;
        int n;
        unsigned now = pd->system->getCurrentTimeMilliseconds();
        if (avail == 0 && o == 0) {
            if (!agent.io_blocking) return -2; /* serve poll: come back next frame */
            if (agent.io_timeout_ms > 0 && (int)(now - start) > agent.io_timeout_ms) return -2;
            continue; /* handshake: wait for the first byte */
        }
        if (o > 0 && agent.io_timeout_ms > 0 && (int)(now - start) > agent.io_timeout_ms) return -2;
        if (avail == 0) continue;
        want = len - o;
        if (want > avail) want = avail;
        n = tcp->read(conn, (char *)buf + o, want);
        if (n == 0) continue; /* transient: re-poll within budget */
        if (n < 0) { last_recv_err = n; return -1; }
        o += (size_t)n;
    }
    ob_rbytes += (unsigned long)len;
    return 0;
}

static int pd_action(void *ctx, const char *command, const char *arg, char *out, size_t outsize) {
    (void)ctx;
    if (!strcmp(command, "screen.text")) {
        strncpy(display_msg, arg, sizeof(display_msg) - 1);
        display_msg[sizeof(display_msg) - 1] = 0;
        snprintf(out, outsize, "shown:%.60s", arg);
        return 0;
    }
    if (!strcmp(command, "beep")) {
        beep_flash = 30;
        snprintf(out, outsize, "beep");
        return 0;
    }
    if (!strcmp(command, "list_controls")) {
        snprintf(out, outsize, "a,b,up,down,left,right,crank");
        return 0;
    }
    return 1;
}

/* --- config + selftest --------------------------------------------------- */

static void read_config(void) {
    SDFile *f = pd->file->open("obconfig.txt", kFileRead);
    char buf[512];
    int n;
    char *line;
    if (!f) return;
    n = pd->file->read(f, buf, sizeof(buf) - 1);
    pd->file->close(f);
    if (n <= 0) return;
    buf[n] = 0;
    for (line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
        char *eq = strchr(line, '=');
        size_t vlen;
        if (!eq || line[0] == '#') continue;
        *eq = 0;
        vlen = strlen(eq + 1);
        while (vlen && (eq[vlen] == '\r' || eq[vlen] == '\n')) eq[vlen--] = 0;
        if (!strcmp(line, "host")) { strncpy(cfg_host, eq + 1, sizeof(cfg_host) - 1); }
        else if (!strcmp(line, "port")) { cfg_port = atoi(eq + 1); }
        else if (!strcmp(line, "psk")) { strncpy(cfg_psk, eq + 1, sizeof(cfg_psk) - 1); }
        else if (!strcmp(line, "agent_id")) { strncpy(cfg_id, eq + 1, sizeof(cfg_id) - 1); }
    }
}

static void run_selftest(void) {
    unsigned char d[32], raw[8];
    char hex[65];
    size_t n;
    selftest_ok = 0;
    ob_sha256_once("abc", 3, d); ob_hex(d, 32, hex);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) return;
    ob_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d); ob_hex(d, 32, hex);
    if (strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")) return;
    n = ob_b64dec("Zg==", 4, raw, sizeof(raw));
    if (n != 1 || raw[0] != 'f') return;
    n = ob_b64dec("Zm8=", 4, raw, sizeof(raw));
    if (n != 2 || memcmp(raw, "fo", 2)) return;
    selftest_ok = 1;
    pd->system->logToConsole("OpenBridge selftest OK (sha/hmac/b64 on Playdate)");
}

/* --- link state machine -------------------------------------------------- */

static void access_cb(bool allowed, void *ud) {
    (void)ud;
    access_waiting = 0;
    access_granted = allowed ? 1 : 0;
    pd->system->logToConsole("OpenBridge TCP access: %s", allowed ? "allowed" : "denied");
}

static void open_cb(TCPConnection *c, PDNetErr err, void *ud) {
    (void)c; (void)ud;
    if (err == NET_OK) {
        tcp_open = 1;
        tcp_err = 0;
        tcp_opens++;
        pd->system->logToConsole("OpenBridge TCP open");
    } else {
        tcp_open = 0;
        tcp_err = err;
        pd->system->logToConsole("OpenBridge TCP open failed: %d", err);
    }
}

static void closed_cb(TCPConnection *c, PDNetErr err) {
    (void)c; (void)err;
    if (conn) { tcp->close(conn); conn = NULL; }
    tcp_open = 0;
    agent.authed = 0;
    tcp_drops++;
    pd->system->logToConsole("OpenBridge TCP closed");
}

static void link_tick(void) {
    unsigned now = pd->system->getCurrentTimeMilliseconds();
    static int boot_frames = 0;
    if (!tcp) return;
    if (boot_frames++ < 90) return; /* show boot UI + selftest before asking consent */
    if (!access_granted && !access_waiting) {
        enum accessReply r;
        access_waiting = 1;
        r = tcp->requestAccess(cfg_host, cfg_port, false, "OpenBridge agent link", access_cb, NULL);
        if (r == kAccessDeny) { access_waiting = 0; }
        else if (r == kAccessAllow) { access_waiting = 0; access_granted = 1; }
        return;
    }
    if (access_granted && !conn && now - last_open_ms > 2000) {
        last_open_ms = now;
        conn = tcp->newConnection(cfg_host, cfg_port, false);
        if (!conn) return;
        tcp->setConnectionClosedCallback(conn, closed_cb);
        tcp->open(conn, open_cb, NULL);
    }
}

static void auth_tick(void) {
    unsigned now = pd->system->getCurrentTimeMilliseconds();
    static unsigned last_hs_ms;
    if (!tcp_open || agent.authed || selftest_ok != 1) return;
    if (now - last_hs_ms < 2000 && hs_tries > 0) return; /* one attempt per 2s */
    last_hs_ms = now;
    { char nonce[OB_NONCE_HEX];
      int r;
      agent.io_blocking = 1;
      ob_nonce_hex(nonce);
      r = ob_handshake(&agent, nonce);
      agent.io_blocking = 0;
      if (r == 0) {
          pd->system->logToConsole("OpenBridge AUTH_OK as %s", agent.agent_id);
      } else {
          hs_tries++;
          /* drop a half-shaken connection: no stale reply may desync the retry */
          if (conn) { tcp->close(conn); conn = NULL; }
          tcp_open = 0;
      } }
}

static void input_tick(void) {
    PDButtons cur, pushed, released;
    float crank;
    if (!agent.authed) return;
    pd->system->getButtonState(&cur, &pushed, &released);
    if (pushed & kButtonA) ob_notify(&agent, "pd.button", "{\"button\":\"a\",\"pressed\":true}");
    if (pushed & kButtonB) ob_notify(&agent, "pd.button", "{\"button\":\"b\",\"pressed\":true}");
    if (pushed & kButtonUp) ob_notify(&agent, "pd.button", "{\"button\":\"up\",\"pressed\":true}");
    if (pushed & kButtonDown) ob_notify(&agent, "pd.button", "{\"button\":\"down\",\"pressed\":true}");
    if (pushed & kButtonLeft) ob_notify(&agent, "pd.button", "{\"button\":\"left\",\"pressed\":true}");
    if (pushed & kButtonRight) ob_notify(&agent, "pd.button", "{\"button\":\"right\",\"pressed\":true}");
    crank = pd->system->getCrankChange();
    if (crank != 0.0f) {
        /* integer tenths: no float printf on device (newlib dtoa pulls syscalls) */
        int c10 = (int)(crank * 10.0f);
        int neg = c10 < 0 ? 1 : 0;
        char p[64];
        if (neg) c10 = -c10;
        snprintf(p, sizeof(p), "{\"change\":%s%d.%d}", neg ? "-" : "", c10 / 10, c10 % 10);
        ob_notify(&agent, "pd.crank", p);
    }
}

/* --- orb UI (400x240 1-bit) ---------------------------------------------- */

static void text(int x, int y, const char *s) {
    pd->graphics->drawText(s, strlen(s), kASCIIEncoding, x, y);
}

static void draw_ui(void) {
    char line[128];
    /* header rule */
    pd->graphics->fillRect(0, 22, 400, 2, kColorBlack);
    /* orb: rings + core lit when linked */
    pd->graphics->drawEllipse(14, 44, 120, 120, 3, 0, 360, kColorBlack);
    pd->graphics->drawEllipse(30, 60, 88, 88, 2, 0, 360, kColorBlack);
    if (agent.authed) pd->graphics->fillEllipse(52, 82, 44, 44, 0, 360, kColorBlack);
    else pd->graphics->drawEllipse(52, 82, 44, 44, 2, 0, 360, kColorBlack);
    if (beep_flash > 0) {
        pd->graphics->fillRect(14, 172, 120, 18, kColorBlack);
    }
    snprintf(line, sizeof(line), "OPENBRIDGE  %s", agent.agent_id);
    text(8, 5, line);
    snprintf(line, sizeof(line), "LINK: %s", !tcp ? "no TCP API" : !access_granted ? (access_waiting ? "consent?" : "ask") : !tcp_open ? (tcp_err ? "open failed" : "dial") : "open");
    text(150, 36, line);
    snprintf(line, sizeof(line), "AUTH: %s (tries %d st%d e%d)", agent.authed ? "yes" : "no", hs_tries, agent.hs_stage, agent.hs_err);
    text(150, 58, line);
    snprintf(line, sizeof(line), "RPC: %lu  NOTIF: %lu", agent.rpc_count, agent.notif_count);
    text(150, 80, line);
    snprintf(line, sizeof(line), "NET: op%d dr%d w%lu r%lu se%d re%d",
             tcp_opens, tcp_drops, ob_wbytes, ob_rbytes, last_send_err, last_recv_err);
    text(8, 182, line);
    snprintf(line, sizeof(line), "SELFTEST: %s", selftest_ok < 0 ? "..." : selftest_ok ? "OK" : "FAIL");
    text(150, 102, line);
    text(150, 124, "MSG:");
    text(150, 142, display_msg[0] ? display_msg : "(none yet)");
    text(8, 200, "A/B/dpad/crank: notify bridge");
    text(8, 218, "bridge->exec screen.text: shows MSG");
}

static int update(void *userdata) {
    (void)userdata;
    pd->graphics->clear(kColorWhite);
    if (selftest_ok < 0) run_selftest();
    link_tick();
    auth_tick();
    if (tcp_open && agent.authed) {
        if (ob_poll(&agent) < 0) {
            /* fatal: drop and redial */
            tcp->close(conn);
            conn = NULL;
            tcp_open = 0;
            agent.authed = 0;
            pd->system->logToConsole("OpenBridge link dropped, redial");
        }
        input_tick();
    }
    draw_ui();
    if (beep_flash > 0) beep_flash--;
    return 1;
}

#ifdef _WINDLL
__declspec(dllexport)
#endif
int eventHandler(PlaydateAPI *playdate, PDSystemEvent event, uint32_t arg) {
    (void)arg;
    if (event == kEventInit) {
        pd = playdate;
        tcp = pd->network ? pd->network->tcp : NULL;
        pd->system->setUpdateCallback(update, pd);
        srand(pd->system->getCurrentTimeMilliseconds());
        read_config();
        memset(&agent, 0, sizeof(agent));
        strncpy(agent.agent_id, cfg_id, sizeof(agent.agent_id) - 1);
        strncpy(agent.psk, cfg_psk, sizeof(agent.psk) - 1);
        strcpy(agent.arch, "playdate");
        agent.send_all = pd_send;
        agent.recv_all = pd_recv;
        agent.io_ctx = NULL;
        agent.io_timeout_ms = 250;
        agent.action = pd_action;
        agent.action_ctx = NULL;
        pd->system->logToConsole("OpenBridge agent %s -> %s:%d", cfg_id, cfg_host, cfg_port);
    } else if (event == kEventTerminate && conn) {
        tcp->close(conn);
        conn = NULL;
    }
    return 0;
}
