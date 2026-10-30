/* host_main: the SAME Playdate agent core on host TCP (tests) or vectors.
 * --selftest : SHA-256/HMAC vectors + framing round-trip, no network.
 * --host H --port P --token T --agent-id A --once N [--notify METHOD,PARAMS_JSON]
 */
#include "obproto.h"
#include "obsha256.h"
#include "obminijson.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET sock_t;
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
typedef int sock_t;
#define INVALID_SOCKET -1
#endif

static int tcp_send(void *ctx, const void *buf, size_t len) {
    sock_t s = *(sock_t*)ctx;
    size_t o = 0;
    while (o < len) {
        int n = send(s, (const char*)buf + o, (int)(len - o), 0);
        if (n <= 0) return -1;
        o += (size_t)n;
    }
    return 0;
}

static int tcp_recv(void *ctx, void *buf, size_t len) {
    sock_t s = *(sock_t*)ctx;
    size_t o = 0;
    while (o < len) {
        fd_set rf; struct timeval tv; int n;
        FD_ZERO(&rf); FD_SET(s, &rf);
        tv.tv_sec = 15; tv.tv_usec = 0; /* idle 15s (ESP32 parity) -> serve exits */
        { int _s = select((int)(s + 1), &rf, 0, 0, &tv); if (_s == 0) return -2; if (_s < 0) return -1; }
        n = recv(s, (char*)buf + o, (int)(len - o), 0);
        if (n <= 0) return -1;
        o += (size_t)n;
    }
    return 0;
}

static int host_action(void *ctx, const char *command, const char *arg, char *out, size_t outsize) {
    (void)ctx;
    if (!strcmp(command, "screen.text")) { snprintf(out, outsize, "shown:%.900s", arg); return 0; }
    if (!strcmp(command, "beep")) { snprintf(out, outsize, "beep"); return 0; }
    if (!strcmp(command, "list_controls")) { snprintf(out, outsize, "a,b,up,down,left,right,crank"); return 0; }
    return 1;
}

static int selftest(void) {
    unsigned char d[32];
    char hex[65], b64[64];
    /* FIPS 180-4 SHA-256("abc") */
    ob_sha256_once("abc", 3, d); ob_hex(d, 32, hex);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) {
        printf("SHA256_FAIL %s\n", hex); return 1;
    }
    printf("SHA256_OK %s\n", hex);
    /* RFC 4231 case 2: key "Jefe", data "what do ya want for nothing?" */
    ob_hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d); ob_hex(d, 32, hex);
    if (strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")) {
        printf("HMAC_FAIL %s\n", hex); return 1;
    }
    printf("HMAC_OK %s\n", hex);
    /* long-message HMAC path (>64-byte key + >55-byte data, the old ESP32 pad bug shape) */
    { char big[200]; memset(big, 'a', sizeof(big));
      ob_hmac_sha256(big, sizeof(big), big, sizeof(big), d); ob_hex(d, 32, hex);
      printf("LONGMAC_OK %s\n", hex); }
    /* base64 round-trip incl. padding shapes */
    if (ob_b64enc((unsigned char*)"f", 1, b64, sizeof(b64)) == (size_t)-1 || strcmp(b64, "Zg==")) { printf("B64_FAIL\n"); return 1; }
    if (ob_b64enc((unsigned char*)"fo", 2, b64, sizeof(b64)) == (size_t)-1 || strcmp(b64, "Zm8=")) { printf("B64_FAIL\n"); return 1; }
    if (ob_b64enc((unsigned char*)"foo", 3, b64, sizeof(b64)) == (size_t)-1 || strcmp(b64, "Zm9v")) { printf("B64_FAIL\n"); return 1; }
    if (ob_b64enc((unsigned char*)"", 0, b64, sizeof(b64)) != 0 || b64[0]) { printf("B64_FAIL empty\n"); return 1; }
    { unsigned char raw[8]; size_t n = ob_b64dec("Zm9vYmFy", 8, raw, sizeof(raw));
      if (n != 6 || memcmp(raw, "foobar", 6)) { printf("B64_FAIL\n"); return 1; }
      n = ob_b64dec("Zg==", 4, raw, sizeof(raw));
      if (n != 1 || raw[0] != 'f') { printf("B64_FAIL pad2\n"); return 1; }
      n = ob_b64dec("Zm8=", 4, raw, sizeof(raw));
      if (n != 2 || memcmp(raw, "fo", 2)) { printf("B64_FAIL pad1\n"); return 1; }
      n = ob_b64dec("TWFu", 4, raw, sizeof(raw));
      if (n != 3 || memcmp(raw, "Man", 3)) { printf("B64_FAIL nopad\n"); return 1; } }
    /* JSON parse incl. escapes + nested params */
    { oj_pool p; const char *doc = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"exec.run\","
        "\"params\":{\"command\":\"screen.text hi\\u0021\"}}";
      int root = oj_parse(&p, doc, strlen(doc));
      int m, idn, ps, cn;
      if (root < 0) { printf("JSON_FAIL parse\n"); return 1; }
      m = oj_get(&p, root, "method"); idn = oj_get(&p, root, "id"); ps = oj_get(&p, root, "params");
      if (m < 0 || strcmp(p.n[m].str, "exec.run")) { printf("JSON_FAIL method\n"); return 1; }
      if (idn < 0 || p.n[idn].t != OJ_NUM || p.n[idn].num != 7) { printf("JSON_FAIL id\n"); return 1; }
      cn = oj_get(&p, ps, "command");
      if (cn < 0 || strcmp(p.n[cn].str, "screen.text hi!")) { printf("JSON_FAIL escape\n"); return 1; }
      printf("JSON_OK\n"); }
    printf("FRAMING_OK\n");
    return 0;
}

static const char *flag(int argc, char **argv, const char *name) {
    int i;
    for (i = 1; i + 1 < argc; ++i)
        if (!strcmp(argv[i], name)) return argv[i + 1];
    return 0;
}

int main(int argc, char **argv) {
    const char *host, *token, *agent_id;
    int port, once;
    ob_agent a;
    sock_t s;
    char nonce[OB_NONCE_HEX];
    if (argc > 1 && !strcmp(argv[1], "--selftest")) return selftest();
    host = flag(argc, argv, "--host"); token = flag(argc, argv, "--token");
    agent_id = flag(argc, argv, "--agent-id");
    port = flag(argc, argv, "--port") ? atoi(flag(argc, argv, "--port")) : 0;
    once = flag(argc, argv, "--once") ? atoi(flag(argc, argv, "--once")) : 0;
    if (!host || !token || !agent_id || port <= 0) { printf("usage error\n"); return 2; }
#ifdef _WIN32
    { WSADATA w; if (WSAStartup(MAKEWORD(2,2), &w)) return 2; }
#endif
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) { printf("socket fail\n"); return 1; }
    { struct sockaddr_in sa;
      memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)port);
      sa.sin_addr.s_addr = inet_addr(host);
      if (connect(s, (struct sockaddr*)&sa, sizeof(sa))) { printf("connect fail\n"); return 1; } }
    memset(&a, 0, sizeof(a));
    strncpy(a.agent_id, agent_id, sizeof(a.agent_id) - 1);
    strncpy(a.psk, token, sizeof(a.psk) - 1);
    strcpy(a.arch, "host-test");
    a.send_all = tcp_send; a.recv_all = tcp_recv; a.io_ctx = &s;
    a.action = host_action; a.action_ctx = 0;
    srand((unsigned)time(0) ^ (unsigned)port);
    ob_nonce_hex(nonce);
    if (ob_handshake(&a, nonce)) { printf("AUTH_FAIL\n"); return 1; }
    printf("AUTH_OK\n"); fflush(stdout);
    { const char *nt = flag(argc, argv, "--notify");
      if (nt) {
          const char *comma = strchr(nt, ',');
          char method[72];
          if (!comma || (size_t)(comma - nt) >= sizeof(method)) return 1;
          memcpy(method, nt, (size_t)(comma - nt)); method[comma - nt] = 0;
          if (ob_notify(&a, method, comma + 1)) return 1;
          printf("NOTIFY_OK %s\n", method); fflush(stdout);
      } }
    { const char *pl = flag(argc, argv, "--poll");
      if (pl && atoi(pl) > 0) { /* frame-stepped path (what the Playdate update loop drives) */
          int want = atoi(pl), served = 0;
          for (;;) {
              int r = ob_poll(&a);
              if (r < 0) return 1;
              if (r == 0) continue; /* idle tick: no data yet */
              served++;
              printf("POLL_OK %d\n", served); fflush(stdout);
              if (served >= want) break;
          }
          printf("SERVED %lu rpc\n", a.rpc_count);
          return 0;
      } }
    if (ob_serve(&a, once)) return 1;
    printf("SERVED %lu rpc\n", a.rpc_count);
    return 0;
}
