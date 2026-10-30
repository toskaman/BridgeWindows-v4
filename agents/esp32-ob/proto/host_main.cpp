/* Host test harness for the ESP32 firmware core: same obproto over TCP sockets.
 * CLI: ob_esp32_host --host H --port P --token PSK --agent-id ID [--once N]
 *      ob_esp32_host --selftest
 */
#include "obproto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET sock_t;
#define SOCK_BAD INVALID_SOCKET
static void sock_init(void) {
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
}
static int sock_wait(sock_t s, int ms) {
    fd_set f;
    struct timeval tv;
    FD_ZERO(&f);
    FD_SET(s, &f);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &f, NULL, NULL, &tv);
}
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int sock_t;
#define SOCK_BAD (-1)
static void sock_init(void) {}
static int sock_wait(sock_t s, int ms) {
    fd_set f;
    struct timeval tv;
    FD_ZERO(&f);
    FD_SET(s, &f);
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select((int)s + 1, &f, NULL, NULL, &tv);
}
#endif

typedef struct {
    sock_t sock;
    unsigned long t0;
} ctx_t;

static int h_read(void *c, unsigned char *buf, int len, int timeout_ms) {
    ctx_t *x = (ctx_t *)c;
    int r = sock_wait(x->sock, timeout_ms);
    int n;
    if (r <= 0)
        return 0;
#ifdef _WIN32
    n = recv(x->sock, (char *)buf, len, 0);
#else
    n = (int)recv(x->sock, buf, (size_t)len, 0);
#endif
    if (n <= 0)
        return -1;
    return n;
}

static int h_write(void *c, const unsigned char *buf, int len) {
    ctx_t *x = (ctx_t *)c;
#ifdef _WIN32
    int n = send(x->sock, (const char *)buf, len, 0);
#else
    ssize_t n = send(x->sock, buf, (size_t)len, 0);
#endif
    return n <= 0 ? -1 : (int)n;
}

static unsigned long h_millis(void *c) {
    ctx_t *x = (ctx_t *)c;
#ifdef _WIN32
    return (unsigned long)GetTickCount() - x->t0;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long)(tv.tv_sec * 1000 + tv.tv_usec / 1000) - x->t0;
#endif
}

static void h_nonce(void *c, char out32[33]) {
    static const char *xd = "0123456789abcdef";
    int i;
    (void)c;
    srand((unsigned)time(NULL) ^ (unsigned)clock());
    for (i = 0; i < 32; i++)
        out32[i] = xd[rand() % 16];
    out32[32] = 0;
}

static void h_emit(void *c, const char *line) {
    (void)c;
    printf("%s\n", line);
    fflush(stdout);
}

static const char *flag(int argc, char **argv, const char *name) {
    int i;
    for (i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0)
            return argv[i + 1];
    }
    return NULL;
}

static int hasflag(int argc, char **argv, const char *name) {
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], name) == 0)
            return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    ctx_t x;
    ob_agent_t a;
    const char *host, *port, *token, *agent_id, *once;
    struct sockaddr_in sa;
    struct hostent *he;
    int nreq = 1000000, r, served;

    if (hasflag(argc, argv, "--selftest"))
        return ob_selftest(h_emit, NULL);
    host = flag(argc, argv, "--host");
    port = flag(argc, argv, "--port");
    token = flag(argc, argv, "--token");
    agent_id = flag(argc, argv, "--agent-id");
    once = flag(argc, argv, "--once");
    if (!host || !port || !token || !agent_id) {
        fprintf(stderr, "usage: ob_esp32_host --host H --port P --token T --agent-id ID [--once N] | --selftest\n");
        return 2;
    }
    if (once)
        nreq = atoi(once);

    sock_init();
    he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "resolve failed\n");
        return 3;
    }
    x.sock = socket(AF_INET, SOCK_STREAM, 0);
    if (x.sock == SOCK_BAD) {
        fprintf(stderr, "socket failed\n");
        return 3;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)atoi(port));
    memcpy(&sa.sin_addr, he->h_addr_list[0], 4);
#ifdef _WIN32
    if (connect(x.sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
#else
    if (connect(x.sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
#endif
        fprintf(stderr, "connect failed\n");
        return 3;
    }
    x.t0 = h_millis(&x) - h_millis(&x); /* 0 base; h_millis subtracts below */
    x.t0 = 0;
    memset(&a, 0, sizeof(a));
    a.read = h_read;
    a.write = h_write;
    a.millis = h_millis;
    a.nonce = h_nonce;
    a.ctx = &x;
    r = ob_handshake(&a, agent_id, token);
    if (r != 0) {
        fprintf(stderr, "handshake failed: %d\n", r);
        return 4;
    }
    printf("AUTH_OK %s\n", agent_id);
    fflush(stdout);
    served = ob_serve(&a, nreq);
    printf("SERVED %d\n", served);
    return served < 0 ? 5 : 0;
}
