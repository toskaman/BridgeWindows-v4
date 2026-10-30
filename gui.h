#ifndef BRIDGE_GUI_H
#define BRIDGE_GUI_H
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

/* Connection states published by the agent core. */
#define BW_STATE_IDLE        0   /* starting / backing off / unreachable */
#define BW_STATE_CONNECTING  1   /* TCP up, handshake in progress */
#define BW_STATE_CONNECTED   2   /* mutual auth complete, session live */

typedef struct {
    int state;
    char agent_id[64];
    char master[280];
    char version[16];
    char arch[16];
    char os[16];
    uint64_t uptime_s, session_uptime_s;
    uint64_t rpc_total, packets_rx, packets_tx, bytes_rx, bytes_tx;
    uint64_t reconnects;
    double cpu_pct;
    uint64_t ram_avail_mb, ram_total_mb;
    char last_error[128];
} bw_snapshot_t;

typedef void (*bw_log_cb)(uint64_t seq, int level, uint64_t uptime_ms,
                          const char *msg, void *ctx);

/* Live data flows: one event per message crossing the link. */
#define BW_FLOW_IN   0   /* master -> this PC */
#define BW_FLOW_OUT  1   /* this PC -> master */
typedef void (*bw_flow_cb)(int dir, const char *label, uint64_t bytes, void *ctx);

/* Implemented by agent.c (core side). */
void bw_snapshot(bw_snapshot_t *out);
int bw_drain_logs(uint64_t *last_seq, bw_log_cb cb, void *ctx);
int bw_drain_flows(uint64_t *last_seq, bw_flow_cb cb, void *ctx);
void bw_force_reconnect(void);
void bw_quit(void);
void bw_console_toggle(void);     /* show/hide (allocates on first use) */
bool bw_console_visible(void);

/* Implemented by gui.c. gui_start: false = no desktop, stay headless. */
bool gui_start(void);
void gui_stop(void);
#endif
