/* =========================================================================
 * Bridge Agent status window (Win32 + GDI, no external deps).
 *
 * One full-window 32-bit DIB per frame: background, the voice orb
 * (orb_core.h), live data flows (outgoing amber comets leave the sphere and
 * fly off-screen, incoming emerald comets fly in and dive into it, each with
 * a short label), glass cards and drawn buttons. GDI text goes on top.
 * Data comes from bw_snapshot(), bw_drain_logs() and bw_drain_flows().
 * Same gui.h contract as before; the network core is untouched.
 * ========================================================================= */
#include "gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "orb_core.h"

#define TIMER_ID     1
#define FRAME_MS     33
#define FEED_CAP     200
#define FEED_MSG_MAX 240
#define PMAX         72      /* live flow comets */
#define TRAIL        18      /* trail samples per comet */

/* palette (0xRRGGBB) */
#define C_BG_TOP  0x05070F
#define C_BG_BOT  0x0D0B1F
#define C_TEXT    0xECF0FF
#define C_MUTED   0x8A94B6
#define C_FAINT   0x5C6484
#define C_CYAN    0x00E5FF
#define C_VIOLET  0x8C64FF
#define C_MAGENTA 0xFF4FD8
#define C_OK      0x69F0AE
#define C_WARN    0xFFB74D
#define C_ERR     0xFF5252
#define C_OUT     0xFFB040   /* outgoing flows: amber  */
#define C_IN      0x34FFAA   /* incoming flows: emerald */

#define RGBX(h) RGB(((h) >> 16) & 255, ((h) >> 8) & 255, (h) & 255)

/* ---- state ---------------------------------------------------------------- */
typedef struct { int level; char time[12]; char msg[FEED_MSG_MAX]; } feed_t;
typedef struct {
    int alive, dir, labeled;
    float t, life, size;
    float ax, ay, bx, by, cx, cy;          /* quadratic bezier: start, end, control */
    float tr[TRAIL][2]; int tn;
    char label[48];
} comet_t;

enum { BTN_RECONNECT, BTN_FLOWS, BTN_CONSOLE, BTN_QUIT, BTN_N };
typedef struct { RECT r; const char *label; int kind; } button_t;   /* kind 0 normal, 1 toggle, 2 danger */

static HWND g_wnd = NULL;
static HANDLE g_ready_ev = NULL, g_gui_thread = NULL;
static volatile LONG g_gui_ok = 0;
static HFONT g_f_brand, g_f_id, g_f_ui, g_f_small, g_f_tiny, g_f_val, g_f_state, g_f_mono, g_f_btn, g_f_cap;
static uint64_t g_last_seq = 0, g_flow_seq = 0;

static orb_t g_orb;
static bw_snapshot_t g_snap;
static feed_t g_feed[FEED_CAP];
static int g_feed_head = 0, g_feed_count = 0;
static int g_prev_state = -2;

static comet_t g_comets[PMAX];
static int g_show_flows = 1;
static uint64_t g_msgs[2], g_bytes_dir[2];
static double g_rate[2];                     /* smoothed bytes/s per direction */
static double g_rate_acc[2];
static DWORD g_rate_tick = 0;
static DWORD g_last_label_tick[2] = {0, 0};
static char g_last_label[2][48];
static int g_spawn_budget[2];

static button_t g_btn[BTN_N];
static int g_hover = -1, g_pressed = -1, g_focus = -1;
static int g_tracking = 0;

/* full-window back buffer */
static HDC g_memdc = NULL;
static HBITMAP g_dib = NULL, g_dib_old = NULL;
static uint32_t *g_px = NULL;
static uint32_t *g_static = NULL;            /* cached background + cards */
static int g_W = 0, g_H = 0, g_static_ok = 0;

/* layout (client pixels) */
static int g_pad = 22;
static float g_orb_cx, g_orb_cy, g_orb_R;
static RECT g_r_tiles[6], g_r_feed, g_r_chip;
static int g_y_state, g_y_caption, g_y_legend;

/* ---- small helpers -------------------------------------------------------- */
static float clampf(float v, float a, float b) { return v < a ? a : v > b ? b : v; }
static float frand(void) { return (float)rand() / (float)RAND_MAX; }

static const char *level_tag(int l) { switch (l) { case 0: return "DEBUG"; case 2: return "WARN"; case 3: return "ERROR"; } return "INFO"; }
static int level_color(int l) { switch (l) { case 0: return C_FAINT; case 2: return C_WARN; case 3: return C_ERR; } return C_CYAN; }

/* Strip ANSI CSI sequences ("ESC[...m") the core embeds in log lines. */
static size_t strip_ansi(const char *in, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < cap; ) {
        if ((unsigned char)in[i] == 0x1B && in[i + 1] == '[') { i += 2; while (in[i] && in[i] != 'm') i++; if (in[i] == 'm') i++; }
        else out[o++] = in[i++];
    }
    out[o] = '\0'; return o;
}
static void fmt_bytes(uint64_t n, char *o, size_t c) {
    if (n < 1024) { snprintf(o, c, "%llu B", (unsigned long long)n); return; }
    double v = (double)n / 1024.0; const char *u = "KB";
    if (v >= 1024) { v /= 1024; u = "MB"; }
    if (v >= 1024) { v /= 1024; u = "GB"; }
    snprintf(o, c, v < 10 ? "%.1f %s" : "%.0f %s", v, u);
}
static void fmt_dur(uint64_t s, char *o, size_t c) {
    if (s < 90) snprintf(o, c, "%llus", (unsigned long long)s);
    else if (s < 5400) snprintf(o, c, "%llum %02llus", (unsigned long long)(s / 60), (unsigned long long)(s % 60));
    else snprintf(o, c, "%lluh %02llum", (unsigned long long)(s / 3600), (unsigned long long)((s / 60) % 60));
}

/* ---- pixel primitives (0x00RRGGBB, top-down, stride = g_W) ----------------- */
static void px_blend(int x, int y, int rgb, float a) {
    if (x < 0 || y < 0 || x >= g_W || y >= g_H || a <= 0.f) return;
    if (a > 1.f) a = 1.f;
    uint32_t *p = &g_px[y * g_W + x], v = *p;
    int r = (v >> 16) & 255, g = (v >> 8) & 255, b = v & 255;
    r += (int)((((rgb >> 16) & 255) - r) * a);
    g += (int)((((rgb >> 8) & 255) - g) * a);
    b += (int)(((rgb & 255) - b) * a);
    *p = (uint32_t)(r << 16 | g << 8 | b);
}

/* rounded rectangle via signed distance: AA fill + optional 1px border */
static void px_rrect(int x0, int y0, int w, int h, float rad, int fill, float fa, int border, float ba) {
    float hw = w * 0.5f, hh = h * 0.5f, cx = x0 + hw, cy = y0 + hh;
    if (rad > hw) rad = hw;
    if (rad > hh) rad = hh;
    for (int y = y0 - 1; y <= y0 + h; y++) {
        if (y < 0 || y >= g_H) continue;
        float qy = fabsf(y + 0.5f - cy) - (hh - rad);
        for (int x = x0 - 1; x <= x0 + w; x++) {
            if (x < 0 || x >= g_W) continue;
            float qx = fabsf(x + 0.5f - cx) - (hw - rad);
            float ox = qx > 0 ? qx : 0, oy = qy > 0 ? qy : 0;
            float d = sqrtf(ox * ox + oy * oy) + fminf(fmaxf(qx, qy), 0.f) - rad;
            float cov = clampf(0.5f - d, 0.f, 1.f);
            if (cov > 0.f && fa > 0.f) px_blend(x, y, fill, fa * cov);
            if (ba > 0.f) {
                float e = clampf(1.f - fabsf(d + 0.5f), 0.f, 1.f);
                if (e > 0.f) {
                    /* glassy edge: brighter on top */
                    float top = 1.f - clampf((y - y0) / (float)(h > 1 ? h : 1), 0.f, 1.f);
                    px_blend(x, y, border, ba * e * (0.55f + 0.45f * top));
                }
            }
        }
    }
}

/* AA stroke: segment with width w */
static void px_line(float x0, float y0, float x1, float y1, float w, int rgb, float a) {
    int minx = (int)floorf(fminf(x0, x1) - w - 1), maxx = (int)ceilf(fmaxf(x0, x1) + w + 1);
    int miny = (int)floorf(fminf(y0, y1) - w - 1), maxy = (int)ceilf(fmaxf(y0, y1) + w + 1);
    float dx = x1 - x0, dy = y1 - y0, L2 = dx * dx + dy * dy;
    for (int y = miny; y <= maxy; y++) for (int x = minx; x <= maxx; x++) {
        float px = x + 0.5f - x0, py = y + 0.5f - y0;
        float t = L2 > 0 ? clampf((px * dx + py * dy) / L2, 0.f, 1.f) : 0.f;
        float ex = px - dx * t, ey = py - dy * t;
        float cov = clampf(w * 0.5f + 0.5f - sqrtf(ex * ex + ey * ey), 0.f, 1.f);
        if (cov > 0) px_blend(x, y, rgb, a * cov);
    }
}
static void px_arc(float cx, float cy, float r, float a0, float a1, float w, int rgb, float a) {
    int n = (int)(fabsf(a1 - a0) * r / 2.f) + 6;
    float px = cx + cosf(a0) * r, py = cy + sinf(a0) * r;
    for (int i = 1; i <= n; i++) {
        float an = a0 + (a1 - a0) * i / n, qx = cx + cosf(an) * r, qy = cy + sinf(an) * r;
        px_line(px, py, qx, qy, w, rgb, a);
        px = qx; py = qy;
    }
}
static void px_disc(float cx, float cy, float r, int rgb, float a) {
    for (int y = (int)(cy - r - 1); y <= (int)(cy + r + 1); y++)
        for (int x = (int)(cx - r - 1); x <= (int)(cx + r + 1); x++) {
            float dx = x + 0.5f - cx, dy = y + 0.5f - cy;
            float cov = clampf(r + 0.5f - sqrtf(dx * dx + dy * dy), 0.f, 1.f);
            if (cov > 0) px_blend(x, y, rgb, a * cov);
        }
}
static void rgbf(int rgb, float o[3]) { o[0] = (float)((rgb >> 16) & 255); o[1] = (float)((rgb >> 8) & 255); o[2] = (float)(rgb & 255); }

/* ---- GDI text (UTF-8 -> wide; the A-API would show mojibake) ------------- */
static void text_at(HFONT f, int color, int x, int y, int w, int h, UINT flags, const char *s) {
    HGDIOBJ of = SelectObject(g_memdc, f);
    SetTextColor(g_memdc, RGBX(color)); SetBkMode(g_memdc, TRANSPARENT);
    RECT r = { x, y, x + w, y + h };
    WCHAR ws[512];
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, ws, 512) > 0) DrawTextW(g_memdc, ws, -1, &r, flags | DT_NOPREFIX);
    else DrawTextA(g_memdc, s, -1, &r, flags | DT_NOPREFIX);
    SelectObject(g_memdc, of);
}
static int text_width(HFONT f, const char *s) {
    HGDIOBJ of = SelectObject(g_memdc, f);
    WCHAR ws[256]; SIZE sz = {0, 0};
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, ws, 256);
    if (n > 1) GetTextExtentPoint32W(g_memdc, ws, n - 1, &sz);
    SelectObject(g_memdc, of);
    return sz.cx;
}
static int mix_rgb(int a, int b, float f) {
    f = clampf(f, 0.f, 1.f);
    int r = (int)(((a >> 16) & 255) + ((((b >> 16) & 255) - ((a >> 16) & 255)) * f));
    int g = (int)(((a >> 8) & 255) + ((((b >> 8) & 255) - ((a >> 8) & 255)) * f));
    int bl = (int)((a & 255) + (((b & 255) - (a & 255)) * f));
    return r << 16 | g << 8 | bl;
}

/* ---- feed --------------------------------------------------------------- */
static void feed_push(int level, const char *msg) {
    feed_t *e = &g_feed[g_feed_head];
    SYSTEMTIME st; GetLocalTime(&st);
    e->level = level;
    snprintf(e->time, sizeof(e->time), "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    strip_ansi(msg, e->msg, sizeof(e->msg));
    g_feed_head = (g_feed_head + 1) % FEED_CAP;
    if (g_feed_count < FEED_CAP) g_feed_count++;
}
static void feed_drain_cb(uint64_t seq, int level, uint64_t ms, const char *msg, void *ctx) {
    (void)seq; (void)ms; (void)ctx; feed_push(level, msg);
}

/* ---- flow comets ------------------------------------------------------------ */
static float g_act_dir[2];                  /* decaying per-direction activity */

static void comet_spawn(int dir, const char *label, uint64_t bytes) {
    dir = dir ? 1 : 0;
    g_msgs[dir]++; g_bytes_dir[dir] += bytes; g_rate_acc[dir] += (double)bytes;
    g_act_dir[dir] = fminf(1.f, g_act_dir[dir] + 0.35f);
    orb_bump(&g_orb, dir == BW_FLOW_OUT ? 0.30f : 0.20f);
    if (!g_show_flows || g_W <= 0) return;
    if (g_spawn_budget[dir] <= 0) return;            /* per-frame cap: bursts become a stream, not a flood */
    g_spawn_budget[dir]--;
    comet_t *c = NULL; int labeled_alive = 0;
    for (int i = 0; i < PMAX; i++) { if (g_comets[i].alive && g_comets[i].labeled) labeled_alive++; }
    for (int i = 0; i < PMAX && !c; i++) if (!g_comets[i].alive) c = &g_comets[i];
    if (!c) return;
    memset(c, 0, sizeof(*c));
    c->alive = 1; c->dir = dir;

    float ang = frand() * 6.2831853f, ux = cosf(ang), uy = sinf(ang);
    float reach = sqrtf((float)g_W * g_W + (float)g_H * g_H) * 0.8f + 60.f;
    float sx = g_orb_cx + ux * g_orb_R * 0.98f, sy = g_orb_cy + uy * g_orb_R * 0.98f;
    float ox = g_orb_cx + ux * reach, oy = g_orb_cy + uy * reach;
    if (dir == BW_FLOW_OUT) { c->ax = sx; c->ay = sy; c->bx = ox; c->by = oy; }
    else { c->ax = ox; c->ay = oy; c->bx = sx; c->by = sy; }
    float mx = (c->ax + c->bx) * 0.5f, my = (c->ay + c->by) * 0.5f;
    float dx = c->bx - c->ax, dy = c->by - c->ay, L = sqrtf(dx * dx + dy * dy) + 1e-3f;
    float bend = (0.10f + 0.16f * frand()) * L * (dir == BW_FLOW_OUT ? 1.f : -1.f);   /* swirl with the spin */
    c->cx = mx - dy / L * bend; c->cy = my + dx / L * bend;
    c->life = (dir == BW_FLOW_OUT ? 1.45f : 1.65f) + frand() * 0.55f;
    float lb = bytes > 0 ? log10f((float)bytes + 1.f) : 0.f;
    DWORD now = GetTickCount();
    int fresh = strcmp(label ? label : "", g_last_label[dir]) != 0 || now - g_last_label_tick[dir] > 650;
    c->labeled = fresh && labeled_alive < 10;
    c->size = (c->labeled ? 3.0f : 1.9f) + fminf(2.2f, lb * 0.32f);
    if (c->labeled) {
        char sz[24] = "", nm[30];
        snprintf(nm, sizeof(nm), "%s", label ? label : "?");
        if (strlen(label ? label : "") > 26) { nm[25] = '\0'; strcat(nm, "\xE2\x80\xA6"); }
        if (bytes > 0) fmt_bytes(bytes, sz, sizeof(sz));
        snprintf(c->label, sizeof(c->label), "%s %s%s%s", dir == BW_FLOW_OUT ? "\xE2\x86\x91" : "\xE2\x86\x93",
                 nm, sz[0] ? "  \xC2\xB7  " : "", sz);
        snprintf(g_last_label[dir], sizeof(g_last_label[dir]), "%s", label ? label : "");
        g_last_label_tick[dir] = now;
    }
}
static void flow_drain_cb(int dir, const char *label, uint64_t bytes, void *ctx) {
    (void)ctx; comet_spawn(dir, label, bytes);
}

static void comet_pos(const comet_t *c, float t, float *x, float *y) {
    float u = c->dir == BW_FLOW_OUT ? powf(t, 1.6f) : 1.f - powf(1.f - t, 1.7f);
    float a = (1 - u) * (1 - u), b = 2 * (1 - u) * u, d = u * u;
    *x = a * c->ax + b * c->cx + d * c->bx;
    *y = a * c->ay + b * c->cy + d * c->by;
}

static void comets_step(float dt) {
    for (int i = 0; i < PMAX; i++) {
        comet_t *c = &g_comets[i];
        if (!c->alive) continue;
        c->t += dt / c->life;
        if (c->t >= 1.f) {
            if (c->dir == BW_FLOW_IN) orb_bump(&g_orb, 0.45f);      /* absorbed by the sphere */
            c->alive = 0; continue;
        }
        float x, y; comet_pos(c, c->t, &x, &y);
        int n = c->tn < TRAIL ? c->tn + 1 : TRAIL;
        for (int k = n - 1; k > 0; k--) { c->tr[k][0] = c->tr[k - 1][0]; c->tr[k][1] = c->tr[k - 1][1]; }
        c->tr[0][0] = x; c->tr[0][1] = y; c->tn = n;
    }
}

static float comet_fade(const comet_t *c) {
    float t = c->t;
    if (c->dir == BW_FLOW_OUT) return clampf(t / 0.06f, 0.f, 1.f) * clampf((1.f - t) / 0.18f, 0.f, 1.f);
    return clampf(t / 0.12f, 0.f, 1.f) * clampf((1.f - t) / 0.06f, 0.f, 1.f);
}

static void comets_draw(void) {
    orb_surface s = { g_px, g_W, g_W, g_H };
    for (int i = 0; i < PMAX; i++) {
        comet_t *c = &g_comets[i];
        if (!c->alive || c->tn == 0) continue;
        float fade = comet_fade(c), col[3], hot[3];
        rgbf(c->dir == BW_FLOW_OUT ? C_OUT : C_IN, col);
        for (int k = 0; k < 3; k++) hot[k] = col[k] + (255.f - col[k]) * 0.65f;
        float shrink = c->dir == BW_FLOW_IN ? clampf((1.f - c->t) / 0.25f, 0.35f, 1.f) : 1.f;
        /* trail: oldest -> newest, thin and faint to bright */
        for (int k = c->tn - 1; k >= 1; k--) {
            float x0 = c->tr[k][0], y0 = c->tr[k][1], x1 = c->tr[k - 1][0], y1 = c->tr[k - 1][1];
            float d = sqrtf((x1 - x0) * (x1 - x0) + (y1 - y0) * (y1 - y0));
            int steps = (int)(d / 1.6f) + 1;
            if (steps > 40) steps = 40;
            for (int j = 0; j < steps; j++) {
                float u = (float)j / steps;
                float f = 1.f - ((float)k - u) / TRAIL;
                orb__splat(&s, x0 + (x1 - x0) * u, y0 + (y1 - y0) * u, c->size * shrink * (0.22f + 0.55f * f), col,
                           0.20f * f * f * fade);
            }
        }
        float hx = c->tr[0][0], hy = c->tr[0][1];
        orb__splat(&s, hx, hy, c->size * 3.2f * shrink, col, 0.10f * fade);
        orb__splat(&s, hx, hy, c->size * 1.7f * shrink, col, 0.35f * fade);
        orb__splat(&s, hx, hy, c->size * 0.9f * shrink, hot, 0.95f * fade);
    }
}

/* label pills: background in the DIB, text in the GDI pass */
typedef struct { int on; int x, y, w, h, color; float a; const char *txt; } pill_t;
static pill_t g_pills[PMAX];

static void comet_labels_bg(void) {
    for (int i = 0; i < PMAX; i++) {
        comet_t *c = &g_comets[i]; pill_t *p = &g_pills[i];
        p->on = 0;
        if (!c->alive || !c->labeled || c->tn < 2) continue;
        float a = comet_fade(c);
        if (c->dir == BW_FLOW_IN) a *= clampf((1.f - c->t) / 0.3f, 0.f, 1.f);   /* fade before diving in */
        else a *= clampf((1.f - c->t) / 0.45f, 0.f, 1.f);
        if (a < 0.05f) continue;
        float hx = c->tr[0][0], hy = c->tr[0][1];
        float vx = c->tr[0][0] - c->tr[1][0], vy = c->tr[0][1] - c->tr[1][1], L = sqrtf(vx * vx + vy * vy) + 1e-3f;
        float nx = -vy / L, ny = vx / L;                   /* label sits beside the comet, not on its path */
        float odx = hx - g_orb_cx, ody = hy - g_orb_cy;
        if (odx * odx + ody * ody < (g_orb_R * 1.45f) * (g_orb_R * 1.45f)) continue;   /* never on the sphere */
        int tw = text_width(g_f_tiny, c->label);
        int w = tw + 16, h = 19;
        int x = (int)(hx + nx * 14.f - (nx < 0 ? w : 0)), y = (int)(hy + ny * 14.f - h / 2);
        if (x < 4 || y < 66 || x + w > g_W - 4 || y + h > g_btn[0].r.top - 6) continue;
        {   /* the whole label stays off the sphere, not just the comet head */
            float qx = fmaxf((float)x, fminf(g_orb_cx, (float)(x + w))), qy = fmaxf((float)y, fminf(g_orb_cy, (float)(y + h)));
            if ((qx - g_orb_cx) * (qx - g_orb_cx) + (qy - g_orb_cy) * (qy - g_orb_cy) < (g_orb_R * 1.3f) * (g_orb_R * 1.3f)) continue;
        }
        RECT me = { x - 4, y - 3, x + w + 4, y + h + 3 }, band = { 0, g_y_state - 4, g_W, g_y_legend + 26 }, tmp;
        if (IntersectRect(&tmp, &me, &band)) continue;
        int clash = 0;
        for (int j = 0; j < i && !clash; j++) {
            if (!g_pills[j].on) continue;
            RECT o = { g_pills[j].x, g_pills[j].y, g_pills[j].x + g_pills[j].w, g_pills[j].y + g_pills[j].h };
            if (IntersectRect(&tmp, &me, &o)) clash = 1;
        }
        if (clash) continue;
        int col = c->dir == BW_FLOW_OUT ? C_OUT : C_IN;
        px_rrect(x, y, w, h, 9.5f, 0x090C18, 0.78f * a, col, 0.70f * a);
        p->on = 1; p->x = x; p->y = y; p->w = w; p->h = h; p->color = col; p->a = a; p->txt = c->label;
    }
}
static void comet_labels_text(void) {
    for (int i = 0; i < PMAX; i++) {
        pill_t *p = &g_pills[i];
        if (!p->on) continue;
        text_at(g_f_tiny, mix_rgb(0x090C18, mix_rgb(p->color, 0xFFFFFF, 0.35f), p->a), p->x, p->y, p->w, p->h,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE, p->txt);
    }
}

/* ---- layout ----------------------------------------------------------------- */
static int g_ntiles = 6, g_tile_of[6] = {0, 1, 2, 3, 4, 5}, g_btn_short = 0;

/* Responsive: full layout on desktop sizes, compact below 700 px, one tile row below 560 px
 * (800x600-era screens), narrow buttons with short labels below ~700 px width. */
static void layout(int W, int H) {
    int pad = g_pad, compact = H < 700, tiny = H < 560;
    int top = compact ? 62 : 66, btnH = compact ? 36 : 40, gap = compact ? 8 : 10, tileH = compact ? 52 : 62;
    int textH = compact ? 78 : 90, feedMin = tiny ? 72 : compact ? 84 : 150;
    g_ntiles = tiny ? 3 : 6;
    static const int all[6] = {0, 1, 2, 3, 4, 5}, few[3] = {1, 2, 3};   /* tiny: SESSION, RPC CALLS, NETWORK */
    for (int k = 0; k < g_ntiles; k++) g_tile_of[k] = tiny ? few[k] : all[k];
    int rows = g_ntiles / 3;
    int fixed = top + textH + rows * tileH + (rows - 1) * gap + 12 + feedMin + 12 + btnH + pad;
    int orbH = H - fixed;
    if (orbH < 110) orbH = 110;
    if (orbH > 400) orbH = 400;
    g_orb_cx = W * 0.5f; g_orb_cy = top + orbH * 0.5f; g_orb_R = orbH * 0.30f;
    g_y_state = top + orbH + 2; g_y_caption = g_y_state + (compact ? 20 : 22); g_y_legend = g_y_caption + (compact ? 24 : 28);
    int yt = g_y_state + textH - 2, tw = (W - 2 * pad - 2 * gap) / 3;
    for (int k = 0; k < g_ntiles; k++) {
        int x = pad + (k % 3) * (tw + gap), y = yt + (k / 3) * (tileH + gap);
        SetRect(&g_r_tiles[k], x, y, x + tw, y + tileH);
    }
    int by = H - pad - btnH;
    SetRect(&g_r_feed, pad, yt + rows * tileH + (rows - 1) * gap + 12, W - pad, by - 12);
    int widths[BTN_N] = { 140, 176, 200, 112 };
    int avail = W - 2 * pad, need = widths[0] + widths[1] + widths[2] + widths[3] + 2 * 10 + 16;
    g_btn_short = need > avail;
    if (g_btn_short) {                                   /* shrink the left group, keep Quit */
        float f = (float)(avail - widths[3] - 2 * 10 - 16) / (float)(widths[0] + widths[1] + widths[2]);
        for (int i = 0; i < 3; i++) widths[i] = (int)(widths[i] * f);
    }
    int x = pad;
    for (int i = 0; i < BTN_N; i++) {
        if (i == BTN_QUIT) SetRect(&g_btn[i].r, W - pad - widths[i], by, W - pad, by + btnH);
        else { SetRect(&g_btn[i].r, x, by, x + widths[i], by + btnH); x += widths[i] + 10; }
    }
    g_btn[BTN_RECONNECT].label = "Reconnect";                          g_btn[BTN_RECONNECT].kind = 0;
    g_btn[BTN_FLOWS].label     = g_btn_short ? "Flows" : "View flows"; g_btn[BTN_FLOWS].kind = 1;
    g_btn[BTN_CONSOLE].label   = "Show console";                       g_btn[BTN_CONSOLE].kind = 1;
    g_btn[BTN_QUIT].label      = "Quit";                               g_btn[BTN_QUIT].kind = 2;
    g_static_ok = 0;
}

/* background + glass cards: rebuilt only on resize */
static void build_static(void) {
    for (int y = 0; y < g_H; y++) {
        float f = (float)y / (g_H > 1 ? g_H - 1 : 1);
        int r = (int)(0x05 + (0x0D - 0x05) * f), g = (int)(0x07 + (0x0B - 0x07) * f), b = (int)(0x0F + (0x1F - 0x0F) * f);
        uint32_t c = (uint32_t)(r << 16 | g << 8 | b), *row = &g_px[y * g_W];
        for (int x = 0; x < g_W; x++) row[x] = c;
    }
    /* faint grid dots: a little depth behind the comets */
    for (int y = 28; y < g_H; y += 28) for (int x = 28; x < g_W; x += 28) px_blend(x, y, 0x3A4270, 0.35f);
    for (int i = 0; i < g_ntiles; i++) {
        RECT *r = &g_r_tiles[i];
        px_rrect(r->left, r->top, r->right - r->left, r->bottom - r->top, 14.f, 0x111530, 0.62f, 0xFFFFFF, 0.13f);
    }
    px_rrect(g_r_feed.left, g_r_feed.top, g_r_feed.right - g_r_feed.left, g_r_feed.bottom - g_r_feed.top, 16.f, 0x0F1228, 0.66f, 0xFFFFFF, 0.12f);
    memcpy(g_static, g_px, (size_t)g_W * g_H * 4);
    g_static_ok = 1;
}

/* ---- buttons ---------------------------------------------------------------- */
static int btn_accent(int i) { return i == BTN_QUIT ? C_ERR : i == BTN_FLOWS ? C_OUT : i == BTN_CONSOLE ? C_VIOLET : C_CYAN; }
static int btn_on(int i) { return (i == BTN_FLOWS && g_show_flows) || (i == BTN_CONSOLE && bw_console_visible()); }

static void draw_icon(int i, float cx, float cy, int ink) {
    float w = 1.8f;
    if (i == BTN_RECONNECT) {
        px_arc(cx, cy, 6.5f, -0.7f, 4.4f, w, ink, 1.f);
        float ex = cx + cosf(-0.7f) * 6.5f, ey = cy + sinf(-0.7f) * 6.5f;
        px_line(ex, ey, ex - 4.2f, ey - 0.6f, w, ink, 1.f);
        px_line(ex, ey, ex + 0.4f, ey + 4.2f, w, ink, 1.f);
    } else if (i == BTN_FLOWS) {
        px_disc(cx, cy, 2.4f, ink, 1.f);
        float an[3] = { -0.5f, 1.6f, 3.6f };
        for (int k = 0; k < 3; k++) {
            float ux = cosf(an[k]), uy = sinf(an[k]);
            px_line(cx + ux * 4.f, cy + uy * 4.f, cx + ux * 7.5f, cy + uy * 7.5f, 1.3f, ink, 0.55f);
            px_disc(cx + ux * 8.6f, cy + uy * 8.6f, 1.7f, ink, 1.f);
        }
    } else if (i == BTN_CONSOLE) {
        px_rrect((int)(cx - 8), (int)(cy - 6.5f), 16, 13, 3.f, ink, 0.f, ink, 1.f);
        px_line(cx - 4.5f, cy - 2.5f, cx - 1.5f, cy, 1.5f, ink, 1.f);
        px_line(cx - 1.5f, cy, cx - 4.5f, cy + 2.5f, 1.5f, ink, 1.f);
        px_line(cx + 0.5f, cy + 3.f, cx + 4.5f, cy + 3.f, 1.5f, ink, 1.f);
    } else {
        px_arc(cx, cy + 0.5f, 6.5f, -1.05f, 4.19f, w, ink, 1.f);
        px_line(cx, cy - 8.f, cx, cy - 1.f, w, ink, 1.f);
    }
}

static void draw_button_bg(int i) {
    button_t *b = &g_btn[i];
    int x = b->r.left, y = b->r.top, w = b->r.right - b->r.left, h = b->r.bottom - b->r.top;
    int acc = btn_accent(i), on = btn_on(i);
    int hov = g_hover == i, press = g_pressed == i && hov;
    float rad = h * 0.5f;
    if (on) px_rrect(x - 3, y - 3, w + 6, h + 6, rad + 3, acc, 0.07f, acc, 0.f);            /* soft glow */
    float fa = press ? 0.30f : on ? (hov ? 0.22f : 0.15f) : hov ? 0.10f : 0.05f;
    int fill = (press || on) ? acc : 0xFFFFFF;
    float ba = on ? 0.85f : hov ? 0.60f : 0.18f;
    int border = (on || hov) ? acc : 0xFFFFFF;
    if (b->kind == 2 && !hov) { border = acc; ba = 0.35f; }
    px_rrect(x, y, w, h, rad, fill, fa, border, ba);
    if (g_focus == i) px_rrect(x - 4, y - 4, w + 8, h + 8, rad + 4, 0, 0.f, 0xFFFFFF, 0.85f);
    int ink = on ? mix_rgb(acc, 0xFFFFFF, 0.25f) : (hov ? 0xFFFFFF : 0xD8DEF5);
    if (b->kind == 2 && hov) ink = mix_rgb(acc, 0xFFFFFF, 0.3f);
    draw_icon(i, x + 22.f, y + h * 0.5f, ink);
    if (b->kind == 1) {                                   /* switch affordance on toggles */
        int sw = 26, sh = 14, sx = x + w - sw - 14, sy = y + (h - sh) / 2;
        px_rrect(sx, sy, sw, sh, sh * 0.5f, on ? acc : 0x2A3150, on ? 0.55f : 0.9f, on ? acc : 0x5C6484, 0.6f);
        px_disc(on ? sx + sw - 7.f : sx + 7.f, sy + sh * 0.5f, 4.6f, on ? 0xFFFFFF : 0x9AA3C7, 1.f);
    }
}
static void draw_button_text(int i) {
    button_t *b = &g_btn[i];
    int on = btn_on(i), hov = g_hover == i;
    const char *lbl = b->label;
    if (i == BTN_CONSOLE) lbl = g_btn_short ? "Console" : on ? "Hide console" : "Show console";
    int col = on || hov ? 0xFFFFFF : 0xD8DEF5;
    if (b->kind == 2) col = hov ? 0xFFFFFF : 0xFFB3B3;
    int right = b->kind == 1 ? 44 : 12;
    text_at(g_f_btn, col, b->r.left + 40, b->r.top, (b->r.right - b->r.left) - 40 - right, b->r.bottom - b->r.top,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS, lbl);
}
static int btn_hit(int x, int y) {
    for (int i = 0; i < BTN_N; i++) { POINT p = { x, y }; if (PtInRect(&g_btn[i].r, p)) return i; }
    return -1;
}
static void flows_pref_save(void) {
    HKEY k;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\OpenBridge\\BridgeAgent", 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) == ERROR_SUCCESS) {
        DWORD v = (DWORD)g_show_flows; RegSetValueExA(k, "ShowFlows", 0, REG_DWORD, (const BYTE *)&v, sizeof(v)); RegCloseKey(k);
    }
}
static void flows_pref_load(void) {
    HKEY k; DWORD v = 1, sz = sizeof(v), type = 0;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\OpenBridge\\BridgeAgent", 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "ShowFlows", NULL, &type, (BYTE *)&v, &sz) == ERROR_SUCCESS && type == REG_DWORD) g_show_flows = v ? 1 : 0;
        RegCloseKey(k);
    }
}
static void btn_activate(int i) {
    if (i == BTN_RECONNECT) { bw_force_reconnect(); orb_pulse(&g_orb); feed_push(1, "Reconnect requested from the status window."); }
    else if (i == BTN_FLOWS) {
        g_show_flows = !g_show_flows; flows_pref_save();
        if (!g_show_flows) for (int k = 0; k < PMAX; k++) g_comets[k].alive = 0;
    }
    else if (i == BTN_CONSOLE) bw_console_toggle();
    else if (i == BTN_QUIT) PostMessageA(g_wnd, WM_CLOSE, 0, 0);
}

/* ---- orb mood ---------------------------------------------------------------- */
static int g_mood = ORB_OFFLINE;
static int g_busy[2];                        /* hysteresis per direction */
static const char *link_word(int *accent) {
    int err = g_snap.last_error[0] != 0;
    if (err && g_snap.state != BW_STATE_CONNECTED) { *accent = C_ERR; return "ATTENTION"; }
    if (g_snap.state == BW_STATE_CONNECTED) { *accent = C_OK; return "CONNECTED"; }
    if (g_snap.state == BW_STATE_CONNECTING) { *accent = C_VIOLET; return "CONNECTING"; }
    *accent = C_MUTED; return "OFFLINE";
}
static const char *mood_word(int *accent) {
    int err = g_snap.last_error[0] != 0;
    if (err && g_snap.state != BW_STATE_CONNECTED) { *accent = C_ERR; g_mood = ORB_ERROR; return "ATTENTION"; }
    if (g_snap.state == BW_STATE_CONNECTED) {
        for (int d = 0; d < 2; d++) g_busy[d] = g_busy[d] ? g_act_dir[d] > 0.10f : g_act_dir[d] > 0.24f;
        if (g_busy[0] && g_busy[1]) { *accent = 0xFFD27A; g_mood = ORB_SPEAK; return "EXCHANGING"; }
        if (g_busy[BW_FLOW_OUT]) { *accent = C_OUT; g_mood = ORB_SPEAK; return "SENDING"; }
        if (g_busy[BW_FLOW_IN]) { *accent = C_IN; g_mood = ORB_LISTEN; return "RECEIVING"; }
        *accent = C_CYAN; g_mood = ORB_IDLE; return "LINKED";
    }
    if (g_snap.state == BW_STATE_CONNECTING) { *accent = C_VIOLET; g_mood = ORB_THINK; return "CONNECTING"; }
    *accent = C_MUTED; g_mood = ORB_OFFLINE; return "OFFLINE";
}

/* ---- one frame ------------------------------------------------------------------ */
static void render(void) {
    if (!g_px || g_W <= 0 || g_H <= 0) return;
    GdiFlush();
    if (!g_static_ok) build_static(); else memcpy(g_px, g_static, (size_t)g_W * g_H * 4);
    int accent; const char *word = mood_word(&accent);
    orb_surface s = { g_px, g_W, g_W, g_H };
    orb_render(&g_orb, &s, g_orb_cx, g_orb_cy, g_orb_R, fmaxf(1.4f, g_orb_R / 42.f));
    comets_draw();

    /* CPU bar inside the "THIS PC" tile */
    for (int k = 0; k < g_ntiles; k++) {
        if (g_tile_of[k] != 4) continue;
        RECT *tp = &g_r_tiles[k];
        int bw = (tp->right - tp->left) - 28;
        int by0 = (tp->bottom - tp->top) < 60 ? tp->bottom - 7 : tp->bottom - 12;
        px_rrect(tp->left + 14, by0, bw, 4, 2.f, 0x2A3150, 0.9f, 0, 0.f);
        px_rrect(tp->left + 14, by0, (int)(bw * clampf((float)g_snap.cpu_pct / 100.f, 0.02f, 1.f)), 4, 2.f,
                 g_snap.cpu_pct > 80 ? C_ERR : g_snap.cpu_pct > 50 ? C_WARN : C_OK, 0.95f, 0, 0.f);
    }

    comet_labels_bg();

    /* status chip (top-right) */
    int chip_acc; const char *chip_word = link_word(&chip_acc);
    int cw = text_width(g_f_small, chip_word) + 44, ch = 30;
    SetRect(&g_r_chip, g_W - g_pad - cw, 20, g_W - g_pad, 20 + ch);
    px_rrect(g_r_chip.left, g_r_chip.top, cw, ch, ch * 0.5f, chip_acc, 0.12f, chip_acc, 0.70f);
    float pulse = 0.55f + 0.45f * sinf(g_orb.t * 4.f);
    { float c[3]; rgbf(chip_acc, c); orb__splat(&s, g_r_chip.left + 17.f, g_r_chip.top + ch * 0.5f, 7.f, c, 0.25f * pulse); }
    px_disc(g_r_chip.left + 17.f, g_r_chip.top + ch * 0.5f, 4.f, chip_acc, 1.f);

    /* flow legend pills */
    char out_t[96], in_t[96], ro[24], ri[24];
    fmt_bytes((uint64_t)g_rate[BW_FLOW_OUT], ro, sizeof(ro)); fmt_bytes((uint64_t)g_rate[BW_FLOW_IN], ri, sizeof(ri));
    snprintf(out_t, sizeof(out_t), "\xE2\x86\x91 OUT  %llu msgs  \xC2\xB7  %s/s", (unsigned long long)g_msgs[BW_FLOW_OUT], ro);
    snprintf(in_t, sizeof(in_t), "\xE2\x86\x93 IN  %llu msgs  \xC2\xB7  %s/s", (unsigned long long)g_msgs[BW_FLOW_IN], ri);
    int wo = text_width(g_f_tiny, out_t) + 30, wi = text_width(g_f_tiny, in_t) + 30, lh = 22;
    int lx = (g_W - (wo + wi + 12)) / 2;
    float ao = 0.5f + 0.5f * clampf(g_act_dir[BW_FLOW_OUT], 0.f, 1.f), ai = 0.5f + 0.5f * clampf(g_act_dir[BW_FLOW_IN], 0.f, 1.f);
    px_rrect(lx, g_y_legend, wo, lh, lh * 0.5f, C_OUT, 0.06f + 0.10f * g_act_dir[BW_FLOW_OUT], C_OUT, 0.45f * ao);
    px_disc(lx + 13.f, g_y_legend + lh * 0.5f, 3.5f, C_OUT, ao);
    px_rrect(lx + wo + 12, g_y_legend, wi, lh, lh * 0.5f, C_IN, 0.06f + 0.10f * g_act_dir[BW_FLOW_IN], C_IN, 0.45f * ai);
    px_disc(lx + wo + 25.f, g_y_legend + lh * 0.5f, 3.5f, C_IN, ai);

    /* feed: level dots */
    int fx = g_r_feed.left + 18, fy = g_r_feed.top + ((g_r_feed.bottom - g_r_feed.top) < 100 ? 34 : 40), rh = 22;
    int rows = (g_r_feed.bottom - fy - 10) / rh; if (rows < 0) rows = 0;
    for (int i = 0; i < g_feed_count && i < rows; i++) {
        feed_t *e = &g_feed[(g_feed_head - 1 - i + FEED_CAP * 2) % FEED_CAP];
        px_disc(fx + 3.f, fy + i * rh + rh * 0.5f, 3.f, level_color(e->level), i == 0 ? 1.f : 0.6f);
    }
    for (int i = 0; i < BTN_N; i++) draw_button_bg(i);

    /* ---- text pass ---- */
    SetTextCharacterExtra(g_memdc, 3);
    text_at(g_f_brand, C_CYAN, g_pad, 18, 300, 16, DT_LEFT | DT_SINGLELINE, "BRIDGE AGENT");
    SetTextCharacterExtra(g_memdc, 0);
    char idl[200];
    snprintf(idl, sizeof(idl), "%s", g_snap.agent_id[0] ? g_snap.agent_id : "agent");
    text_at(g_f_id, C_TEXT, g_pad, 36, g_W / 2, 26, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS, idl);
    int iw = text_width(g_f_id, idl);
    snprintf(idl, sizeof(idl), "v%s  \xC2\xB7  %s  \xC2\xB7  Windows", g_snap.version, g_snap.arch);
    text_at(g_f_small, C_MUTED, g_pad + iw + 12, 42, g_W / 2, 20, DT_LEFT | DT_SINGLELINE, idl);
    text_at(g_f_small, chip_acc, g_r_chip.left + 30, g_r_chip.top, cw - 34, ch, DT_LEFT | DT_VCENTER | DT_SINGLELINE, chip_word);

    SetTextCharacterExtra(g_memdc, 5);
    text_at(g_f_state, accent, 0, g_y_state, g_W, 20, DT_CENTER | DT_SINGLELINE, word);
    SetTextCharacterExtra(g_memdc, 0);
    char cap[320], se[32];
    fmt_dur(g_snap.session_uptime_s, se, sizeof(se));
    if (g_mood == ORB_ERROR) snprintf(cap, sizeof(cap), "%s", g_snap.last_error);
    else if (g_snap.state == BW_STATE_CONNECTED) snprintf(cap, sizeof(cap), "Linked to %s  \xC2\xB7  session %s", g_snap.master, se);
    else if (g_snap.state == BW_STATE_CONNECTING) snprintf(cap, sizeof(cap), "Authenticating with %s\xE2\x80\xA6", g_snap.master);
    else snprintf(cap, sizeof(cap), "Waiting for the master at %s", g_snap.master);
    text_at(g_f_cap, C_MUTED, g_pad, g_y_caption, g_W - 2 * g_pad, 22, DT_CENTER | DT_SINGLELINE | DT_END_ELLIPSIS, cap);
    text_at(g_f_tiny, mix_rgb(C_MUTED, C_OUT, ao), lx + 22, g_y_legend, wo - 26, lh, DT_LEFT | DT_VCENTER | DT_SINGLELINE, out_t);
    text_at(g_f_tiny, mix_rgb(C_MUTED, C_IN, ai), lx + wo + 12 + 22, g_y_legend, wi - 26, lh, DT_LEFT | DT_VCENTER | DT_SINGLELINE, in_t);

    char rx[32], tx[32], up[32], v[6][80];
    const char *tl[6] = { "UPTIME", "SESSION", "RPC CALLS", "NETWORK", "THIS PC", "RECONNECTS" };
    fmt_bytes(g_snap.bytes_rx, rx, sizeof(rx)); fmt_bytes(g_snap.bytes_tx, tx, sizeof(tx));
    fmt_dur(g_snap.uptime_s, up, sizeof(up));
    snprintf(v[0], 80, "%s", up);
    snprintf(v[1], 80, "%s", g_snap.state == BW_STATE_CONNECTED ? se : "\xE2\x80\x94");
    snprintf(v[2], 80, "%llu", (unsigned long long)g_snap.rpc_total);
    snprintf(v[3], 80, "\xE2\x86\x93 %s   \xE2\x86\x91 %s", rx, tx);
    snprintf(v[4], 80, "CPU %.0f%%  \xC2\xB7  %llu MB free", g_snap.cpu_pct, (unsigned long long)g_snap.ram_avail_mb);
    snprintf(v[5], 80, "%llu", (unsigned long long)g_snap.reconnects);
    for (int k = 0; k < g_ntiles; k++) {
        int i = g_tile_of[k];
        RECT *r = &g_r_tiles[k];
        SetTextCharacterExtra(g_memdc, 2);
        text_at(g_f_tiny, C_FAINT, r->left + 14, r->top + 10, r->right - r->left - 24, 14, DT_LEFT | DT_SINGLELINE, tl[i]);
        SetTextCharacterExtra(g_memdc, 0);
        int vc = i == 2 ? C_CYAN : i == 0 ? C_OK : C_TEXT;
        int vy = (r->bottom - r->top) < 60 ? 23 : 27;
        text_at(g_f_val, vc, r->left + 14, r->top + vy, r->right - r->left - 24, 24, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS, v[i]);
    }

    SetTextCharacterExtra(g_memdc, 2);
    text_at(g_f_tiny, C_MUTED, g_r_feed.left + 18, g_r_feed.top + 14, 200, 16, DT_LEFT | DT_SINGLELINE, "ACTIVITY");
    SetTextCharacterExtra(g_memdc, 0);
    text_at(g_f_tiny, C_FAINT, g_r_feed.right - 260, g_r_feed.top + 14, 242, 16, DT_RIGHT | DT_SINGLELINE,
            "F flows  \xC2\xB7  C console  \xC2\xB7  R reconnect");
    for (int i = 0; i < g_feed_count && i < rows; i++) {
        feed_t *e = &g_feed[(g_feed_head - 1 - i + FEED_CAP * 2) % FEED_CAP];
        int y = fy + i * rh;
        text_at(g_f_mono, C_FAINT, fx + 14, y, 70, rh, DT_LEFT | DT_VCENTER | DT_SINGLELINE, e->time);
        text_at(g_f_tiny, level_color(e->level), fx + 86, y, 48, rh, DT_LEFT | DT_VCENTER | DT_SINGLELINE, level_tag(e->level));
        text_at(g_f_ui, i == 0 ? C_TEXT : C_MUTED, fx + 138, y, g_r_feed.right - fx - 156, rh,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS, e->msg);
    }
    comet_labels_text();
    for (int i = 0; i < BTN_N; i++) draw_button_text(i);
}

/* ---- back buffer --------------------------------------------------------------- */
static void ensure_backbuffer(int W, int H) {
    if (W <= 0 || H <= 0) return;
    if (g_dib && W == g_W && H == g_H) return;
    if (!g_memdc) g_memdc = CreateCompatibleDC(NULL);
    if (g_dib) { SelectObject(g_memdc, g_dib_old); DeleteObject(g_dib); g_dib = NULL; g_px = NULL; }
    BITMAPINFO bi; ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = W; bi.bmiHeader.biHeight = -H;
    bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32; bi.bmiHeader.biCompression = BI_RGB;
    g_dib = CreateDIBSection(g_memdc, &bi, DIB_RGB_COLORS, (void **)&g_px, NULL, 0);
    if (!g_dib) { g_px = NULL; return; }
    g_dib_old = (HBITMAP)SelectObject(g_memdc, g_dib);
    free(g_static); g_static = (uint32_t *)malloc((size_t)W * H * 4);
    g_W = W; g_H = H;
    for (int i = 0; i < PMAX; i++) g_comets[i].alive = 0;     /* geometry changed */
    layout(W, H);
}

/* ---- per-tick update -------------------------------------------------------------- */
static LARGE_INTEGER g_qpf, g_last_qpc;
static void tick(HWND w) {
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    float dt = g_last_qpc.QuadPart ? (float)((now.QuadPart - g_last_qpc.QuadPart) / (double)g_qpf.QuadPart) : FRAME_MS / 1000.f;
    g_last_qpc = now;
    if (dt > 0.1f) dt = 0.1f;

    bw_snapshot(&g_snap);
    bw_drain_logs(&g_last_seq, feed_drain_cb, NULL);
    g_spawn_budget[0] = g_spawn_budget[1] = 5;
    bw_drain_flows(&g_flow_seq, flow_drain_cb, NULL);

    DWORD t = GetTickCount();
    if (!g_rate_tick) g_rate_tick = t;
    if (t - g_rate_tick >= 500) {
        float k = 1000.f / (float)(t - g_rate_tick);
        for (int d = 0; d < 2; d++) { g_rate[d] = g_rate[d] * 0.4 + g_rate_acc[d] * k * 0.6; g_rate_acc[d] = 0; }
        g_rate_tick = t;
    }
    for (int d = 0; d < 2; d++) g_act_dir[d] *= powf(0.25f, dt);

    if (g_prev_state != g_snap.state) { orb_pulse(&g_orb); g_prev_state = g_snap.state; }
    int accent; (void)mood_word(&accent);
    g_orb.state = g_mood;                    /* mood changes recolour smoothly; the ring is for link changes only */
    float lvl = fmaxf(g_act_dir[0], g_act_dir[1]);
    if (lvl > 0.02f) orb_level(&g_orb, lvl * 0.85f);
    orb_step(&g_orb, dt);
    comets_step(dt);
    if (!IsIconic(w)) InvalidateRect(w, NULL, FALSE);
}

/* ---- window proc -------------------------------------------------------------------- */
static HFONT mkfont(int h, int weight, const char *face) {
    return CreateFontA(-h, 0, 0, 0, weight, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH, face);
}
static void dark_titlebar(HWND w) {
    typedef HRESULT (WINAPI *dwmset_t)(HWND, DWORD, LPCVOID, DWORD);
    HMODULE dwm = LoadLibraryA("dwmapi.dll");
    if (!dwm) return;
    dwmset_t fn = (dwmset_t)(void *)GetProcAddress(dwm, "DwmSetWindowAttribute");
    BOOL on = TRUE;
    if (fn && fn(w, 20, &on, sizeof(on)) != S_OK) fn(w, 19, &on, sizeof(on));   /* Win10 1809+/Win11; ignored elsewhere */
}

static LRESULT CALLBACK wnd_proc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE:
        g_f_brand = mkfont(12, FW_BOLD, "Segoe UI");
        g_f_id    = mkfont(20, FW_SEMIBOLD, "Segoe UI");
        g_f_ui    = mkfont(14, FW_NORMAL, "Segoe UI");
        g_f_small = mkfont(13, FW_SEMIBOLD, "Segoe UI");
        g_f_tiny  = mkfont(12, FW_SEMIBOLD, "Segoe UI");
        g_f_val   = mkfont(18, FW_SEMIBOLD, "Segoe UI");
        g_f_state = mkfont(14, FW_BOLD, "Segoe UI");
        g_f_cap   = mkfont(15, FW_NORMAL, "Segoe UI");
        g_f_btn   = mkfont(14, FW_SEMIBOLD, "Segoe UI");
        g_f_mono  = mkfont(13, FW_NORMAL, "Consolas");
        dark_titlebar(w);
        bw_snapshot(&g_snap);
        QueryPerformanceFrequency(&g_qpf);
        SetTimer(w, TIMER_ID, FRAME_MS, NULL);
        return 0;
    case WM_SIZE: {
        int W = LOWORD(lp), H = HIWORD(lp);
        if (W > 0 && H > 0) { ensure_backbuffer(W, H); InvalidateRect(w, NULL, FALSE); }
        return 0;
    }
    case WM_GETMINMAXINFO: { MINMAXINFO *mmi = (MINMAXINFO *)lp; mmi->ptMinTrackSize.x = 640; mmi->ptMinTrackSize.y = 480; return 0; }
    case WM_ERASEBKGND: return 1;
    case WM_TIMER: if (wp == TIMER_ID) tick(w); return 0;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(w, &ps);
        if (g_px) { render(); BitBlt(dc, 0, 0, g_W, g_H, g_memdc, 0, 0, SRCCOPY); }
        EndPaint(w, &ps);
        return 0;
    }
    case WM_SETCURSOR:
        if (LOWORD(lp) == HTCLIENT && g_hover >= 0) { SetCursor(LoadCursor(NULL, IDC_HAND)); return TRUE; }
        break;
    case WM_MOUSEMOVE: {
        int hit = btn_hit((short)LOWORD(lp), (short)HIWORD(lp));
        if (hit != g_hover) g_hover = hit;
        if (!g_tracking) { TRACKMOUSEEVENT t = { sizeof(t), TME_LEAVE, w, 0 }; TrackMouseEvent(&t); g_tracking = 1; }
        return 0;
    }
    case WM_MOUSELEAVE: g_hover = -1; g_tracking = 0; return 0;
    case WM_LBUTTONDOWN: g_pressed = btn_hit((short)LOWORD(lp), (short)HIWORD(lp)); if (g_pressed >= 0) SetCapture(w); return 0;
    case WM_LBUTTONUP: {
        int hit = btn_hit((short)LOWORD(lp), (short)HIWORD(lp)), p = g_pressed;
        g_pressed = -1; ReleaseCapture();
        if (p >= 0 && hit == p) btn_activate(p);
        return 0;
    }
    case WM_KEYDOWN:
        if (wp == VK_TAB) { int back = GetKeyState(VK_SHIFT) < 0; g_focus = g_focus < 0 ? (back ? BTN_N - 1 : 0) : (g_focus + (back ? BTN_N - 1 : 1)) % BTN_N; }
        else if ((wp == VK_RETURN || wp == VK_SPACE) && g_focus >= 0) btn_activate(g_focus);
        else if (wp == VK_ESCAPE) g_focus = -1;
        else if (wp == 'F') btn_activate(BTN_FLOWS);
        else if (wp == 'C') btn_activate(BTN_CONSOLE);
        else if (wp == 'R') btn_activate(BTN_RECONNECT);
        return 0;
    case WM_CLOSE: {
        int r = MessageBoxA(w, "Stop the agent and disconnect from the master?", "Bridge Agent",
                            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
        if (r == IDYES) { KillTimer(w, TIMER_ID); bw_quit(); DestroyWindow(w); }
        return 0;
    }
    case WM_DESTROY:
        KillTimer(w, TIMER_ID);
        if (g_dib) { SelectObject(g_memdc, g_dib_old); DeleteObject(g_dib); g_dib = NULL; g_px = NULL; }
        if (g_memdc) { DeleteDC(g_memdc); g_memdc = NULL; }
        free(g_static); g_static = NULL;
        DeleteObject(g_f_brand); DeleteObject(g_f_id); DeleteObject(g_f_ui); DeleteObject(g_f_small); DeleteObject(g_f_tiny);
        DeleteObject(g_f_val); DeleteObject(g_f_state); DeleteObject(g_f_cap); DeleteObject(g_f_btn); DeleteObject(g_f_mono);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(w, m, wp, lp);
}

/* ---- thread + lifecycle ---------------------------------------------------------------- */
static DWORD WINAPI gui_thread(LPVOID arg) {
    (void)arg;
    srand((unsigned)GetTickCount());
    orb_init(&g_orb);
    flows_pref_load();
    WNDCLASSA wc; ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hIcon = LoadIconA(NULL, IDI_APPLICATION);
    wc.hbrBackground = NULL;
    wc.lpszClassName = "BridgeAgentGUI";
    if (!RegisterClassA(&wc)) { InterlockedExchange(&g_gui_ok, 0); SetEvent(g_ready_ev); return 1; }
    RECT r = { 0, 0, 980, 820 };
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    RECT wa; SystemParametersInfoA(SPI_GETWORKAREA, 0, &wa, 0);
    int ww = r.right - r.left, wh = r.bottom - r.top;
    if (ww > (wa.right - wa.left) * 95 / 100) ww = (wa.right - wa.left) * 95 / 100;
    if (wh > (wa.bottom - wa.top) * 95 / 100) wh = (wa.bottom - wa.top) * 95 / 100;
    g_wnd = CreateWindowExA(0, "BridgeAgentGUI", "Bridge Agent", WS_OVERLAPPEDWINDOW,
                            CW_USEDEFAULT, CW_USEDEFAULT, ww, wh, NULL, NULL, GetModuleHandleA(NULL), NULL);
    if (!g_wnd) { InterlockedExchange(&g_gui_ok, 0); SetEvent(g_ready_ev); return 1; }
    ShowWindow(g_wnd, SW_SHOW); UpdateWindow(g_wnd);
    InterlockedExchange(&g_gui_ok, 1); SetEvent(g_ready_ev);
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    g_wnd = NULL;
    return 0;
}

bool gui_start(void) {
    if (g_gui_thread) return true;
    g_ready_ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_ready_ev) return false;
    g_gui_thread = CreateThread(NULL, 0, gui_thread, NULL, 0, NULL);
    if (!g_gui_thread) { CloseHandle(g_ready_ev); g_ready_ev = NULL; return false; }
    WaitForSingleObject(g_ready_ev, 10000);
    CloseHandle(g_ready_ev); g_ready_ev = NULL;
    if (!InterlockedCompareExchange(&g_gui_ok, 1, 1)) { CloseHandle(g_gui_thread); g_gui_thread = NULL; return false; }
    return true;
}

void gui_stop(void) {
    /* Direct destroy: no confirmation box on the shutdown path. */
    if (g_wnd) PostMessageA(g_wnd, WM_DESTROY, 0, 0);
    if (g_gui_thread) { WaitForSingleObject(g_gui_thread, 3000); CloseHandle(g_gui_thread); g_gui_thread = NULL; }
}
