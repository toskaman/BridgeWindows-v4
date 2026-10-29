/* =========================================================================
 * orb_core.h - "voice" presence orb shared by every Bridge agent build
 * (Windows GDI window, Linux terminal HUD). Header-only, C99, libm only.
 *
 * A 3D particle sphere with a halo, a glowing core and Siri-style ribbons,
 * rendered additively into a 0x00RRGGBB pixel buffer. The agent feeds it
 * activity (state, level, bumps, pulses) and the orb moves accordingly.
 * Same look and colour language as the OpenBridge Android companion.
 * ========================================================================= */
#ifndef BRIDGE_ORB_CORE_H
#define BRIDGE_ORB_CORE_H
#include <math.h>
#include <stdint.h>
#include <string.h>

#define ORB_IDLE      0   /* linked, nothing happening: slow breathing (cyan/violet) */
#define ORB_LISTEN    1   /* receiving data from the master (cyan/blue/mint)        */
#define ORB_THINK     2   /* handshake / waiting (violet swirl + orbiting arcs)     */
#define ORB_SPEAK     3   /* executing an RPC / answering (magenta/amber)           */
#define ORB_ALERT     4   /* warning (amber)                                         */
#define ORB_OFFLINE   5   /* no master (dim steel)                                   */
#define ORB_ERROR     6   /* error (red)                                             */
#define ORB_NSTATES   7

#define ORB_LAT 18
#define ORB_LON 46
#define ORB_N   (ORB_LAT * ORB_LON)

static const unsigned char ORB_PALETTE[ORB_NSTATES][3][3] = {
    {{ 64, 196, 255}, {124,  77, 255}, {  0, 229, 255}},
    {{  0, 229, 255}, { 41, 121, 255}, { 29, 233, 182}},
    {{179, 136, 255}, {101,  31, 255}, {  0, 176, 255}},
    {{255,  79, 216}, {140,  91, 255}, {255, 158,  94}},
    {{255, 183,  77}, {255, 110,  64}, {255, 213,  79}},
    {{ 96, 110, 140}, { 70,  78, 110}, {120, 140, 170}},
    {{255,  82,  82}, {255,  23,  68}, {255, 138, 128}},
};

typedef struct {
    float ux[ORB_N], uy[ORB_N], uz[ORB_N], la[ORB_N], lo[ORB_N], pw[ORB_N];
    int state;
    float input, burst;           /* external drive: level (decays), short bursts */
    float level, energy, think, voice, spin, t, pulse_age;
    float col[3][3];
} orb_t;

static inline float orb__clampf(float v, float a, float b) { return v < a ? a : v > b ? b : v; }

static inline void orb_init(orb_t *o) {
    memset(o, 0, sizeof(*o));
    int i = 0;
    for (int a = 0; a < ORB_LAT; a++) {
        double th = 3.14159265358979 * (a + 0.5) / ORB_LAT;
        for (int b = 0; b < ORB_LON; b++, i++) {
            double ph = 2 * 3.14159265358979 * (b + (a % 2) * 0.5) / ORB_LON;
            o->ux[i] = (float)(sin(th) * cos(ph));
            o->uy[i] = (float)cos(th);
            o->uz[i] = (float)(sin(th) * sin(ph));
            o->la[i] = (float)a / ORB_LAT;
            o->lo[i] = (float)b / ORB_LON;
            o->pw[i] = (float)pow(sin(th), 1.5);   /* calm poles: no loops where meridians converge */
        }
    }
    o->state = ORB_OFFLINE;
    o->pulse_age = 9.f;
    for (int k = 0; k < 3; k++) for (int c = 0; c < 3; c++) o->col[k][c] = ORB_PALETTE[ORB_OFFLINE][k][c];
}

static inline void orb_set_state(orb_t *o, int s) {
    if (s < 0 || s >= ORB_NSTATES) s = ORB_IDLE;
    if (s != o->state) { o->state = s; o->pulse_age = 0.f; }
}
static inline void orb_level(orb_t *o, float l) { l = orb__clampf(l, 0.f, 1.f); if (l > o->input) o->input = l; }
static inline void orb_bump(orb_t *o, float b) { b = orb__clampf(b, 0.f, 1.f); if (b > o->burst) o->burst = b; }
static inline void orb_pulse(orb_t *o) { o->pulse_age = 0.f; orb_bump(o, 0.6f); }

/* Advance the simulation by dt seconds (clamped). */
static inline void orb_step(orb_t *o, float dt) {
    dt = orb__clampf(dt, 0.f, 0.05f);
    o->t += dt;
    o->pulse_age += dt;
    int s = o->state;
    float in = o->input; o->input *= powf(0.25f, dt);
    float b = o->burst;  o->burst *= powf(0.04f, dt);
    float t = o->t, synth = 0.f;
    if (s == ORB_SPEAK) synth = 0.28f + 0.30f * fabsf(sinf(t * 8.7f) * sinf(t * 3.1f + 1.f));
    else if (s == ORB_THINK) synth = 0.18f + 0.08f * sinf(t * 2.4f);
    else if (s == ORB_IDLE || s == ORB_OFFLINE) synth = 0.04f + 0.03f * sinf(t * 1.1f);
    else if (s == ORB_ALERT || s == ORB_ERROR) synth = 0.25f + 0.15f * sinf(t * 4.f);
    else if (s == ORB_LISTEN) synth = 0.12f;
    float target = fminf(1.f, fmaxf(in, synth) + b * 0.6f);
    o->level += (target - o->level) * fminf(1.f, dt * (target > o->level ? 14.f : 5.f));
    float base = s == ORB_OFFLINE ? 0.05f : s == ORB_IDLE ? 0.12f : s == ORB_THINK ? 0.45f : 0.3f;
    o->energy += (base + o->level * 0.7f - o->energy) * fminf(1.f, dt * 4.f);
    o->think += ((s == ORB_THINK ? 1.f : 0.f) - o->think) * fminf(1.f, dt * 3.f);
    o->voice += ((s == ORB_SPEAK || s == ORB_LISTEN ? 1.f : 0.f) - o->voice) * fminf(1.f, dt * 3.f);
    o->spin += dt * (0.25f + 1.6f * o->think + 0.6f * o->energy);
    float f = fminf(1.f, dt * 3.5f);
    for (int k = 0; k < 3; k++) for (int c = 0; c < 3; c++)
        o->col[k][c] += (ORB_PALETTE[s][k][c] - o->col[k][c]) * f;
}

/* ---- additive pixel helpers (buffer is 0x00RRGGBB, row stride in pixels) ---- */
typedef struct { uint32_t *px; int stride, w, h; } orb_surface;

static inline void orb__add(orb_surface *s, int x, int y, float r, float g, float b, float a) {
    if (x < 0 || y < 0 || x >= s->w || y >= s->h || a <= 0.f) return;
    uint32_t *p = &s->px[y * s->stride + x], v = *p;
    int R = (int)((v >> 16) & 255) + (int)(r * a), G = (int)((v >> 8) & 255) + (int)(g * a), B = (int)(v & 255) + (int)(b * a);
    *p = (uint32_t)((R > 255 ? 255 : R) << 16 | (G > 255 ? 255 : G) << 8 | (B > 255 ? 255 : B));
}
/* soft round splat, radius rad (px), peak alpha a */
static inline void orb__splat(orb_surface *s, float cx, float cy, float rad, const float c[3], float a) {
    if (rad < 0.45f) rad = 0.45f;
    float rr = rad + 0.8f;
    int x0 = (int)floorf(cx - rr), x1 = (int)ceilf(cx + rr), y0 = (int)floorf(cy - rr), y1 = (int)ceilf(cy + rr);
    for (int y = y0; y <= y1; y++) for (int x = x0; x <= x1; x++) {
        float dx = x + 0.5f - cx, dy = y + 0.5f - cy, d = sqrtf(dx * dx + dy * dy);
        float w = d <= rad - 0.5f ? 1.f : d >= rad + 0.5f ? 0.f : (rad + 0.5f - d);
        if (w > 0.f) orb__add(s, x, y, c[0], c[1], c[2], a * w);
    }
}
static inline void orb__mix(const float a[3], const float b[3], float f, float out[3]) { for (int i = 0; i < 3; i++) out[i] = a[i] + (b[i] - a[i]) * f; }
static inline void orb__white(const float a[3], float f, float out[3]) { for (int i = 0; i < 3; i++) out[i] = a[i] + (255.f - a[i]) * f; }

/* Radial glow: centre colour c0 at alpha a0, mid colour c1 at alpha a1 (at 45%), fading to 0 at radius. */
static inline void orb__glow(orb_surface *s, float cx, float cy, float rad, const float c0[3], float a0, const float c1[3], float a1, float mid) {
    int x0 = (int)(cx - rad), x1 = (int)(cx + rad) + 1, y0 = (int)(cy - rad), y1 = (int)(cy + rad) + 1;
    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > s->w) x1 = s->w;
    if (y1 > s->h) y1 = s->h;
    float inv = 1.f / rad;
    for (int y = y0; y < y1; y++) {
        float dy = (y + 0.5f - cy) * inv;
        for (int x = x0; x < x1; x++) {
            float dx = (x + 0.5f - cx) * inv, d = sqrtf(dx * dx + dy * dy);
            if (d >= 1.f) continue;
            float r, g, b, a;
            if (d < mid) { float f = d / mid; r = c0[0] + (c1[0] - c0[0]) * f; g = c0[1] + (c1[1] - c0[1]) * f; b = c0[2] + (c1[2] - c0[2]) * f; a = a0 + (a1 - a0) * f; }
            else { float f = (d - mid) / (1.f - mid); f = 1.f - f; r = c1[0]; g = c1[1]; b = c1[2]; a = a1 * f * f; }
            orb__add(s, x, y, r, g, b, a);
        }
    }
}

/* Render the orb centred at (cx,cy) with sphere radius R (px). dot = scale for particle size (1 = desktop). */
static inline void orb_render(orb_t *o, orb_surface *s, float cx, float cy, float R, float dot) {
    float t = o->t, level = o->level, energy = o->energy, think = o->think;
    float pulse = o->pulse_age < 1.4f ? 1.f - o->pulse_age / 1.4f : 0.f;
    R *= 1.f + 0.06f * level + 0.05f * pulse * pulse;

    /* halo */
    orb__glow(s, cx, cy, R * (2.0f + 0.5f * energy), o->col[1], 0.30f + 0.28f * energy, o->col[0], 0.10f + 0.08f * energy, 0.45f);

    /* event ring */
    if (pulse > 0.f) {
        float pr = R * (1.05f + (1.f - pulse) * 0.95f);
        int n = (int)(pr * 6.3f / (dot * 1.2f)) + 24;
        for (int i = 0; i < n; i++) {
            float an = 6.2831853f * i / n;
            orb__splat(s, cx + cosf(an) * pr, cy + sinf(an) * pr, dot * (0.5f + 1.2f * pulse), o->col[2], 0.45f * pulse);
        }
    }

    /* particle sphere */
    float tilt = 0.42f + 0.12f * sinf(t * 0.35f);
    float cY = cosf(o->spin), sY = sinf(o->spin), cX = cosf(tilt), sX = sinf(tilt);
    float amp = 0.035f + 0.26f * energy, focal = 3.2f;
    for (int i = 0; i < ORB_N; i++) {
        float la = o->la[i], lo = o->lo[i];
        float n = sinf(lo * 18.85f + t * 2.1f + la * 6.f) * cosf(la * 12.6f - t * 1.4f) * 0.55f
                + sinf(la * 25.1f + lo * 12.57f - t * 3.3f) * (0.25f + 0.55f * level)
                + sinf(lo * 37.7f - t * 5.f + la * 3.f) * 0.35f * think;
        float d = 1.f + amp * n * o->pw[i];
        float x = o->ux[i] * d, y = o->uy[i] * d, z = o->uz[i] * d;
        float x1 = x * cY + z * sY, z1 = -x * sY + z * cY;
        float y2 = y * cX - z1 * sX, z2 = y * sX + z1 * cX;
        float k = focal / (focal - z2);
        float depth = orb__clampf((z2 + 1.25f) / 2.5f, 0.f, 1.f);
        float m = fmodf(lo + t * 0.04f + la * 0.3f, 1.f), f, c[3];
        if (m < 0.5f) { f = m * 2.f; f = f * f * (3 - 2 * f); orb__mix(o->col[0], o->col[1], f, c); }
        else { f = (m - 0.5f) * 2.f; f = f * f * (3 - 2 * f); orb__mix(o->col[1], o->col[2], f, c); }
        orb__white(c, 0.25f * depth * depth, c);
        float a = (0.10f + 0.85f * depth * depth) * (0.75f + 0.25f * energy);
        orb__splat(s, cx + x1 * R * k, cy + y2 * R * k, dot * (0.7f + 1.7f * depth) * k * 0.5f, c, a);
    }

    /* core */
    float core[3]; orb__white(o->col[2], 0.55f, core);
    orb__glow(s, cx, cy, R * (0.62f + 0.18f * level), core, 0.50f + 0.35f * level, o->col[0], 0.28f, 0.35f);

    /* ribbons through the equator: filled band + bright edge, faded at both ends */
    float span = R * 1.55f;
    float ra = R * (0.03f + 0.62f * level * (0.45f + 0.55f * o->voice) + 0.10f * think);
    int xs = (int)(cx - span), xe = (int)(cx + span);
    for (int r = 0; r < 3; r++) {
        float fr = 1.6f + r * 0.55f, sp = 2.4f + r * 1.3f, ph = r * 2.1f, a = ra * (1.f - r * 0.22f);
        float edge[3]; orb__white(o->col[r], 0.25f, edge);
        for (int x = xs; x <= xe; x++) {
            float u = (x + 0.5f - cx) / span;
            if (u < -1.f || u > 1.f) continue;
            float e = powf(4.f / (4.f + powf(u * 2.2f, 4.f)), 4.f);
            float fade = fabsf(u) < 0.4f ? 1.f : orb__clampf((1.f - fabsf(u)) / 0.6f, 0.f, 1.f);
            float yt = cy + sinf(u * 3.14159f * fr + t * sp + ph) * a * e;
            float yb = cy - sinf(u * 3.14159f * fr + t * sp + ph + 0.9f) * a * e * 0.35f;
            float lo_ = fminf(yt, yb), hi = fmaxf(yt, yb);
            for (int y = (int)floorf(lo_); y <= (int)ceilf(hi); y++) {
                float cov = fminf(hi, y + 1.f) - fmaxf(lo_, (float)y);
                if (cov > 0) orb__add(s, x, y, o->col[r][0], o->col[r][1], o->col[r][2], (0.20f + 0.25f * level) * fade * cov);
            }
            orb__splat(s, x + 0.5f, yt, dot * 0.55f, edge, (0.40f + 0.40f * level) * fade * 0.6f);
            orb__splat(s, x + 0.5f, yb, dot * 0.45f, edge, (0.25f + 0.30f * level) * fade * 0.5f);
        }
    }

    /* thinking: orbiting arcs */
    if (think > 0.02f) {
        float rads[2] = {R * 1.22f, R * 1.32f};
        float starts[3] = {t * 3.84f, t * 3.84f + 3.14159f, -t * 2.44f};
        float sweeps[3] = {1.22f, 0.70f, 1.92f};
        int rings[3] = {0, 0, 1};
        float alph[3] = {0.75f, 0.55f, 0.40f};
        int cidx[3] = {2, 0, 1};
        for (int j = 0; j < 3; j++) {
            float rr = rads[rings[j]];
            int n = (int)(rr * sweeps[j] / (dot * 0.8f)) + 8;
            for (int i = 0; i <= n; i++) {
                float an = starts[j] + sweeps[j] * i / n;
                orb__splat(s, cx + cosf(an) * rr, cy + sinf(an) * rr, dot * (j == 2 ? 0.55f : 0.9f), o->col[cidx[j]], alph[j] * think * 0.8f);
            }
        }
    }
}
#endif
