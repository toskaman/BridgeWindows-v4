/* =========================================================================
 * orb_hud.h - terminal canvas for the Linux agent's live HUD.
 * Header-only, C99, libm only. Shares orb_core.h with the Windows window.
 *
 * A band of COLS x ROWS cells. Each cell shows two stacked pixels with the
 * upper-half block U+2580 (fg = top pixel, bg = bottom pixel), so the pixel
 * layer is COLS x 2*ROWS. A text layer can be overlaid on any cell (labels,
 * stats, key caps). hud_flush() emits only the cells that changed since the
 * previous frame (absolute cursor moves, never scrolls), which keeps the
 * output small enough for SSH sessions.
 * ========================================================================= */
#ifndef BRIDGE_ORB_HUD_H
#define BRIDGE_ORB_HUD_H
#include "orb_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HUD_MAX_COLS 220
#define HUD_MAX_ROWS 16

typedef struct {
    char g[5];          /* UTF-8 glyph, "" = pixel cell */
    uint32_t fg, bg;    /* 0xRRGGBB */
    uint8_t bold;
} hud_cell_t;

typedef struct {
    int cols, rows;
    uint32_t px[HUD_MAX_COLS * HUD_MAX_ROWS * 2];
    hud_cell_t txt[HUD_MAX_ROWS][HUD_MAX_COLS];
    hud_cell_t prev[HUD_MAX_ROWS][HUD_MAX_COLS];
    uint32_t rowbg[HUD_MAX_ROWS];   /* plain background per row: text never shows what passes under it */
    int have_prev;
} hud_canvas_t;

/* Start a frame: (re)size, dark gradient background, empty text layer. */
static inline void hud_begin(hud_canvas_t *c, int cols, int rows) {
    if (cols > HUD_MAX_COLS) cols = HUD_MAX_COLS;
    if (rows > HUD_MAX_ROWS) rows = HUD_MAX_ROWS;
    if (cols != c->cols || rows != c->rows) c->have_prev = 0;
    c->cols = cols; c->rows = rows;
    int h = rows * 2;
    for (int y = 0; y < h; y++) {
        float f = (float)y / (h > 1 ? h - 1 : 1);
        uint32_t col = (uint32_t)((int)(5 + 8 * f) << 16 | (int)(7 + 4 * f) << 8 | (int)(15 + 16 * f));
        for (int x = 0; x < cols; x++) c->px[y * cols + x] = col;
        if ((y & 1) == 0) c->rowbg[y / 2] = col;
    }
    memset(c->txt, 0, sizeof(c->txt));
}

static inline orb_surface hud_surface(hud_canvas_t *c) {
    orb_surface s = { c->px, c->cols, c->cols, c->rows * 2 };
    return s;
}

/* number of terminal cells a UTF-8 string occupies (1 per code point) */
static inline int hud_strcells(const char *s) {
    int n = 0;
    for (; *s; s++) if (((unsigned char)*s & 0xC0) != 0x80) n++;
    return n;
}

/* is the text-layer span free? */
static inline int hud_free(hud_canvas_t *c, int row, int col, int len) {
    if (row < 0 || row >= c->rows || col < 0 || col + len > c->cols) return 0;
    for (int i = 0; i < len; i++) if (c->txt[row][col + i].g[0]) return 0;
    return 1;
}

/* Write UTF-8 text on the text layer (clipped). bg = 0 means "darkened pixels under it". */
static inline void hud_text(hud_canvas_t *c, int row, int col, const char *s, uint32_t fg, uint32_t bg, int bold) {
    if (row < 0 || row >= c->rows) return;
    while (*s && col < c->cols) {
        int len = 1;
        unsigned char b = (unsigned char)*s;
        if (b >= 0xF0) len = 4; else if (b >= 0xE0) len = 3; else if (b >= 0xC0) len = 2;
        if (col >= 0) {
            hud_cell_t *t = &c->txt[row][col];
            memset(t->g, 0, sizeof(t->g));
            for (int i = 0; i < len && s[i]; i++) t->g[i] = s[i];
            t->fg = fg; t->bg = bg ? bg : 0x1000000u; t->bold = (uint8_t)bold;
        }
        for (int i = 0; i < len && *s; i++) s++;
        col++;
    }
}

/* Compose and emit the changed cells. rorg/corg: 1-based origin of the band. force: full redraw. */
static inline size_t hud_flush(hud_canvas_t *c, char *out, size_t cap, int rorg, int corg, int force) {
    size_t n = 0;
    int cur_r = -1, cur_c = -1;
    uint32_t last_fg = 0xFFFFFFFFu, last_bg = 0xFFFFFFFFu; int last_bold = -1;
#define HUD_PUT(...) do { if (n < cap) { int k = snprintf(out + n, cap - n, __VA_ARGS__); if (k > 0) n += (size_t)k; } } while (0)
    for (int r = 0; r < c->rows; r++) {
        for (int x = 0; x < c->cols; x++) {
            hud_cell_t cell;
            uint32_t top = c->px[(r * 2) * c->cols + x], bot = c->px[(r * 2 + 1) * c->cols + x];
            hud_cell_t *t = &c->txt[r][x];
            if (t->g[0]) {
                cell = *t;
                if (cell.bg == 0x1000000u) cell.bg = c->rowbg[r];
            } else {
                memset(&cell, 0, sizeof(cell));
                memcpy(cell.g, "\xE2\x96\x80", 4);    /* U+2580 upper half block */
                cell.fg = top & 0xF0F0F0u; cell.bg = bot & 0xF0F0F0u; cell.bold = 0;   /* 4-bit channels: far fewer redraws over SSH */
            }
            hud_cell_t *p = &c->prev[r][x];
            if (!force && c->have_prev && !memcmp(p->g, cell.g, sizeof(cell.g)) && p->fg == cell.fg
                && p->bg == cell.bg && p->bold == cell.bold) continue;
            *p = cell;
            if (cur_r != r || cur_c != x) HUD_PUT("\033[%d;%dH", rorg + r, corg + x);
            if (cell.bold != last_bold) { HUD_PUT(cell.bold ? "\033[1m" : "\033[22m"); last_bold = cell.bold; }
            if (cell.fg != last_fg) { HUD_PUT("\033[38;2;%u;%u;%um", (cell.fg >> 16) & 255, (cell.fg >> 8) & 255, cell.fg & 255); last_fg = cell.fg; }
            if (cell.bg != last_bg) { HUD_PUT("\033[48;2;%u;%u;%um", (cell.bg >> 16) & 255, (cell.bg >> 8) & 255, cell.bg & 255); last_bg = cell.bg; }
            HUD_PUT("%s", cell.g);
            cur_r = r; cur_c = x + 1;
        }
    }
    if (n) HUD_PUT("\033[0m");
#undef HUD_PUT
    c->have_prev = 1;
    return n;
}
#endif
