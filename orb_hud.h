/* =========================================================================
 * orb_hud.h - render the voice orb into a terminal using unicode half-blocks
 * and 24-bit colour. Header-only, C99, libm only. Shares orb_core.h so the
 * Linux agent shows the same presence as the Windows window and the phone.
 *
 * One cell is two stacked pixels: the upper half (foreground) is U+2580,
 * the lower half is the background colour. So COLS x ROWS cells == COLS x 2*ROWS
 * pixels. orb_hud_frame() writes a ready-to-print ANSI string positioned with
 * absolute cursor moves (row rorg.., col corg..), never scrolling.
 * ========================================================================= */
#ifndef BRIDGE_ORB_HUD_H
#define BRIDGE_ORB_HUD_H
#include "orb_core.h"
#include <stdio.h>
#include <string.h>

/* Render the orb into an RGB pixel grid (cols x 2*rows), 0xRRGGBB, dark gradient bg. */
static void orb_hud_pixels(orb_t *o, uint32_t *px, int cols, int rows2) {
    for (int y = 0; y < rows2; y++) {
        float f = (float)y / (rows2 > 1 ? rows2 - 1 : 1);
        int r = (int)(5 + (13 - 5) * f), g = (int)(7 + (11 - 7) * f), b = (int)(15 + (31 - 15) * f);
        uint32_t c = (uint32_t)(r << 16 | g << 8 | b);
        for (int x = 0; x < cols; x++) px[y * cols + x] = c;
    }
    orb_surface s = { px, cols, cols, rows2 };
    /* terminal cells are ~2x taller than wide; squash Y so the sphere stays round */
    float R = (float)cols * 0.30f;
    float dot = R / 22.0f; if (dot < 1.0f) dot = 1.0f;
    orb_render(o, &s, cols * 0.5f, rows2 * 0.5f, R, dot);
}

/* Emit the half-block frame. buf must hold ~ rows*cols*40 + a bit. Returns length.
 * rorg/corg are 1-based terminal origin (top-left of the box). */
static size_t orb_hud_frame(orb_t *o, char *buf, size_t cap, int cols, int rows, int rorg, int corg) {
    static uint32_t px[128 * 128];
    if (cols > 128) cols = 128;
    if (rows * 2 > 128) rows = 64;
    orb_hud_pixels(o, px, cols, rows * 2);
    size_t n = 0;
    for (int ry = 0; ry < rows; ry++) {
        n += (size_t)snprintf(buf + n, n < cap ? cap - n : 0, "\033[%d;%dH", rorg + ry, corg);
        int lastT = -1, lastB = -1;
        for (int cx = 0; cx < cols; cx++) {
            uint32_t top = px[(ry * 2) * cols + cx];
            uint32_t bot = px[(ry * 2 + 1) * cols + cx];
            int tr = top >> 16 & 255, tg = top >> 8 & 255, tb = top & 255;
            int br = bot >> 16 & 255, bg = bot >> 8 & 255, bb = bot & 255;
            if ((int)top != lastT) { n += (size_t)snprintf(buf + n, n < cap ? cap - n : 0, "\033[38;2;%d;%d;%dm", tr, tg, tb); lastT = (int)top; }
            if ((int)bot != lastB) { n += (size_t)snprintf(buf + n, n < cap ? cap - n : 0, "\033[48;2;%d;%d;%dm", br, bg, bb); lastB = (int)bot; }
            n += (size_t)snprintf(buf + n, n < cap ? cap - n : 0, "\xE2\x96\x80");   /* U+2580 upper half block */
        }
        n += (size_t)snprintf(buf + n, n < cap ? cap - n : 0, "\033[0m");
    }
    return n;
}
#endif
