/* OpenBridge ESP32 agent (P1 port #1): native firmware, same v4 wire protocol.
 *
 * Unity-builds the shared dependency-free core in ../proto/ (sha256 + obproto),
 * so the firmware on silicon is byte-identical logic to the host-tested code.
 * Transports: WiFi TCP to the master daemon; Serial selftest + Serial gateway
 * framing (line-delimited JSON) for USB and emulated runs.
 * UI: ILI9341 TFT, OpenBridge identity (dark bg, cyan accent, orb-ish rings).
 *
 * Wiring (ESP32-DevKit + ILI9341):
 *   TFT_CS=5 TFT_DC=27 TFT_RST=4 MOSI=23 SCK=18 MISO=19, LED_BUILTIN=2
 */
#include <WiFi.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>

/* Shared core (same files as the host protocol test): */
#include "../proto/sha256.h"
#include "../proto/sha256.cpp"
#include "../proto/obproto.h"
#include "../proto/obproto.cpp"

/* ---- owner/lab configuration (no secrets committed) ---- */
#ifndef OB_WIFI_SSID
#define OB_WIFI_SSID "Wokwi-GUEST"
#endif
#ifndef OB_WIFI_PASS
#define OB_WIFI_PASS ""
#endif
#ifndef OB_MASTER_HOST
#define OB_MASTER_HOST "192.168.1.23"
#endif
#ifndef OB_MASTER_PORT
#define OB_MASTER_PORT 9876
#endif
#ifndef OB_PSK
#define OB_PSK "BridgeSecret2026!"
#endif
#ifndef OB_AGENT_ID
#define OB_AGENT_ID "ESP32-01"
#endif

#define TFT_CS 5
#define TFT_DC 27
#define TFT_RST 4
#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif
Adafruit_ILI9341 tft(TFT_CS, TFT_DC, TFT_RST);

#define COL_BG 0x080B
#define COL_CYAN 0x07FF
#define COL_GREEN 0x07E0
#define COL_AMBER 0xFD20
#define COL_GREY 0x8410
#define COL_WHITE 0xFFFF

static WiFiClient g_cli;
static ob_agent_t g_agent;
static char g_last_op[48] = "boot";
static int g_handshake_ok = 0;

static int fw_read(void *c, unsigned char *buf, int len, int timeout_ms) {
    (void)c;
    unsigned long t0 = millis();
    int got = 0;
    while (got < len) {
        if (!g_cli.connected())
            return -1;
        int av = g_cli.available();
        if (av > 0) {
            int n = g_cli.read(buf + got, len - got);
            if (n < 0)
                return -1;
            got += n;
        } else if ((int)(millis() - t0) > timeout_ms) {
            return 0;
        } else {
            delay(1);
        }
    }
    return got;
}

static int fw_write(void *c, const unsigned char *buf, int len) {
    (void)c;
    if (!g_cli.connected())
        return -1;
    return (int)g_cli.write(buf, (size_t)len);
}

static unsigned long fw_millis(void *c) {
    (void)c;
    return millis();
}

static void fw_nonce(void *c, char out32[33]) {
    static const char *xd = "0123456789abcdef";
    int i;
    (void)c;
    for (i = 0; i < 32; i++)
        out32[i] = xd[(int)(esp_random() & 15)];
    out32[32] = 0;
}

static void fw_emit(void *c, const char *line) {
    (void)c;
    Serial.println(line);
}

static void ui_state(const char *state, uint16_t col, const char *sub) {
    tft.fillScreen(COL_BG);
    tft.setTextColor(COL_CYAN);
    tft.setTextSize(2);
    tft.setCursor(12, 14);
    tft.print("OPENBRIDGE");
    tft.setTextColor(COL_WHITE);
    tft.setTextSize(3);
    tft.setCursor(12, 42);
    tft.print("ESP32");
    /* orb-ish concentric rings */
    for (int r = 46; r > 10; r -= 9)
        tft.drawCircle(120, 150, r, COL_CYAN);
    tft.fillCircle(120, 150, 5, COL_CYAN);
    tft.setTextColor(col);
    tft.setTextSize(2);
    tft.setCursor(12, 208);
    tft.print(state);
    tft.setTextColor(COL_GREY);
    tft.setTextSize(1);
    tft.setCursor(12, 232);
    tft.print(OB_AGENT_ID);
    tft.setCursor(12, 246);
    tft.print(sub ? sub : "");
    tft.setCursor(12, 260);
    tft.print("IN/OUT MACs: v4");
    tft.setCursor(12, 274);
    tft.print(g_last_op);
}

static void ui_splash(const char *l1, const char *l2) {
    tft.fillScreen(COL_BG);
    tft.setTextColor(COL_CYAN);
    tft.setTextSize(2);
    tft.setCursor(12, 100);
    tft.print("OPENBRIDGE");
    tft.setTextColor(COL_WHITE);
    tft.setTextSize(2);
    tft.setCursor(12, 130);
    tft.print(l1);
    tft.setTextColor(COL_GREY);
    tft.setTextSize(1);
    tft.setCursor(12, 160);
    tft.print(l2);
}

void setup() {
    Serial.begin(115200);
    pinMode(LED_BUILTIN, OUTPUT);
    tft.begin();
    tft.setRotation(1);
    ui_splash("ESP32 agent", "selftest...");
    Serial.println("OB-ESP32 boot");
    if (ob_selftest(fw_emit, NULL) != 0) {
        ui_splash("SELFTEST FAIL", "halted");
        Serial.println("SELFTEST FAIL, halting");
        for (;;)
            delay(1000);
    }
    ui_splash("WiFi...", OB_WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(OB_WIFI_SSID, OB_WIFI_PASS);
    {
        unsigned long t0 = millis();
        while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000)
            delay(200);
    }
    if (WiFi.status() != WL_CONNECTED) {
        ui_state("NO WIFI", COL_AMBER, "serial selftest OK");
        Serial.println("NO WIFI (serial selftest OK)");
        return;
    }
    {
        char ip[32];
        snprintf(ip, sizeof(ip), "ip %s", WiFi.localIP().toString().c_str());
        ui_splash("master...", ip);
    }
    if (!g_cli.connect(OB_MASTER_HOST, OB_MASTER_PORT)) {
        ui_state("NO MASTER", COL_AMBER, OB_MASTER_HOST);
        Serial.println("master connect failed");
        return;
    }
    memset(&g_agent, 0, sizeof(g_agent));
    g_agent.read = fw_read;
    g_agent.write = fw_write;
    g_agent.millis = fw_millis;
    g_agent.nonce = fw_nonce;
    g_agent.ctx = NULL;
    if (ob_handshake(&g_agent, OB_AGENT_ID, OB_PSK) != 0) {
        ui_state("AUTH FAIL", COL_AMBER, "check PSK");
        Serial.println("handshake failed");
        g_cli.stop();
        return;
    }
    g_handshake_ok = 1;
    digitalWrite(LED_BUILTIN, HIGH);
    snprintf(g_last_op, sizeof(g_last_op), "linked %s", OB_MASTER_HOST);
    ui_state("READY", COL_GREEN, g_last_op);
    Serial.println("AUTH_OK");
}

void loop() {
    if (!g_handshake_ok || !g_cli.connected()) {
        delay(1000);
        return;
    }
    /* Serve one request per loop iteration to keep the UI alive. */
    int r = ob_serve(&g_agent, 1);
    if (r > 0) {
        snprintf(g_last_op, sizeof(g_last_op), "served, up %lus", millis() / 1000);
        ui_state("READY", COL_GREEN, g_last_op);
    } else if (r < 0) {
        ui_state("LINK LOST", COL_AMBER, "reboot to rejoin");
        Serial.println("serve error, halting");
        g_cli.stop();
        g_handshake_ok = 0;
    }
}
