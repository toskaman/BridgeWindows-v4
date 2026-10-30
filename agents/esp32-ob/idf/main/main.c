/* OpenBridge ESP32 agent, native ESP-IDF app (emulation target).
 *
 * Same v4 protocol core as the Arduino build (../proto, dependency-free C++):
 * only boot + transport glue differ. Speaks raw v4 frames over UART0 to the
 * host serial gateway: one OB-SER-SYNC marker line, then pure v4 bytes.
 * ROM/bootloader chatter before the marker is dropped by the gateway.
 */
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "obproto.h"
#include "sha256.h"

#ifndef OB_AGENT_ID
#define OB_AGENT_ID "ESP32-01"
#endif
#ifndef OB_PSK
#define OB_PSK "BridgeSecret2026!"
#endif

#define V4_UART UART_NUM_0
#define V4_BAUD 115200

static ob_agent_t g_agent;

static int idf_read(void *ctx, unsigned char *buf, int len, int timeout_ms) {
    (void)ctx;
    int n = uart_read_bytes(V4_UART, buf, (uint32_t)len,
                            timeout_ms / portTICK_PERIOD_MS);
    return n < 0 ? -1 : n; /* 0 = timeout; partials accumulate in read_full */
}

static int idf_write(void *ctx, const unsigned char *buf, int len) {
    (void)ctx;
    return uart_write_bytes(V4_UART, (const char *)buf, (size_t)len);
}

static unsigned long idf_millis(void *ctx) {
    (void)ctx;
    return (unsigned long)(esp_timer_get_time() / 1000ULL);
}

static void idf_nonce(void *ctx, char out32[33]) {
    static const char *xd = "0123456789abcdef";
    (void)ctx;
    for (int i = 0; i < 32; i += 8) {
        uint32_t r = esp_random();
        for (int k = 0; k < 8; k++)
            out32[i + k] = xd[(r >> (k * 4)) & 15];
    }
    out32[32] = 0;
}

static void emit_null(void *ctx, const char *line) {
    (void)ctx;
    (void)line;
}

void app_main(void) {
    const uart_config_t cfg = {
        .baud_rate = V4_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    uart_driver_install(V4_UART, 2048, 2048, 0, NULL, 0);
    uart_param_config(V4_UART, &cfg);
    if (ob_selftest(emit_null, NULL) != 0) {
        for (;;)
            vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    static const char sync_mark[] = "OB-SER-SYNC\r\n";
    uart_write_bytes(V4_UART, sync_mark, sizeof(sync_mark) - 1);
    memset(&g_agent, 0, sizeof(g_agent));
    g_agent.read = idf_read;
    g_agent.write = idf_write;
    g_agent.millis = idf_millis;
    g_agent.nonce = idf_nonce;
    g_agent.ctx = NULL;
    if (ob_handshake(&g_agent, OB_AGENT_ID, OB_PSK) != 0) {
        for (;;)
            vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
    for (;;) {
        if (ob_serve(&g_agent, 1) < 0)
            break;
    }
    for (;;)
        vTaskDelay(1000 / portTICK_PERIOD_MS);
}
