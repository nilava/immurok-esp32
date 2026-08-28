#include "fingerprint.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "fp";

// Wiring (XIAO ESP32-S3 <-> ZW101): sensor TX->D7/GPIO44 (MCU RX),
// RX->D6/GPIO43 (MCU TX), IRQ->D1/GPIO2 (active high). UART1 @ 57600 8N1.
#define FP_UART        UART_NUM_1
#define FP_TX_PIN      43
#define FP_RX_PIN      44
#define FP_INT_PIN     2
#define FP_INT_ACTIVE  1

#define FP_HEADER      0xEF01
#define FP_ADDR        0xFFFFFFFF
#define PID_COMMAND    0x01
#define PID_ACK        0x07

// Instruction codes.
#define CMD_GEN_IMAGE    0x01
#define CMD_IMG2TZ       0x02
#define CMD_MATCH        0x03
#define CMD_SEARCH       0x04
#define CMD_REG_MODEL    0x05
#define CMD_STORE        0x06
#define CMD_LOAD_CHAR    0x07
#define CMD_DELETE_CHAR  0x0C
#define CMD_EMPTY        0x0D
#define CMD_TEMPLATE_NUM 0x1D
#define CMD_AURA_LED     0x3C

// Search across this slot range (ZW101 default library is 1..N).
#define SLOT_START 1
#define SLOT_END   50

// Send a command packet and read the ack. `data`/`data_len` are the instruction
// payload; the confirmation code lands in *confirm; any ack data (beyond the
// confirmation byte) is copied into `resp`/`*resp_len`.
static bool fp_command(uint8_t instruction, const uint8_t *data, size_t data_len,
                       uint8_t *confirm, uint8_t *resp, size_t *resp_len,
                       uint32_t timeout_ms) {
  uint8_t packet[64];
  size_t n = 0;
  packet[n++] = (FP_HEADER >> 8) & 0xff;
  packet[n++] = FP_HEADER & 0xff;
  packet[n++] = (FP_ADDR >> 24) & 0xff;
  packet[n++] = (FP_ADDR >> 16) & 0xff;
  packet[n++] = (FP_ADDR >> 8) & 0xff;
  packet[n++] = FP_ADDR & 0xff;
  packet[n++] = PID_COMMAND;
  uint16_t length = (uint16_t)(1 + data_len + 2);  // instruction + data + checksum
  packet[n++] = (length >> 8) & 0xff;
  packet[n++] = length & 0xff;
  packet[n++] = instruction;
  for (size_t i = 0; i < data_len; i++) packet[n++] = data[i];
  uint16_t checksum = PID_COMMAND + (length >> 8) + (length & 0xff) + instruction;
  for (size_t i = 0; i < data_len; i++) checksum += data[i];
  packet[n++] = (checksum >> 8) & 0xff;
  packet[n++] = checksum & 0xff;

  uint8_t drain[64];
  while (uart_read_bytes(FP_UART, drain, sizeof(drain), 0) > 0) {}
  uart_write_bytes(FP_UART, (const char *)packet, n);

  // Robust receive: bytes may arrive fragmented or with stray leading bytes, so
  // accumulate into a buffer, resync to the 0xEF01 header, and wait for the full
  // declared packet before parsing (matches the proven ZW101 driver).
  uint8_t buf[128];
  size_t pos = 0;
  TickType_t start = xTaskGetTickCount();
  TickType_t deadline = pdMS_TO_TICKS(timeout_ms);
  while ((xTaskGetTickCount() - start) < deadline) {
    int got = uart_read_bytes(FP_UART, buf + pos, sizeof(buf) - pos, pdMS_TO_TICKS(10));
    if (got <= 0) continue;
    pos += (size_t)got;
    // Discard bytes until the buffer starts with the 0xEF01 header.
    while (pos >= 2 && !(buf[0] == 0xEF && buf[1] == 0x01)) {
      memmove(buf, buf + 1, --pos);
    }
    if (pos < 9) continue;
    uint16_t ack_len = ((uint16_t)buf[7] << 8) | buf[8];  // confirm + data + checksum(2)
    size_t expected = 9 + ack_len;
    if (expected > sizeof(buf) || ack_len < 3) return false;
    if (pos < expected) continue;
    if (buf[6] != PID_ACK) return false;
    if (confirm) *confirm = buf[9];
    size_t payload = ack_len - 3;  // exclude confirm byte + 2 checksum bytes
    if (resp && resp_len) {
      size_t copy = payload < *resp_len ? payload : *resp_len;
      memcpy(resp, buf + 10, copy);
      *resp_len = copy;
    }
    return true;
  }
  // Timed out. Log what (if anything) arrived: 0 bytes => RX wire/UART problem;
  // some bytes => framing/protocol mismatch.
  ESP_LOGW(TAG, "cmd 0x%02x: no valid ack, %u raw byte(s): %02x %02x %02x %02x",
           instruction, (unsigned)pos,
           pos > 0 ? buf[0] : 0, pos > 1 ? buf[1] : 0,
           pos > 2 ? buf[2] : 0, pos > 3 ? buf[3] : 0);
  return false;
}

void fingerprint_init(void) {
  gpio_config_t io = {
    .pin_bit_mask = 1ULL << FP_INT_PIN,
    .mode = GPIO_MODE_INPUT,
    .pull_down_en = GPIO_PULLDOWN_ENABLE,
    .intr_type = GPIO_INTR_DISABLE,
  };
  gpio_config(&io);

  uart_config_t cfg = {
    .baud_rate = 57600,
    .data_bits = UART_DATA_8_BITS,
    .parity = UART_PARITY_DISABLE,
    .stop_bits = UART_STOP_BITS_1,
    .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    .source_clk = UART_SCLK_DEFAULT,
  };
  uart_driver_install(FP_UART, 1024, 0, 0, NULL, 0);
  uart_param_config(FP_UART, &cfg);
  uart_set_pin(FP_UART, FP_TX_PIN, FP_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

  // VfyPwd (0x13) with the default all-zero password — some ZW101 units require
  // this handshake before answering other commands.
  uint8_t pw[] = {0x00, 0x00, 0x00, 0x00};
  uint8_t confirm = 0xff;
  bool verify = fp_command(0x13, pw, sizeof(pw), &confirm, NULL, NULL, 2000) && confirm == 0x00;
  ESP_LOGI(TAG, "sensor verify: %s (confirm=0x%02x)", verify ? "ok" : "failed", confirm);

  int n = fingerprint_count();
  ESP_LOGI(TAG, "sensor init: %d template(s) enrolled", n);
  fingerprint_led(0x03, true);  // purple idle
}

bool fingerprint_present(void) {
  return gpio_get_level(FP_INT_PIN) == FP_INT_ACTIVE;
}

void fingerprint_led(uint8_t color, bool steady) {
  // Aura params: [function][speed/start][color][cycles]. fn 3=steady, 2=flash.
  uint8_t params[] = {(uint8_t)(steady ? 3 : 2), (uint8_t)(steady ? color : 40),
                      color, (uint8_t)(steady ? 0 : 2)};
  uint8_t confirm = 0xff;
  fp_command(CMD_AURA_LED, params, sizeof(params), &confirm, NULL, NULL, 1000);
}

int fingerprint_count(void) {
  uint8_t confirm = 0xff;
  uint8_t data[2];
  size_t len = sizeof(data);
  if (!fp_command(CMD_TEMPLATE_NUM, NULL, 0, &confirm, data, &len, 1000) ||
      confirm != 0x00 || len < 2) {
    return -1;
  }
  return ((int)data[0] << 8) | data[1];
}

// Capture one image into char buffer `buffer` (1 or 2). Returns true on success.
static bool capture_to_buffer(uint8_t buffer, uint32_t wait_ms) {
  uint8_t confirm = 0xff;
  TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(wait_ms);
  do {
    if (fp_command(CMD_GEN_IMAGE, NULL, 0, &confirm, NULL, NULL, 1000) && confirm == 0x00) {
      uint8_t buf = buffer;
      if (fp_command(CMD_IMG2TZ, &buf, 1, &confirm, NULL, NULL, 1000) && confirm == 0x00) {
        return true;
      }
      return false;
    }
    vTaskDelay(pdMS_TO_TICKS(80));
  } while (xTaskGetTickCount() < deadline);
  return false;
}

bool fingerprint_search(uint16_t *page_id, uint16_t *score) {
  if (!capture_to_buffer(1, 400)) return false;
  uint8_t params[] = {0x01, (SLOT_START >> 8) & 0xff, SLOT_START & 0xff,
                      ((SLOT_END - SLOT_START + 1) >> 8) & 0xff,
                      (SLOT_END - SLOT_START + 1) & 0xff};
  uint8_t confirm = 0xff;
  uint8_t data[4];
  size_t len = sizeof(data);
  if (!fp_command(CMD_SEARCH, params, sizeof(params), &confirm, data, &len, 2000) ||
      confirm != 0x00 || len < 4) {
    fingerprint_led(0x04, false);  // red flash on no-match
    return false;
  }
  if (page_id) *page_id = ((uint16_t)data[0] << 8) | data[1];
  if (score) *score = ((uint16_t)data[2] << 8) | data[3];
  fingerprint_led(0x02, false);  // green flash on match
  return true;
}

bool fingerprint_enroll(uint16_t slot, void (*prompt)(const char *msg)) {
  uint8_t confirm = 0xff;
  if (prompt) prompt("place finger");
  if (!capture_to_buffer(1, 8000)) return false;
  if (prompt) prompt("lift finger");
  while (fingerprint_present()) vTaskDelay(pdMS_TO_TICKS(50));
  if (prompt) prompt("place same finger again");
  if (!capture_to_buffer(2, 8000)) return false;

  if (!fp_command(CMD_REG_MODEL, NULL, 0, &confirm, NULL, NULL, 1500) || confirm != 0x00) {
    return false;
  }
  uint8_t params[] = {0x01, (slot >> 8) & 0xff, slot & 0xff};
  if (!fp_command(CMD_STORE, params, sizeof(params), &confirm, NULL, NULL, 1500) ||
      confirm != 0x00) {
    return false;
  }
  if (prompt) prompt("enrolled");
  return true;
}

bool fingerprint_delete(uint16_t slot) {
  uint8_t params[] = {(slot >> 8) & 0xff, slot & 0xff, 0x00, 0x01};
  uint8_t confirm = 0xff;
  return fp_command(CMD_DELETE_CHAR, params, sizeof(params), &confirm, NULL, NULL, 1500) &&
         confirm == 0x00;
}

bool fingerprint_delete_all(void) {
  uint8_t confirm = 0xff;
  return fp_command(CMD_EMPTY, NULL, 0, &confirm, NULL, NULL, 2000) && confirm == 0x00;
}
