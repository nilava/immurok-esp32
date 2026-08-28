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

  uart_flush_input(FP_UART);
  uart_write_bytes(FP_UART, (const char *)packet, n);

  // Read ack header (9 bytes) then the declared payload.
  uint8_t head[9];
  int got = uart_read_bytes(FP_UART, head, sizeof(head), pdMS_TO_TICKS(timeout_ms));
  if (got != sizeof(head) || head[0] != 0xEF || head[1] != 0x01 || head[6] != PID_ACK) {
    return false;
  }
  uint16_t ack_len = ((uint16_t)head[7] << 8) | head[8];
  if (ack_len < 3 || ack_len > 128) return false;  // confirm(1)+data+checksum(2)
  uint8_t body[128];
  got = uart_read_bytes(FP_UART, body, ack_len, pdMS_TO_TICKS(timeout_ms));
  if (got != ack_len) return false;

  if (confirm) *confirm = body[0];
  size_t payload = ack_len - 3;  // exclude confirm byte + 2 checksum bytes
  if (resp && resp_len) {
    size_t copy = payload < *resp_len ? payload : *resp_len;
    memcpy(resp, body + 1, copy);
    *resp_len = copy;
  }
  return true;
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
