#include "fingerprint.h"

#include <string.h>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "fp";

static SemaphoreHandle_t fp_mutex;   // serializes UART access across tasks
static int cached_count = -1;        // last known template count

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
#define CMD_READ_INDEX   0x1F
#define CMD_AURA_LED     0x3C

// Minimum match score to accept (rejects weak/false matches like a stray score=1).
#define MATCH_MIN_SCORE 50

// Search across this slot range. The immurok app enrolls 0-based (slot 0), so
// start at 0 to cover app-enrolled templates as well as legacy 1-based ones.
#define SLOT_START 0
#define SLOT_END   50

// Send a command packet and read the ack. `data`/`data_len` are the instruction
// payload; the confirmation code lands in *confirm; any ack data (beyond the
// confirmation byte) is copied into `resp`/`*resp_len`.
static bool fp_command_locked(uint8_t instruction, const uint8_t *data, size_t data_len,
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

  // Flush any leftover/in-flight bytes from a prior command's ack before
  // sending. A non-blocking drain can miss an ack still arriving (esp. with BLE
  // loading the CPU), desyncing subsequent reads; wait for the line to go idle.
  uint8_t drain[64];
  while (uart_read_bytes(FP_UART, drain, sizeof(drain), pdMS_TO_TICKS(20)) > 0) {}
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
  return false;
}

// Mutex-guarded wrapper so concurrent tasks (main loop vs BLE-context calls)
// never interleave UART bytes.
static bool fp_command(uint8_t instruction, const uint8_t *data, size_t data_len,
                       uint8_t *confirm, uint8_t *resp, size_t *resp_len,
                       uint32_t timeout_ms) {
  if (fp_mutex && xSemaphoreTake(fp_mutex, pdMS_TO_TICKS(timeout_ms + 500)) != pdTRUE) {
    return false;
  }
  bool ok = fp_command_locked(instruction, data, data_len, confirm, resp, resp_len, timeout_ms);
  if (fp_mutex) xSemaphoreGive(fp_mutex);
  return ok;
}

void fingerprint_init(void) {
  fp_mutex = xSemaphoreCreateMutex();
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

  // Give the ZW101 time to finish its own power-on boot before the first command.
  vTaskDelay(pdMS_TO_TICKS(600));

  // Try VfyPwd (0x13, default zero password) on the assumed orientation; if it
  // gets no answer, retry with TX/RX swapped and a couple of attempts, and keep
  // whichever works. This self-heals a wiring/pin-order surprise.
  uint8_t pw[] = {0x00, 0x00, 0x00, 0x00};
  bool verify = false;
  const int pairs[2][2] = {{FP_TX_PIN, FP_RX_PIN}, {FP_RX_PIN, FP_TX_PIN}};
  for (int p = 0; p < 2 && !verify; p++) {
    uart_set_pin(FP_UART, pairs[p][0], pairs[p][1], UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    for (int attempt = 0; attempt < 3 && !verify; attempt++) {
      uint8_t confirm = 0xff;
      verify = fp_command(0x13, pw, sizeof(pw), &confirm, NULL, NULL, 800) && confirm == 0x00;
      if (verify) {
        ESP_LOGI(TAG, "sensor verify OK with tx=%d rx=%d", pairs[p][0], pairs[p][1]);
      }
      vTaskDelay(pdMS_TO_TICKS(200));
    }
  }
  if (!verify) ESP_LOGW(TAG, "sensor verify failed on both orientations");

  int n = fingerprint_count();
  ESP_LOGI(TAG, "sensor init: %d template(s) enrolled, index bitmap=0x%02x",
           n, fingerprint_index_bitmap());
  fingerprint_led_idle();  // calm purple breathing
}

bool fingerprint_present(void) {
  return gpio_get_level(FP_INT_PIN) == FP_INT_ACTIVE;
}

void fingerprint_led(uint8_t color, bool steady) {
  // Aura params: [function][start color][end color][cycles] — the 2nd byte is a
  // COLOR, not a speed (a stray value there lights its bit-pattern color).
  // fn 3 = steady, 2 = flash.
  uint8_t params[] = {(uint8_t)(steady ? 3 : 2), color, color, (uint8_t)(steady ? 0 : 2)};
  uint8_t confirm = 0xff;
  fp_command(CMD_AURA_LED, params, sizeof(params), &confirm, NULL, NULL, 1000);
}

// Continuous gentle breathing — used for idle (purple) and "waiting to enroll"
// (blue). fn 1 = breathing, cycles 0 = run until the next aura command.
void fingerprint_led_breathe(uint8_t color) {
  uint8_t params[] = {1, color, color, 0};
  uint8_t confirm = 0xff;
  fp_command(CMD_AURA_LED, params, sizeof(params), &confirm, NULL, NULL, 1000);
}

// Breathing on this ZW101 runs at a fixed, frantic pace and washes purple out
// to blue — steady is the calm, proven mode, so idle holds steady purple.
void fingerprint_led_idle(void) { fingerprint_led(0x03, true); }

int fingerprint_count(void) {
  for (int attempt = 0; attempt < 3; attempt++) {
    uint8_t confirm = 0xff;
    uint8_t data[2];
    size_t len = sizeof(data);
    if (fp_command(CMD_TEMPLATE_NUM, NULL, 0, &confirm, data, &len, 1000) &&
        confirm == 0x00 && len >= 2) {
      ESP_LOGI(TAG, "TemplateNum raw: %02x %02x", data[0], data[1]);
      cached_count = ((int)data[0] << 8) | data[1];
      return cached_count;
    }
    vTaskDelay(pdMS_TO_TICKS(120));
  }
  return -1;
}

int fingerprint_cached_count(void) {
  return cached_count;
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
      // Poor image (0x06 messy / 0x07 too few points — common on the first
      // frame after a cold boot): keep retrying inside the window instead of
      // giving up on one bad frame.
      ESP_LOGW(TAG, "Img2Tz buf %u: confirm=0x%02x, retrying", buffer, confirm);
    }
    vTaskDelay(pdMS_TO_TICKS(80));
  } while (xTaskGetTickCount() < deadline);
  return false;
}

bool fingerprint_search(uint16_t *page_id, uint16_t *score) {
  if (!capture_to_buffer(1, 800)) {
    ESP_LOGW(TAG, "search: capture failed");
    return false;
  }

  // Try the Search (0x04) fast path first.
  uint8_t params[] = {0x01, (SLOT_START >> 8) & 0xff, SLOT_START & 0xff,
                      ((SLOT_END - SLOT_START + 1) >> 8) & 0xff,
                      (SLOT_END - SLOT_START + 1) & 0xff};
  uint8_t confirm = 0xff;
  uint8_t data[4];
  size_t len = sizeof(data);
  bool sok = fp_command(CMD_SEARCH, params, sizeof(params), &confirm, data, &len, 2000);
  ESP_LOGI(TAG, "Search: ok=%d confirm=0x%02x len=%u data=%02x %02x %02x %02x",
           sok, confirm, (unsigned)len,
           len > 0 ? data[0] : 0, len > 1 ? data[1] : 0,
           len > 2 ? data[2] : 0, len > 3 ? data[3] : 0);
  if (sok && confirm == 0x00 && len >= 4) {
    uint16_t s = ((uint16_t)data[2] << 8) | data[3];
    if (s >= MATCH_MIN_SCORE) {
      if (page_id) *page_id = ((uint16_t)data[0] << 8) | data[1];
      if (score) *score = s;
      fingerprint_led(0x02, true);  // steady green: matched
      return true;
    }
  }

  // This ZW101 firmware returns Search as confirm-only (no page/score), so fall
  // back to per-slot LoadChar (0x07) into buffer 2 + Match (0x03), which is what
  // actually reports the matched slot on this sensor.
  for (uint16_t slot = 0; slot <= 15; slot++) {
    uint8_t load[] = {0x02, (uint8_t)(slot >> 8), (uint8_t)(slot & 0xff)};
    confirm = 0xff;
    if (!fp_command(CMD_LOAD_CHAR, load, sizeof(load), &confirm, NULL, NULL, 1000) ||
        confirm != 0x00) {
      continue;  // empty slot
    }
    uint8_t mdata[2];
    size_t mlen = sizeof(mdata);
    confirm = 0xff;
    bool mok = fp_command(CMD_MATCH, NULL, 0, &confirm, mdata, &mlen, 1000);
    uint16_t s = (mlen >= 2) ? (((uint16_t)mdata[0] << 8) | mdata[1]) : 0;
    ESP_LOGI(TAG, "slot %u: Match ok=%d confirm=0x%02x score=%u", slot, mok, confirm, s);
    if (mok && confirm == 0x00 && s >= MATCH_MIN_SCORE) {
      if (page_id) *page_id = slot;
      if (score) *score = s;
      fingerprint_led(0x02, true);  // steady green: matched
      return true;
    }
  }

  return false;  // caller paints the no-match verdict (it may retry first)
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

bool fingerprint_enroll_stream(uint16_t slot,
                               void (*progress)(uint8_t status, uint8_t captured, uint8_t total)) {
  const uint8_t TOTAL = 2;  // ZW101 RegModel merges CharBuffer1 + CharBuffer2
  uint8_t confirm = 0xff;

  for (uint8_t i = 1; i <= TOTAL; i++) {
    if (progress) progress(0x00, i - 1, TOTAL);  // waiting for finger
    fingerprint_led(0x01, true);  // steady blue: waiting for a finger
    ESP_LOGI(TAG, "enroll: waiting for finger %u/%u", i, TOTAL);
    // Wait for a finger to be present, then capture into buffer i. Re-send the
    // "waiting" frame every ~3s — the app uses it as an enrollment keep-alive.
    TickType_t start = xTaskGetTickCount();
    TickType_t last_ka = start;
    while (!fingerprint_present()) {
      if ((xTaskGetTickCount() - start) > pdMS_TO_TICKS(15000)) {
        ESP_LOGW(TAG, "enroll: timed out waiting for finger");
        if (progress) progress(0xFF, i - 1, TOTAL);
        return false;
      }
      if ((xTaskGetTickCount() - last_ka) > pdMS_TO_TICKS(3000)) {
        last_ka = xTaskGetTickCount();
        if (progress) progress(0x00, i - 1, TOTAL);
      }
      vTaskDelay(pdMS_TO_TICKS(50));
    }
    ESP_LOGI(TAG, "enroll: finger detected, capturing to buffer %u", i);
    if (!capture_to_buffer(i, 6000)) {
      ESP_LOGW(TAG, "enroll: capture %u failed", i);
      if (progress) progress(0xFF, i - 1, TOTAL);
      return false;
    }
    if (progress) progress(0x01, i, TOTAL);  // captured
    if (i < TOTAL) {
      if (progress) progress(0x03, i, TOTAL);  // lift finger
      while (fingerprint_present()) vTaskDelay(pdMS_TO_TICKS(50));
    }
  }

  if (progress) progress(0x02, TOTAL, TOTAL);  // processing
  bool rm = fp_command(CMD_REG_MODEL, NULL, 0, &confirm, NULL, NULL, 1500);
  ESP_LOGI(TAG, "enroll RegModel: ok=%d confirm=0x%02x", rm, confirm);
  if (!rm || confirm != 0x00) {
    if (progress) progress(0xFF, TOTAL, TOTAL);
    return false;
  }
  uint8_t params[] = {0x01, (uint8_t)(slot >> 8), (uint8_t)(slot & 0xff)};
  bool st = fp_command(CMD_STORE, params, sizeof(params), &confirm, NULL, NULL, 1500);
  ESP_LOGI(TAG, "enroll Store page %u: ok=%d confirm=0x%02x", slot, st, confirm);
  if (!st || confirm != 0x00) {
    if (progress) progress(0xFF, TOTAL, TOTAL);
    return false;
  }
  // Trust but verify: this sensor has ACKed stores that didn't persist. Probe
  // the slot with LoadChar into buffer 2; if it can't load back, retry the
  // store once, and fail the enrollment loudly rather than pretend.
  for (int attempt = 0; attempt < 2; attempt++) {
    uint8_t probe[] = {0x02, (uint8_t)(slot >> 8), (uint8_t)(slot & 0xff)};
    confirm = 0xff;
    bool loaded = fp_command(CMD_LOAD_CHAR, probe, sizeof(probe), &confirm, NULL, NULL, 1000) &&
                  confirm == 0x00;
    ESP_LOGI(TAG, "enroll verify LoadChar page %u: %s (confirm=0x%02x)",
             slot, loaded ? "ok" : "MISSING", confirm);
    if (loaded) break;
    if (attempt == 1) {
      if (progress) progress(0xFF, TOTAL, TOTAL);
      return false;
    }
    ESP_LOGW(TAG, "store did not persist; retrying Store");
    vTaskDelay(pdMS_TO_TICKS(200));
    confirm = 0xff;
    if (!fp_command(CMD_STORE, params, sizeof(params), &confirm, NULL, NULL, 1500) ||
        confirm != 0x00) {
      if (progress) progress(0xFF, TOTAL, TOTAL);
      return false;
    }
  }
  if (progress) progress(0x04, TOTAL, TOTAL);  // complete
  fingerprint_led(0x02, true);  // steady green: enrolled
  fingerprint_count();  // refresh cached_count
  return true;
}

// Probe slots 0..7 with LoadChar; returns a static string like "01......"
// marking which slots actually hold a loadable template.
const char *fingerprint_slot_probe(void) {
  static char out[9];
  for (uint16_t s = 0; s < 8; s++) {
    uint8_t probe[] = {0x02, (uint8_t)(s >> 8), (uint8_t)(s & 0xff)};
    uint8_t confirm = 0xff;
    bool ok = fp_command(CMD_LOAD_CHAR, probe, sizeof(probe), &confirm, NULL, NULL, 800) &&
              confirm == 0x00;
    out[s] = ok ? ('0' + (s % 10)) : '.';
  }
  out[8] = 0;
  return out;
}

uint8_t fingerprint_index_bitmap(void) {
  // ReadIndexTable (0x1F) page 0 returns 32 bytes; each bit marks an enrolled
  // template slot. Return the first byte = slots 0..7 (immurok uses an 8-slot
  // bitmap in GET_STATUS / FP_LIST).
  uint8_t page = 0;
  uint8_t confirm = 0xff;
  uint8_t table[32];
  size_t len = sizeof(table);
  if (fp_command(CMD_READ_INDEX, &page, 1, &confirm, table, &len, 1000) &&
      confirm == 0x00 && len >= 1) {
    return table[0];
  }
  return 0;
}

bool fingerprint_delete(uint16_t slot) {
  uint8_t params[] = {(slot >> 8) & 0xff, slot & 0xff, 0x00, 0x01};
  uint8_t confirm = 0xff;
  bool ok = fp_command(CMD_DELETE_CHAR, params, sizeof(params), &confirm, NULL, NULL, 1500) &&
            confirm == 0x00;
  if (ok) fingerprint_count();
  return ok;
}

bool fingerprint_delete_all(void) {
  uint8_t confirm = 0xff;
  bool ok = fp_command(CMD_EMPTY, NULL, 0, &confirm, NULL, NULL, 3000) && confirm == 0x00;
  ESP_LOGI(TAG, "Empty: ok=%d confirm=0x%02x", ok, confirm);
  if (ok) return true;
  // Some units reject Empty; sweep slots with DeleteChar(slot, 1) instead.
  bool any_fail = false;
  for (uint16_t slot = 0; slot <= 15; slot++) {
    uint8_t params[] = {(uint8_t)(slot >> 8), (uint8_t)(slot & 0xff), 0x00, 0x01};
    confirm = 0xff;
    bool dok = fp_command(CMD_DELETE_CHAR, params, sizeof(params), &confirm, NULL, NULL, 1500);
    if (!dok || (confirm != 0x00 && confirm != 0x10)) {  // 0x10 = delete failed/empty on some fw
      ESP_LOGW(TAG, "DeleteChar slot %u: ok=%d confirm=0x%02x", slot, dok, confirm);
      any_fail = true;
    }
    vTaskDelay(pdMS_TO_TICKS(30));
  }
  return !any_fail;
}
