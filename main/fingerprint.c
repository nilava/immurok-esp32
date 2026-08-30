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
  fingerprint_led_idle();
}

bool fingerprint_present(void) {
  return gpio_get_level(FP_INT_PIN) == FP_INT_ACTIVE;
}

// Is a finger STILL on the sensor? The IRQ pin can't answer this: it
// de-asserts the moment a capture completes even while the finger stays
// down (proven — a held touch logged a 0-iteration wait loop). Ask the
// sensor directly instead: GenImg returns 0x00 when it can capture an
// image, 0x02 when there is no finger.
bool fingerprint_finger_down(void) {
  uint8_t confirm = 0xff;
  bool ok = fp_command(CMD_GEN_IMAGE, NULL, 0, &confirm, NULL, NULL, 600);
  return ok && confirm == 0x00;
}

// Block until the finger is lifted (or `timeout_ms` passes). Must poll the
// sensor rather than the IRQ pin: the pin de-asserts on capture completion,
// so an IRQ-based wait returned instantly and the next enrollment capture
// could re-photograph the finger that was never lifted.
static void wait_for_lift(uint32_t timeout_ms) {
  TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
  while (fingerprint_finger_down() && xTaskGetTickCount() < deadline) {
    vTaskDelay(pdMS_TO_TICKS(120));
  }
  vTaskDelay(pdMS_TO_TICKS(150));  // settle so the next capture is a fresh press
}

// Aura params: [mode][speed][color][count]. Modes: 1=breathe 2=flash
// 3=steady-on 4=off. Speed: ~0 fast … 255 slow (100 = calm fade).
// Color indices are UNIT-SPECIFIC — swept on this ZW101 with the 'c'
// console key (2026-08-29): 1=off 2=pink 3=blue 4=green 5=cyan 6=red
// 7=purple. No white or yellow on this ring.
#define AURA_BREATHE 1
#define AURA_FLASH   2
#define AURA_ON      3
#define AURA_OFF     4

// 3-bit RGB mask per the datasheet: bit0 blue, bit1 green, bit2 red.
#define C_OFF     0x00
#define C_BLUE    0x01
#define C_GREEN   0x02
#define C_CYAN    0x03
#define C_RED     0x04
#define C_MAGENTA 0x05  // "purple" in the UI
#define C_YELLOW  0x06
#define C_WHITE   0x07
#define C_PURPLE  C_MAGENTA

// Real spec (Hi-Link "Fingerprint module user communication protocol" v1.1,
// §3.5.7 PS_ControlBLN — user supplied the datasheet, settling three rounds
// of guessing): params are [function][starting color][ending color][cycles].
// There is NO speed byte — every earlier "speed" value (60/100/25) was
// landing in the starting-color field, which is why colors looked random.
// Colors are a 3-bit RGB mask: bit0=blue bit1=green bit2=red (0x01 blue,
// 0x02 green, 0x04 red, 0x03 cyan, 0x05 magenta, 0x06 yellow, 0x07 white,
// 0x00 off). Functions: 1 breathe (start->end), 2 flash (alternates
// start/end), 3 steady-on, 4 steady-off, 5 fade in, 6 fade out. For 3/4/5/6
// the doc says starting/ending color should match; cycles is ignored for
// 3-6 and 0 means "loop forever" for 1/2.
// Two DIFFERENT parameter conventions coexist in this command, confirmed by
// direct sweep testing: for steady-on (function 3), byte[1] is the color and
// byte[2] is ignored. For breathe/flash (functions 1/2), the datasheet's
// "starting/ending color" framing didn't produce any visible animation when
// tried; dashtouch — a real project driving genuine smooth breathing on this
// same sensor family — uses byte[1] as a SPEED and byte[2] as the color for
// those functions, so that's the convention used here.
static void aura(uint8_t function, uint8_t p1, uint8_t p2, uint8_t count) {
  uint8_t params[] = {function, p1, p2, count};
  uint8_t confirm = 0xff;
  ESP_LOGD(TAG, "AURA fn=%u p1=%u p2=%u cyc=%u", function, p1, p2, count);
  fp_command(CMD_AURA_LED, params, sizeof(params), &confirm, NULL, NULL, 1000);
}

static void aura_steady(uint8_t color) { aura(AURA_ON, color, color, 0); }
static void aura_off(void) { aura(AURA_OFF, 0, 0, 0); }
// Byte[1] is the real color selector on this unit for EVERY function, not
// just steady — a "speed" value there (previously 100) got read as a color
// mask (100 & 0x07 = 4 = red), which is why breathing showed the wrong hue
// regardless of what was asked for. There is no working speed control;
// mirror color into both fields like steady and let the module's own fixed
// breathing rate run.
static void aura_breathe(uint8_t color) { aura(AURA_BREATHE, color, color, 0); }

// Whether a host is connected steers what "idle" looks like (purple = ready,
// red = can't reach a computer). Set from the BLE layer.
static bool s_host_connected;

// While locked, idle repaints are suppressed. Needed because switching hosts
// deliberately disconnects, and the disconnect handler would otherwise wipe
// the "switching" blue within milliseconds of it being shown.
static bool s_led_locked;
void fingerprint_led_lock(bool locked) { s_led_locked = locked; }

void fingerprint_led_set_connected(bool connected) {
  if (connected) s_led_locked = false;  // a real connection ends any hold
  s_host_connected = connected;
  fingerprint_led_idle();
}

static int s_current_state = -1;

// The module runs its own ~1s green after a successful match and ignores
// ControlBLN during it; a paint issued mid-window collides and reads as a
// flicker. Record when that window opened so callers can let it finish.
#define MODULE_INDICATOR_MS 1000
static TickType_t s_match_tick;

void fingerprint_led_settle(void) {
  TickType_t elapsed = xTaskGetTickCount() - s_match_tick;
  TickType_t window = pdMS_TO_TICKS(MODULE_INDICATOR_MS);
  if (elapsed < window) vTaskDelay(window - elapsed);
}

void fingerprint_led_state(fp_led_state_t s) {
  // Skip redundant repaints: re-sending an identical aura command makes this
  // module blink, so "holding" a color by repainting it was creating the very
  // flicker it was meant to cure. (tinytouch does the same dedupe.)
  if ((int)s == s_current_state) return;
  s_current_state = (int)s;
  switch (s) {
    case FP_LED_IDLE:         aura_steady(C_PURPLE); break;
    case FP_LED_UNREACHABLE:  aura_breathe(C_RED); break;
    case FP_LED_READING:      aura_breathe(C_PURPLE); break;  // breathing version of idle
    // No flash function: earlier attempts showed this ring's flash sequence
    // swallows commands sent while it runs and then holds its color,
    // orphaning the idle repaint. Verdicts are steady holds instead; the
    // callers time the return to idle.
    case FP_LED_MATCH:        aura_steady(C_GREEN); break;
    case FP_LED_NOMATCH:      aura_steady(C_RED); break;
    case FP_LED_ENROLL_PLACE: aura_breathe(C_BLUE); break;
    case FP_LED_ENROLL_LIFT:  aura_steady(C_CYAN); break;
    case FP_LED_ENROLL_OK:    aura_steady(C_GREEN); break;
    case FP_LED_ENROLL_FAIL:  aura_steady(C_RED); break;
    case FP_LED_PAIRING:      aura_breathe(C_PURPLE); break;
    case FP_LED_SWITCHING:    aura_breathe(C_BLUE); break;
    case FP_LED_LOCK_SENT:    aura_steady(C_BLUE); break;
    case FP_LED_AUTH_WAIT:    aura_breathe(C_CYAN); break;
  }
}

// Compatibility shims for older call sites: legacy bitmask colors map onto
// the nearest semantic state.
void fingerprint_led(uint8_t color, bool steady) {
  if (color == 0x02) fingerprint_led_state(steady ? FP_LED_MATCH : FP_LED_MATCH);
  else if (color == 0x04) fingerprint_led_state(FP_LED_NOMATCH);
  else if (color == 0x01) fingerprint_led_state(FP_LED_SWITCHING);
  else fingerprint_led_state(FP_LED_PAIRING);
}

void fingerprint_led_breathe(uint8_t color) { (void)color; fingerprint_led_state(FP_LED_ENROLL_PLACE); }

void fingerprint_led_idle(void) {
  if (s_led_locked) return;
  fingerprint_led_state(s_host_connected ? FP_LED_IDLE : FP_LED_UNREACHABLE);
}

// The module drives its own brief LED indication right after a capture (green
// on a successful match, a red blink on failure). It is not one of the
// documented parameters — no ControlBLN option or system parameter disables
// it — so instead re-assert our own color across the window where those
// auto-indications land, and ours is what the user actually sees. Steady
// states only: re-issuing a breathe command would restart its fade.
// Force the ring dark, bypassing the state dedupe (used to try to interrupt
// the module's own post-match indicator).
void fingerprint_led_off(void) {
  s_current_state = -1;
  aura_off();
}

void fingerprint_led_hold(fp_led_state_t s, uint32_t ms) {
  fingerprint_led_state(s);
  vTaskDelay(pdMS_TO_TICKS(ms));
}

// Console diagnostic: sweep the seven indexed colors, 2s each, then idle.
// Verifies the datasheet's RGB bit assignment (bit0 blue, bit1 green,
// bit2 red) directly, mask 0..7, steady-on with start=end=mask.
void fingerprint_led_sweep(void) {
  static const char *EXPECT[] = {"0=off", "1=blue", "2=green", "3=cyan",
                                 "4=red", "5=magenta/purple", "6=yellow", "7=white"};
  for (int m = 0; m <= 7; m++) {
    aura_off();
    vTaskDelay(pdMS_TO_TICKS(500));
    ESP_LOGW(TAG, "aura mask %s ...", EXPECT[m]);
    aura_steady((uint8_t)m);
    vTaskDelay(pdMS_TO_TICKS(3000));
  }
  fingerprint_led_idle();
}

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

// Does not paint any verdict color — only the caller knows whether a match
// means "unlock", "this is the switch finger", "gate passed", etc, and
// painting green/red here caused a visible flash of the wrong color before
// the caller's own paint (e.g. green then blue on the switch finger).
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
      s_match_tick = xTaskGetTickCount();  // module green starts now
      return true;
    }
    return false;  // searched, found, but too weak — a real verdict
  }
  // 0x09 = "not found" per the datasheet: an authoritative no-match. Trust it
  // instead of grinding through the per-slot fallback, which fires the
  // module's red blink once per failed Match and read as a flicker.
  if (sok && confirm == 0x09) return false;

  // Fallback only for a MALFORMED Search reply (the old UART-desync case where
  // it came back confirm-only with no page/score). A well-formed 0x00 or 0x09
  // answer is handled above and never reaches here.
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
      s_match_tick = xTaskGetTickCount();  // module green starts now
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
  wait_for_lift(6000);
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
    fingerprint_led_state(FP_LED_ENROLL_PLACE);  // breathing white
    ESP_LOGI(TAG, "enroll: waiting for finger %u/%u", i, TOTAL);
    // Wait for a finger to be present, then capture into buffer i. Re-send the
    // "waiting" frame every ~3s — the app uses it as an enrollment keep-alive.
    TickType_t start = xTaskGetTickCount();
    TickType_t last_ka = start;
    while (!fingerprint_present()) {
      if ((xTaskGetTickCount() - start) > pdMS_TO_TICKS(15000)) {
        ESP_LOGW(TAG, "enroll: timed out waiting for finger");
        if (progress) progress(0xFF, i - 1, TOTAL);
        fingerprint_led_state(FP_LED_ENROLL_FAIL);
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
      fingerprint_led_state(FP_LED_ENROLL_LIFT);  // steady cyan
      wait_for_lift(6000);
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
  fingerprint_led_state(FP_LED_ENROLL_OK);
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
