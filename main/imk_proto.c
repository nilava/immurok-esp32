#include "imk_proto.h"

#include <string.h>

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "imk_crypto.h"
#include "fingerprint.h"
#include "imk_keystore.h"

static const char *TAG = "imk_proto";

// Opcodes (immurok protocol subset for Phase 5A).
#define CMD_GET_STATUS    0x01
#define CMD_GET_BATT_RAW  0x02
#define CMD_ENROLL_START  0x10
#define CMD_ENROLL_CANCEL 0x11
#define CMD_DELETE_FP     0x12
#define CMD_FP_LIST       0x13
#define CMD_FP_MATCH_ACK  0x22
#define CMD_PAIR_INIT     0x30
#define CMD_PAIR_CONFIRM  0x31
#define CMD_PAIR_STATUS   0x32
#define CMD_AUTH_REQUEST  0x33
#define CMD_GATE_CANCEL   0x37
#define CMD_CHALLENGE     0x38
#define CMD_SLOT_STATUS   0x39
#define CMD_SLOT_CLEAR    0x3C
#define CMD_KEY_COUNT     0x60
#define CMD_KEY_READ      0x61
#define CMD_KEY_WRITE     0x62
#define CMD_KEY_DELETE    0x63
#define CMD_KEY_COMMIT    0x64
#define CMD_KEY_SIGN      0x65
#define CMD_KEY_GET_PUB   0x66
#define CMD_KEY_GENERATE  0x67
#define CMD_KEY_RESULT    0x68
#define CMD_KEY_OTP_GET   0x69

// Status/response bytes.
#define ST_OK          0x00
#define ST_ERR_TIMEOUT 0x06
#define ST_FP_NO_MATCH 0x07
#define ST_GATE_OK     0x10  // gate approved, operation in progress
#define ST_WAIT_FP     0x11
#define ST_WAIT_BUTTON 0xF0
#define ST_NEEDS_RESET 0xF1
#define ST_ERROR       0xFF

// Notification tags.
#define NOTIF_FP_MATCH 0x21
#define NOTIF_LOCK_REQ 0x23  // long-press: ask the host to lock its screen

static imk_send_fn s_send;

// Pairing progresses through touch-driven stages. First-time pairing needs a
// presence touch only; binding a SECOND host requires an enrolled-finger
// match first (PAIR_BUTTON 0x03), then a confirm touch (the "button").
typedef enum {
  PAIR_IDLE,
  PAIR_WAIT_PRESENCE,   // first-time: any touch confirms
  PAIR_WAIT_MATCH,      // second host: enrolled finger required
  PAIR_WAIT_CONFIRM,    // second host: fp passed, one more touch to confirm
} pair_stage_t;
static pair_stage_t s_pair_stage;
static bool s_pairing_pending;  // any stage active (main loop routes touches)
static volatile bool s_enroll_requested;
static uint16_t s_enroll_slot;

// Fingerprint gate: sensitive ops (enroll-with-existing-prints, auth/test) first
// require verifying an already-enrolled finger. Reply WAIT_FP, wait for a touch
// that produces a signed [0x21] the app verifies, then FP_MATCH_ACK runs the op.
typedef enum { GATE_NONE, GATE_AUTH, GATE_ENROLL, GATE_DELETE, GATE_KEYOP } gate_t;

// Keystore operation buffered behind the fingerprint gate.
typedef struct {
  uint8_t op, cat, idx;
  uint8_t hash[32];
  uint32_t ts;
} keyop_t;
static keyop_t s_keyop;
static gate_t s_gate;
static uint16_t s_gate_page;      // enroll target / delete target (sensor page)
static uint8_t s_gate_attempts;   // wrong-finger count (3 strikes)
static TickType_t s_gate_start;   // for the 25s device-side gate timeout
#define GATE_TIMEOUT_MS 25000

static void gate_arm(gate_t g, uint16_t page) {
  s_gate = g;
  s_gate_page = page;
  s_gate_attempts = 0;
  s_gate_start = xTaskGetTickCount();
}


// Wire format asymmetry (from app-macos/BLEManager.swift): app->device writes
// are [cmd][len][payload], but device->app responses/notifications are RAW
// bytes with no length byte — e.g. PAIR_INIT ack is exactly [0x30][0xF0] and
// the device pubkey message is [0x30][pubkey:33] (34 bytes).
static void send_raw(const uint8_t *data, size_t len) {
  if (s_send) s_send(data, len);
}

static void send2(uint8_t b0, uint8_t b1) {
  uint8_t pkt[2] = {b0, b1};
  send_raw(pkt, sizeof(pkt));
}

static void send1(uint8_t b0) { send_raw(&b0, 1); }

// Sensitive ops are gated only when there is a finger that could pass the gate.
static bool gate_needed(void) { return (fingerprint_index_bitmap() >> 1) != 0; }

// Execute a buffered keystore op; sends its result frame. Runs ungated (no
// prints enrolled) straight from the dispatcher, or post-gate from the touch
// handler.
static void keyop_execute(void) {
  switch (s_keyop.op) {
    case CMD_KEY_COMMIT:
      send1(imk_ks_commit(s_keyop.cat, s_keyop.idx) ? ST_OK : ST_ERROR);
      break;
    case CMD_KEY_DELETE:
      send1(imk_ks_delete(s_keyop.cat, s_keyop.idx) ? ST_OK : ST_ERROR);
      break;
    case CMD_KEY_SIGN: {
      if (imk_ks_sign(s_keyop.idx, s_keyop.hash)) {
        uint8_t r[2] = {ST_OK, 64};
        send_raw(r, 2);
      } else {
        send1(ST_ERROR);
      }
      break;
    }
    case CMD_KEY_GENERATE: {
      uint8_t new_idx = 0;
      if (imk_ks_generate(s_keyop.hash, &new_idx)) {  // hash[0..15] holds the name
        uint8_t r[3] = {ST_OK, 64, new_idx};
        send_raw(r, 3);
      } else {
        send1(ST_ERROR);
      }
      break;
    }
    case CMD_KEY_OTP_GET: {
      char code[6];
      if (imk_ks_totp(s_keyop.idx, s_keyop.ts, code)) {
        uint8_t r[7];
        r[0] = ST_OK;
        memcpy(r + 1, code, 6);
        send_raw(r, 7);
      } else {
        send1(ST_ERROR);
      }
      break;
    }
    default:
      send1(ST_ERROR);
      break;
  }
}

void imk_proto_init(imk_send_fn send) {
  s_send = send;
  s_pairing_pending = false;
}

bool imk_proto_pairing_pending(void) { return s_pairing_pending; }

void imk_proto_on_disconnect(void) {
  s_pairing_pending = false;
  s_pair_stage = PAIR_IDLE;
  s_gate = GATE_NONE;
  imk_pair_abort();
}

void imk_proto_handle(const uint8_t *pkt, size_t len) {
  if (len < 2) return;
  uint8_t cmd = pkt[0];
  uint8_t plen = pkt[1];
  const uint8_t *payload = pkt + 2;
  if (2 + plen > len) plen = (uint8_t)(len - 2);  // tolerate short framing

  switch (cmd) {
    case CMD_GET_STATUS: {
      uint8_t bitmap = fingerprint_index_bitmap() >> 1;
      uint8_t body[9] = {
        ST_OK, bitmap,
        (uint8_t)(imk_crypto_is_paired() ? 1 : 0),
        100,           // battery %
        99, 0, 0,      // fw major.minor.patch — deliberately far above any
        0, 1,          // released manifest so the app never prompts an update
                       // (this firmware updates over USB, not immurok OTA)
      };
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_PAIR_INIT: {
      if (imk_crypto_is_paired() && fingerprint_count() > 0) {
        // THIS host is already bound; re-pairing it needs an explicit reset.
        send2(CMD_PAIR_INIT, ST_NEEDS_RESET);
      } else if (imk_crypto_free_slot() < 0) {
        send2(CMD_PAIR_INIT, ST_NEEDS_RESET);  // both slots taken
      } else if (imk_crypto_any_paired() && (fingerprint_index_bitmap() >> 1) != 0) {
        // Second host: prove you're the owner (enrolled finger), then confirm.
        s_pair_stage = PAIR_WAIT_MATCH;
        s_pairing_pending = true;
        send2(CMD_PAIR_INIT, ST_WAIT_BUTTON);
        ESP_LOGI(TAG, "PAIR_INIT: second host — verify enrolled finger first");
        fingerprint_led(0x03, false);
      } else {
        s_pair_stage = PAIR_WAIT_PRESENCE;
        s_pairing_pending = true;
        send2(CMD_PAIR_INIT, ST_WAIT_BUTTON);  // waiting for the presence gate (a touch)
        ESP_LOGI(TAG, "PAIR_INIT: waiting for fingerprint touch to confirm");
        fingerprint_led(0x03, false);  // purple flash: awaiting confirm
      }
      break;
    }

    case CMD_PAIR_CONFIRM: {
      // [0x31][app_pubkey:33]
      uint8_t status = ST_ERROR;
      if (plen >= 33 && imk_pair_complete(payload)) status = ST_OK;
      s_pairing_pending = false;
      s_pair_stage = PAIR_IDLE;
      send2(CMD_PAIR_CONFIRM, status);
      break;
    }

    case CMD_PAIR_STATUS: {
      send2(CMD_PAIR_STATUS, imk_crypto_is_paired() ? 1 : 0);
      break;
    }

    case CMD_AUTH_REQUEST: {
      gate_arm(GATE_AUTH, 0);
      send1(ST_WAIT_FP);
      ESP_LOGI(TAG, "AUTH_REQUEST: gate (touch to verify)");
      break;
    }

    case CMD_GATE_CANCEL: {
      ESP_LOGI(TAG, "GATE_CANCEL");
      s_gate = GATE_NONE;
      s_enroll_requested = false;
      send1(ST_OK);
      break;
    }

    case CMD_GET_BATT_RAW: {
      // [status][mv:2LE][pct][adc:2LE] — USB-powered, report a full battery.
      uint8_t body[6] = {ST_OK, (uint8_t)(4200 & 0xff), (uint8_t)(4200 >> 8), 100, 0, 0};
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_CHALLENGE: {
      // [0x38][nonce:8] → [0x38][hmac:8]
      uint8_t hmac[8];
      if (plen >= 8 && imk_hmac8(payload, 8, hmac)) {
        uint8_t pkt[9];
        pkt[0] = CMD_CHALLENGE;
        memcpy(pkt + 1, hmac, 8);
        send_raw(pkt, sizeof(pkt));
      } else {
        send2(CMD_CHALLENGE, ST_ERROR);
      }
      break;
    }

    case CMD_ENROLL_START: {
      // [0x10][slot]. First-time enroll needs no FP gate; start immediately.
      uint8_t app_slot = (plen >= 1) ? payload[0] : 0;
      uint16_t page = app_slot + 1;  // sensor page (page 0 is unusable)
      // Gate on app-visible slots (index bitmap >> 1), not the raw template
      // count: a ghost template at the unusable page 0 inflates the count but
      // can never pass the gate, which would deadlock enrollment.
      if ((fingerprint_index_bitmap() >> 1) != 0) {
        // Existing prints: require verifying an enrolled finger first.
        gate_arm(GATE_ENROLL, page);
        send1(ST_WAIT_FP);  // responses are status-first (no cmd echo)
        ESP_LOGI(TAG, "ENROLL_START app_slot=%u: gate (verify enrolled finger) -> page %u",
                 app_slot, page);
      } else {
        s_enroll_slot = page;
        s_enroll_requested = true;
        send1(ST_OK);
        ESP_LOGI(TAG, "ENROLL_START app_slot=%u -> sensor page=%u (first enroll)", app_slot, page);
      }
      break;
    }

    case CMD_ENROLL_CANCEL: {
      s_enroll_requested = false;
      send1(ST_OK);
      break;
    }

    case CMD_DELETE_FP: {
      uint16_t page = ((plen >= 1) ? payload[0] : 0) + 1;
      gate_arm(GATE_DELETE, page);
      send1(ST_WAIT_FP);
      ESP_LOGI(TAG, "DELETE_FP page %u: gate (verify enrolled finger)", page);
      break;
    }

    case CMD_FP_LIST: {
      uint8_t body[2] = {ST_OK, (uint8_t)(fingerprint_index_bitmap() >> 1)};
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_SLOT_STATUS: {
      // [0x39][0x00][bound bitmap][active slot] — bitmap bit0 = slot 1;
      // active is the 1-based slot of the connected host (its future slot
      // when it isn't bound yet, so the app can tell it's the second host).
      uint8_t body[4] = {CMD_SLOT_STATUS, ST_OK,
                         imk_crypto_slot_bitmap(), imk_crypto_active_slot_1b()};
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_SLOT_CLEAR: {
      if (plen == 0) {
        // Clear the requesting host's own slot: reply [0x3C][OK], then reboot
        // (the reference device restarts to rotate its BLE address; the app
        // treats the disconnect itself as success).
        imk_unpair();
        send2(CMD_SLOT_CLEAR, ST_OK);
        ESP_LOGW(TAG, "own slot cleared; restarting");
        vTaskDelay(pdMS_TO_TICKS(400));
        esp_restart();
      } else {
        // Clearing another host's slot (1-based) is fingerprint-gated; the
        // live connection's own slot stays, so no reboot.
        uint8_t target = payload[0];
        if (target < 1 || target > 2) { send1(ST_ERROR); break; }
        gate_arm(GATE_DELETE, 0xFFF0 | (target - 1));  // sentinel + slot
        send1(ST_WAIT_FP);
        ESP_LOGI(TAG, "SLOT_CLEAR slot %u: gate", target);
      }
      break;
    }

    case CMD_KEY_COUNT: {
      uint8_t cat = (plen >= 1) ? payload[0] : 0;
      uint32_t crc = imk_ks_checksum(cat);
      uint8_t body[6] = {ST_OK, (uint8_t)imk_ks_count(cat),
                         (uint8_t)crc, (uint8_t)(crc >> 8),
                         (uint8_t)(crc >> 16), (uint8_t)(crc >> 24)};
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_KEY_READ: {
      // [cat][idx][off] -> [OK][readable_total][off][data<=59]
      if (plen < 3) { send1(ST_ERROR); break; }
      uint8_t body[3 + 59];
      uint8_t readable = 0;
      size_t n = imk_ks_read(payload[0], payload[1], payload[2], body + 3, 59, &readable);
      if (n == 0) { send1(ST_ERROR); break; }
      body[0] = ST_OK;
      body[1] = readable;
      body[2] = payload[2];
      send_raw(body, 3 + n);
      break;
    }

    case CMD_KEY_WRITE: {
      // [cat][idx][off][data...] — chunks accumulate in the staging buffer.
      if (plen < 4) { send1(ST_ERROR); break; }
      bool ok = imk_ks_stage(payload[0], payload[2], payload + 3, plen - 3);
      send1(ok ? ST_OK : ST_ERROR);
      break;
    }

    case CMD_KEY_COMMIT:
    case CMD_KEY_DELETE: {
      if (plen < 2) { send1(ST_ERROR); break; }
      s_keyop = (keyop_t){.op = cmd, .cat = payload[0], .idx = payload[1]};
      if (gate_needed()) {
        gate_arm(GATE_KEYOP, 0);
        send1(ST_WAIT_FP);
        ESP_LOGI(TAG, "keyop 0x%02x cat %u idx %u: gate", cmd, payload[0], payload[1]);
      } else {
        keyop_execute();
      }
      break;
    }

    case CMD_KEY_SIGN: {
      // [cat][idx][hash_off][hash:32]
      if (plen < 35) { send1(ST_ERROR); break; }
      s_keyop = (keyop_t){.op = cmd, .cat = payload[0], .idx = payload[1]};
      memcpy(s_keyop.hash, payload + 3, 32);
      if (gate_needed()) {
        gate_arm(GATE_KEYOP, 0);
        send1(ST_WAIT_FP);
        ESP_LOGI(TAG, "KEY_SIGN idx %u: gate", payload[1]);
      } else {
        keyop_execute();
      }
      break;
    }

    case CMD_KEY_GET_PUB: {
      if (plen < 2 || !imk_ks_get_pub(payload[1])) { send1(ST_ERROR); break; }
      uint8_t r[2] = {ST_OK, 64};
      send_raw(r, 2);
      break;
    }

    case CMD_KEY_GENERATE: {
      // [cat][name:16] — name rides in s_keyop.hash
      if (plen < 17) { send1(ST_ERROR); break; }
      s_keyop = (keyop_t){.op = cmd, .cat = payload[0]};
      memcpy(s_keyop.hash, payload + 1, 16);
      if (gate_needed()) {
        gate_arm(GATE_KEYOP, 0);
        send1(ST_WAIT_FP);
        ESP_LOGI(TAG, "KEY_GENERATE: gate");
      } else {
        keyop_execute();
      }
      break;
    }

    case CMD_KEY_RESULT: {
      // [off] -> [OK][total][off][data<=59]
      uint8_t off = (plen >= 1) ? payload[0] : 0;
      uint8_t body[3 + 59];
      uint8_t total = 0;
      size_t n = imk_ks_result_read(off, body + 3, 59, &total);
      if (n == 0) { send1(ST_ERROR); break; }
      body[0] = ST_OK;
      body[1] = total;
      body[2] = off;
      send_raw(body, 3 + n);
      break;
    }

    case CMD_KEY_OTP_GET: {
      // [idx][ts:4LE]
      if (plen < 5) { send1(ST_ERROR); break; }
      s_keyop = (keyop_t){.op = cmd, .idx = payload[0]};
      s_keyop.ts = (uint32_t)payload[1] | ((uint32_t)payload[2] << 8) |
                   ((uint32_t)payload[3] << 16) | ((uint32_t)payload[4] << 24);
      if (gate_needed()) {
        gate_arm(GATE_KEYOP, 0);
        send1(ST_WAIT_FP);
        ESP_LOGI(TAG, "KEY_OTP_GET idx %u: gate", payload[0]);
      } else {
        keyop_execute();
      }
      break;
    }

    case CMD_FP_MATCH_ACK: {
      send1(ST_OK);
      break;
    }

    default:
      send2(cmd, ST_ERROR);
      break;
  }
}

static void enroll_progress(uint8_t status, uint8_t captured, uint8_t total) {
  // immurok enrollment notification: [0x11][status][captured][total].
  ESP_LOGI(TAG, "enroll progress: status=0x%02x captured=%u/%u", status, captured, total);
  uint8_t n[4] = {0x11, status, captured, total};
  send_raw(n, sizeof(n));
}

bool imk_proto_enroll_requested(void) { return s_enroll_requested; }

// Runs the (blocking) streaming enrollment. Call from the main loop, not the
// BLE callback, so captures don't stall the stack.
void imk_proto_run_enrollment(void) {
  if (!s_enroll_requested) return;
  s_enroll_requested = false;
  // Let the ENROLL_START [0x10][0x00] reply be delivered before the first
  // [0x11] progress notification, so the app doesn't read progress as the reply.
  vTaskDelay(pdMS_TO_TICKS(200));
  ESP_LOGI(TAG, "running enrollment into slot %u", s_enroll_slot);
  bool ok = fingerprint_enroll_stream(s_enroll_slot, enroll_progress);
  ESP_LOGI(TAG, "enroll %s; count=%d bitmap=0x%02x",
           ok ? "ok" : "FAIL", fingerprint_count(), fingerprint_index_bitmap());
}

// Long-press (>=2s hold) lock-screen request. The app fires it regardless of
// match outcome and gates on screen state itself.
void imk_proto_send_lock_request(void) {
  send1(NOTIF_LOCK_REQ);
  ESP_LOGI(TAG, "sent lock request (long press)");
}

bool imk_proto_gate_active(void) { return s_gate != GATE_NONE; }

// Called from the main loop: ends an expired gate the way the reference
// firmware does — SEC_ERR_TIMEOUT (0x06) and back to idle.
void imk_proto_gate_tick(void) {
  if (s_gate == GATE_NONE) return;
  if ((xTaskGetTickCount() - s_gate_start) > pdMS_TO_TICKS(GATE_TIMEOUT_MS)) {
    ESP_LOGW(TAG, "gate timed out");
    s_gate = GATE_NONE;
    send1(ST_ERR_TIMEOUT);
    fingerprint_led_idle();
  }
}

// Called from the main loop with the local match result while a gate is armed.
// The device resolves the gate itself: [0x10] approve then the operation's
// result byte; wrong fingers send [0x07] (3 strikes then terminal [0x06]).
void imk_proto_gate_on_touch(bool matched, uint16_t page_id) {
  (void)page_id;
  if (s_gate == GATE_NONE) return;
  if (!matched) {
    if (++s_gate_attempts >= 3) {
      ESP_LOGW(TAG, "gate: 3 wrong fingers, denying");
      s_gate = GATE_NONE;
      send1(ST_ERR_TIMEOUT);  // terminal: device ends the gate
    } else {
      ESP_LOGW(TAG, "gate: wrong finger (%u/3)", s_gate_attempts);
      send1(ST_FP_NO_MATCH);  // app counts the attempt, keeps waiting
    }
    return;
  }

  gate_t g = s_gate;
  s_gate = GATE_NONE;
  switch (g) {
    case GATE_AUTH:
      ESP_LOGI(TAG, "gate passed: AUTH_OK");
      send1(ST_OK);  // 1-byte AUTH_OK notification
      break;
    case GATE_ENROLL:
      ESP_LOGI(TAG, "gate passed: starting enrollment into page %u", s_gate_page);
      send1(ST_GATE_OK);                 // fingerprint approved
      vTaskDelay(pdMS_TO_TICKS(150));
      send1(ST_OK);                      // gated ENROLL_START result: started
      s_enroll_slot = s_gate_page;
      s_enroll_requested = true;         // main loop runs the capture
      break;
    case GATE_KEYOP:
      ESP_LOGI(TAG, "gate passed: keyop 0x%02x", s_keyop.op);
      send1(ST_GATE_OK);
      vTaskDelay(pdMS_TO_TICKS(150));
      keyop_execute();
      break;
    case GATE_DELETE: {
      send1(ST_GATE_OK);
      bool ok;
      if ((s_gate_page & 0xFFF0) == 0xFFF0) {  // sentinel: SLOT_CLEAR
        int slot = s_gate_page & 0x0F;
        ESP_LOGI(TAG, "gate passed: clearing host slot %d", slot);
        imk_unpair_slot(slot);
        ok = true;
      } else {
        ESP_LOGI(TAG, "gate passed: deleting page %u", s_gate_page);
        ok = fingerprint_delete(s_gate_page);
        fingerprint_count();  // refresh cache
      }
      vTaskDelay(pdMS_TO_TICKS(150));
      send1(ok ? ST_OK : ST_ERROR);      // gated command result
      break;
    }
    default:
      break;
  }
}

// True when the pairing stage requires a real enrolled-finger match (second
// host), not just presence.
bool imk_proto_pairing_needs_match(void) { return s_pair_stage == PAIR_WAIT_MATCH; }

// Advance the pairing state machine on a touch. `matched` reflects a real
// search result when a match was required; presence stages pass true.
void imk_proto_on_pairing_touch(bool matched) {
  switch (s_pair_stage) {
    case PAIR_WAIT_MATCH:
      if (!matched) return;  // wrong finger: stay in the stage, LED showed red
      s_pair_stage = PAIR_WAIT_CONFIRM;
      send2(0x34, 0x03);  // PAIR_BUTTON 0x03: fingerprint passed, confirm next
      ESP_LOGI(TAG, "pairing: enrolled finger verified; touch again to confirm");
      fingerprint_led(0x03, false);
      return;
    case PAIR_WAIT_PRESENCE:
    case PAIR_WAIT_CONFIRM: {
      send2(0x34, 0x01);  // PAIR_BUTTON: confirmed — ECDH starts
      uint8_t pkt[34];
      pkt[0] = CMD_PAIR_INIT;
      if (imk_pair_begin(pkt + 1)) {
        send_raw(pkt, sizeof(pkt));
        ESP_LOGI(TAG, "pairing: sent device public key");
      } else {
        send2(CMD_PAIR_INIT, ST_ERROR);
        s_pairing_pending = false;
      }
      s_pair_stage = PAIR_IDLE;
      return;
    }
    default:
      return;
  }
}

void imk_proto_on_fingerprint(uint16_t page_id) {
  if (s_pairing_pending) {
    imk_proto_on_pairing_touch(true);
    return;
  }

  // Normal auth: map the matched sensor page back to the app's 0-based slot.
  uint16_t app_slot = (page_id > 0) ? (page_id - 1) : 0;
  uint8_t msg[3] = {NOTIF_FP_MATCH, (uint8_t)(app_slot & 0xff), (uint8_t)(app_slot >> 8)};
  uint8_t hmac[8];
  if (!imk_hmac8(msg, sizeof(msg), hmac)) return;  // not paired; nothing to send
  uint8_t notif[11];
  memcpy(notif, msg, 3);
  memcpy(notif + 3, hmac, 8);
  if (s_send) s_send(notif, sizeof(notif));
  ESP_LOGI(TAG, "sent signed match notification for app slot %u (page %u)", app_slot, page_id);
}
