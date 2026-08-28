#include "imk_proto.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "imk_crypto.h"
#include "fingerprint.h"

static const char *TAG = "imk_proto";

// Opcodes (immurok protocol subset for Phase 5A).
#define CMD_GET_STATUS    0x01
#define CMD_ENROLL_START  0x10
#define CMD_ENROLL_CANCEL 0x11
#define CMD_DELETE_FP     0x12
#define CMD_FP_LIST       0x13
#define CMD_FP_MATCH_ACK  0x22
#define CMD_PAIR_INIT     0x30
#define CMD_PAIR_CONFIRM  0x31
#define CMD_PAIR_STATUS   0x32
#define CMD_AUTH_REQUEST  0x33
#define CMD_CHALLENGE     0x38
#define CMD_SLOT_STATUS   0x39
#define CMD_SLOT_CLEAR    0x3C

// Status/response bytes.
#define ST_OK          0x00
#define ST_WAIT_FP     0x11
#define ST_WAIT_BUTTON 0xF0
#define ST_NEEDS_RESET 0xF1
#define ST_ERROR       0xFF

// Notification tags.
#define NOTIF_FP_MATCH 0x21

static imk_send_fn s_send;
static bool s_pairing_pending;  // PAIR_INIT received, waiting for a touch
static volatile bool s_enroll_requested;
static uint16_t s_enroll_slot;

// Fingerprint gate: sensitive ops (enroll-with-existing-prints, auth/test) first
// require verifying an already-enrolled finger. Reply WAIT_FP, wait for a touch
// that produces a signed [0x21] the app verifies, then FP_MATCH_ACK runs the op.
typedef enum { GATE_NONE, GATE_AUTH, GATE_ENROLL } gate_t;
static gate_t s_gate;
static uint16_t s_gate_enroll_page;

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

void imk_proto_init(imk_send_fn send) {
  s_send = send;
  s_pairing_pending = false;
}

bool imk_proto_pairing_pending(void) { return s_pairing_pending; }

void imk_proto_on_disconnect(void) {
  s_pairing_pending = false;
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
        0, 1, 0,       // fw major.minor.patch
        0, 1,          // build (big-endian)
      };
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_PAIR_INIT: {
      if (imk_crypto_is_paired() && fingerprint_count() > 0) {
        // Already provisioned; require an explicit unpair/reset first.
        send2(CMD_PAIR_INIT, ST_NEEDS_RESET);
      } else {
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
      send2(CMD_PAIR_CONFIRM, status);
      break;
    }

    case CMD_PAIR_STATUS: {
      send2(CMD_PAIR_STATUS, imk_crypto_is_paired() ? 1 : 0);
      break;
    }

    case CMD_AUTH_REQUEST: {
      s_gate = GATE_AUTH;
      send2(CMD_AUTH_REQUEST, ST_WAIT_FP);
      ESP_LOGI(TAG, "AUTH_REQUEST: gate (touch to verify)");
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
      if (fingerprint_cached_count() > 0) {
        // Existing prints: require verifying an enrolled finger first.
        s_gate = GATE_ENROLL;
        s_gate_enroll_page = page;
        send2(CMD_ENROLL_START, ST_WAIT_FP);
        ESP_LOGI(TAG, "ENROLL_START app_slot=%u: gate (verify enrolled finger) -> page %u",
                 app_slot, page);
      } else {
        s_enroll_slot = page;
        s_enroll_requested = true;
        send2(CMD_ENROLL_START, ST_OK);
        ESP_LOGI(TAG, "ENROLL_START app_slot=%u -> sensor page=%u (first enroll)", app_slot, page);
      }
      break;
    }

    case CMD_ENROLL_CANCEL: {
      s_enroll_requested = false;
      send2(CMD_ENROLL_CANCEL, ST_OK);
      break;
    }

    case CMD_DELETE_FP: {
      uint16_t page = ((plen >= 1) ? payload[0] : 0) + 1;
      send2(CMD_DELETE_FP, fingerprint_delete(page) ? ST_OK : ST_ERROR);
      break;
    }

    case CMD_FP_LIST: {
      uint8_t body[2] = {ST_OK, (uint8_t)(fingerprint_index_bitmap() >> 1)};
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_SLOT_STATUS: {
      // Dual-host binding status: [0x39][0x00][bound bitmap][active slot].
      // We currently keep a single shared key = host slot 0 (Host 1).
      uint8_t bound = imk_crypto_is_paired() ? 0x01 : 0x00;
      uint8_t body[4] = {CMD_SLOT_STATUS, ST_OK, bound, 0x00};
      send_raw(body, sizeof(body));
      break;
    }

    case CMD_SLOT_CLEAR: {
      // Clear a host binding. Slot 0 = the paired key; clearing it unpairs.
      uint8_t slot = (plen >= 1) ? payload[0] : 0;
      if (slot == 0) imk_unpair();
      send2(CMD_SLOT_CLEAR, ST_OK);
      break;
    }

    case CMD_FP_MATCH_ACK: {
      if (s_gate == GATE_ENROLL) {
        s_gate = GATE_NONE;
        s_enroll_slot = s_gate_enroll_page;
        s_enroll_requested = true;  // main loop starts the actual enrollment
        ESP_LOGI(TAG, "gate passed; starting enrollment into page %u", s_enroll_slot);
      } else if (s_gate == GATE_AUTH) {
        s_gate = GATE_NONE;
        ESP_LOGI(TAG, "gate passed (auth/test)");
      }
      uint8_t ok = ST_OK;
      send_raw(&ok, 1);
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

void imk_proto_on_fingerprint(uint16_t page_id) {
  if (s_pairing_pending) {
    // The touch confirms physical presence: notify the app (PAIR_BUTTON, as
    // immurok's hardware button would), then generate our ephemeral key and
    // send the raw [0x30][pubkey:33] message the app slices as 1..<34.
    send2(0x34, 0x01);  // PAIR_BUTTON: confirmed
    uint8_t pkt[34];
    pkt[0] = CMD_PAIR_INIT;
    if (imk_pair_begin(pkt + 1)) {
      send_raw(pkt, sizeof(pkt));
      ESP_LOGI(TAG, "pairing: sent device public key");
    } else {
      send2(CMD_PAIR_INIT, ST_ERROR);
      s_pairing_pending = false;
    }
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
