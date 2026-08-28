#include "imk_proto.h"

#include <string.h>

#include "esp_log.h"

#include "imk_crypto.h"
#include "fingerprint.h"

static const char *TAG = "imk_proto";

// Opcodes (immurok protocol subset for Phase 5A).
#define CMD_GET_STATUS    0x01
#define CMD_ENROLL_START  0x10
#define CMD_ENROLL_CANCEL 0x11
#define CMD_DELETE_FP     0x12
#define CMD_FP_MATCH_ACK  0x22
#define CMD_PAIR_INIT     0x30
#define CMD_PAIR_CONFIRM  0x31
#define CMD_PAIR_STATUS   0x32
#define CMD_CHALLENGE     0x38

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
      int fp = fingerprint_cached_count();
      uint8_t bitmap = 0;
      for (int i = 0; i < fp && i < 8; i++) bitmap |= (uint8_t)(1u << i);
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
      s_enroll_slot = (plen >= 1) ? payload[0] : 1;
      s_enroll_requested = true;
      send2(CMD_ENROLL_START, ST_OK);
      ESP_LOGI(TAG, "ENROLL_START slot=%u", s_enroll_slot);
      break;
    }

    case CMD_ENROLL_CANCEL: {
      s_enroll_requested = false;
      send2(CMD_ENROLL_CANCEL, ST_OK);
      break;
    }

    case CMD_DELETE_FP: {
      uint16_t slot = (plen >= 1) ? payload[0] : 0;
      send2(CMD_DELETE_FP, fingerprint_delete(slot) ? ST_OK : ST_ERROR);
      break;
    }

    case CMD_FP_MATCH_ACK: {
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
  uint8_t n[4] = {0x11, status, captured, total};
  send_raw(n, sizeof(n));
}

bool imk_proto_enroll_requested(void) { return s_enroll_requested; }

// Runs the (blocking) streaming enrollment. Call from the main loop, not the
// BLE callback, so captures don't stall the stack.
void imk_proto_run_enrollment(void) {
  if (!s_enroll_requested) return;
  s_enroll_requested = false;
  ESP_LOGI(TAG, "running enrollment into slot %u", s_enroll_slot);
  fingerprint_enroll_stream(s_enroll_slot, enroll_progress);
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

  // Normal auth: HMAC-signed match notification [0x21][page_id:2LE][hmac:8].
  uint8_t msg[3] = {NOTIF_FP_MATCH, (uint8_t)(page_id & 0xff), (uint8_t)(page_id >> 8)};
  uint8_t hmac[8];
  if (!imk_hmac8(msg, sizeof(msg), hmac)) return;  // not paired; nothing to send
  uint8_t notif[11];
  memcpy(notif, msg, 3);
  memcpy(notif + 3, hmac, 8);
  if (s_send) s_send(notif, sizeof(notif));
  ESP_LOGI(TAG, "sent signed match notification for slot %u", page_id);
}
