#include "imk_proto.h"

#include <string.h>

#include "esp_log.h"

#include "imk_crypto.h"
#include "fingerprint.h"

static const char *TAG = "imk_proto";

// Opcodes (immurok protocol subset for Phase 5A).
#define CMD_GET_STATUS    0x01
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

// Response framing: immurok packets are [cmd][len][payload]. Helper to send one.
static void respond(uint8_t cmd, const uint8_t *payload, size_t plen) {
  uint8_t pkt[64];
  if (plen > sizeof(pkt) - 2) plen = sizeof(pkt) - 2;
  pkt[0] = cmd;
  pkt[1] = (uint8_t)plen;
  if (plen) memcpy(pkt + 2, payload, plen);
  if (s_send) s_send(pkt, plen + 2);
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
      int fp = fingerprint_count();
      uint8_t body[8] = {
        ST_OK,
        (uint8_t)(fp > 0 ? fp : 0),          // fingerprint count/bitmap (simplified)
        (uint8_t)(imk_crypto_is_paired() ? 1 : 0),
        100,                                  // battery %
        1, 0, 0, 0,                           // fw major/minor/patch/build (placeholder)
      };
      respond(CMD_GET_STATUS, body, sizeof(body));
      break;
    }

    case CMD_PAIR_INIT: {
      if (imk_crypto_is_paired() && fingerprint_count() > 0) {
        // Already provisioned; require an explicit unpair/reset first.
        uint8_t b = ST_NEEDS_RESET;
        respond(CMD_PAIR_INIT, &b, 1);
      } else {
        s_pairing_pending = true;
        uint8_t b = ST_WAIT_BUTTON;  // waiting for the physical-presence gate (a touch)
        respond(CMD_PAIR_INIT, &b, 1);
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
      respond(CMD_PAIR_CONFIRM, &status, 1);
      break;
    }

    case CMD_PAIR_STATUS: {
      uint8_t b = imk_crypto_is_paired() ? 1 : 0;
      respond(CMD_PAIR_STATUS, &b, 1);
      break;
    }

    case CMD_CHALLENGE: {
      // [0x38][nonce:8] → [0x38][hmac:8]
      uint8_t hmac[8];
      if (plen >= 8 && imk_hmac8(payload, 8, hmac)) {
        respond(CMD_CHALLENGE, hmac, sizeof(hmac));
      } else {
        uint8_t b = ST_ERROR;
        respond(CMD_CHALLENGE, &b, 1);
      }
      break;
    }

    case CMD_FP_MATCH_ACK:
      // App acknowledged a match notification; nothing to do for now.
      break;

    default: {
      uint8_t b = ST_ERROR;
      respond(cmd, &b, 1);
      break;
    }
  }
}

void imk_proto_on_fingerprint(uint16_t page_id) {
  if (s_pairing_pending) {
    // The touch confirms pairing: generate our ephemeral key and send the
    // compressed public key so the app can complete ECDH.
    uint8_t pub[33];
    if (imk_pair_begin(pub)) {
      // Device→app pubkey notification: [0x30][pubkey:33].
      respond(CMD_PAIR_INIT, pub, sizeof(pub));
      ESP_LOGI(TAG, "pairing: sent device public key");
    } else {
      uint8_t b = ST_ERROR;
      respond(CMD_PAIR_INIT, &b, 1);
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
