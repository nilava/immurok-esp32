#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// immurok command protocol dispatcher. Packets are [cmd][len][payload], ≤64B.
// Responses are sent back through the response characteristic via the callback
// registered with imk_proto_init().

// Sends a response packet over the BLE response characteristic (notify).
typedef void (*imk_send_fn)(const uint8_t *data, size_t len);

void imk_proto_init(imk_send_fn send);

// Handle one inbound command packet from the command characteristic.
void imk_proto_handle(const uint8_t *pkt, size_t len);

// Called from the fingerprint task on a confirmed match: sends the HMAC-signed
// [0x21][page_id:2LE][hmac:8] notification. During pairing, a touch instead
// drives the ECDH public-key exchange step.
void imk_proto_on_fingerprint(uint16_t page_id);

// True while waiting for a fingerprint touch to confirm pairing (so the main
// loop knows to route the next touch to pairing rather than auth).
bool imk_proto_pairing_pending(void);
bool imk_proto_enroll_requested(void);
void imk_proto_run_enrollment(void);

// Reset transient state on BLE disconnect.
void imk_proto_on_disconnect(void);
