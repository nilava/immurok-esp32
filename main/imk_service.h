#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// BLE bring-up: Bluedroid GATTS custom immurok service + GAP advertising +
// Just Works bonding. Advertises as "immurok-tt" so the immurok companion apps
// discover it (service UUID 45529919-… + name filter) and pair via ECDH.

void imk_service_start(void);

// Send a packet on the response characteristic (notify). No-op if no host is
// connected or notifications aren't enabled.
void imk_service_respond(const uint8_t *data, size_t len);

bool imk_service_connected(void);
