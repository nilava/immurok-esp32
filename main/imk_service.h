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

// Disconnect and advertise whitelist-only toward `addr` for 30s, so the
// other bound host picks the device up (the switch-finger feature).
void imk_service_switch_host(const uint8_t addr[6], uint8_t atype);

bool imk_service_connected(void);

// Proximity feasibility probe: passively survey nearby BLE advertisers for
// `seconds` and log each one's name, address, RSSI and advertising cadence.
// Blocks — call from the console task, not from a BLE callback.
// `active` also solicits scan responses (finds names that aren't in the
// advertising packet) at the cost of transmitting scan requests.
void imk_service_scan_dump(uint32_t seconds, bool active);
