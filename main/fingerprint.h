#pragma once

#include <stdbool.h>
#include <stdint.h>

// ZW101 (Grow/Synochip-style) UART fingerprint sensor driver.
// Packet framing: 0xEF01 | addr(4) | pid(1) | len(2) | data | checksum(2).

void fingerprint_init(void);

// True while a finger is on the sensor (IRQ pin, active high).
bool fingerprint_present(void);

// Capture + search the enrolled database. On a match returns true and writes the
// matched template slot (page id) to *page_id and the score to *score.
bool fingerprint_search(uint16_t *page_id, uint16_t *score);

// Enroll a new fingerprint into `slot`, driving the caller's prompt callback with
// progress. Returns true on success.
bool fingerprint_enroll(uint16_t slot, void (*prompt)(const char *msg));

bool fingerprint_delete(uint16_t slot);
bool fingerprint_delete_all(void);

// Count of enrolled templates, or -1 on sensor error.
int fingerprint_count(void);

// Ring LED (aura). color is a 3-bit mask: blue 0x01, green 0x02, red 0x04
// (purple 0x03, white 0x07). steady=true holds; steady=false flashes.
void fingerprint_led(uint8_t color, bool steady);
