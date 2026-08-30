#pragma once

#include <stdbool.h>
#include <stdint.h>

// ZW101 (Grow/Synochip-style) UART fingerprint sensor driver.
// Packet framing: 0xEF01 | addr(4) | pid(1) | len(2) | data | checksum(2).

void fingerprint_init(void);

// True while a finger is on the sensor (IRQ pin, active high). Only valid
// for detecting the START of a touch — the pin de-asserts once a capture
// completes, so it cannot tell you a finger is still held.
bool fingerprint_present(void);

// True while a finger is still on the sensor, asked of the sensor itself.
// Use this for hold/lift detection; costs one UART round-trip per call.
bool fingerprint_finger_down(void);

// Capture + search the enrolled database. On a match returns true and writes the
// matched template slot (page id) to *page_id and the score to *score.
bool fingerprint_search(uint16_t *page_id, uint16_t *score);

// Enroll a new fingerprint into `slot`, driving the caller's prompt callback with
// progress. Returns true on success.
bool fingerprint_enroll(uint16_t slot, void (*prompt)(const char *msg));

// Streaming enrollment for the immurok protocol. Calls progress() with immurok
// EnrollEvent status codes as it captures: 0x00 waiting, 0x01 captured,
// 0x02 processing, 0x03 lift finger, 0x04 complete, 0x06 overlap, 0xFF failed.
bool fingerprint_enroll_stream(uint16_t slot,
                               void (*progress)(uint8_t status, uint8_t captured, uint8_t total));

bool fingerprint_delete(uint16_t slot);
bool fingerprint_delete_all(void);

// Count of enrolled templates, or -1 on sensor error.
int fingerprint_count(void);
int fingerprint_cached_count(void);  // last known count, no UART access
uint8_t fingerprint_index_bitmap(void);  // bit i set = slot i enrolled (slots 0..7)
const char *fingerprint_slot_probe(void);  // "01..3..." map of loadable slots 0..7

// Ring LED language (mirrors the states the app documents):
//   purple ready · yellow can't-reach-host · white reading · green matched ·
//   red no-match/error · white-breathe place finger · cyan lift finger ·
//   blue switching hosts · purple-breathe pairing.
typedef enum {
  FP_LED_IDLE,
  FP_LED_UNREACHABLE,
  FP_LED_READING,
  FP_LED_MATCH,
  FP_LED_NOMATCH,
  FP_LED_ENROLL_PLACE,
  FP_LED_ENROLL_LIFT,
  FP_LED_ENROLL_OK,
  FP_LED_ENROLL_FAIL,
  FP_LED_PAIRING,
  FP_LED_SWITCHING,   // breathing blue: handing off to the other host
  FP_LED_LOCK_SENT,   // steady blue: long-press lock request sent
  FP_LED_AUTH_WAIT,  // breathing: verify an enrolled finger to proceed (any gate)
} fp_led_state_t;

void fingerprint_led_state(fp_led_state_t s);
// Hold a steady state for `ms`, re-asserting it so the module's own
// post-capture auto-indication (green on match / red blink on fail) can't
// show through. Blocks for the duration.
void fingerprint_led_hold(fp_led_state_t s, uint32_t ms);
// Suppress idle repaints (used while switching hosts, which disconnects).
void fingerprint_led_lock(bool locked);
void fingerprint_led_off(void);  // force dark, bypassing the repaint dedupe
// Block until the module's own post-match indicator window has elapsed, so
// the next paint lands cleanly instead of colliding with it. No-op when the
// last match was longer ago than the window.
void fingerprint_led_settle(void);
void fingerprint_led_set_connected(bool connected);  // steers idle color
void fingerprint_led_idle(void);   // purple when connected, yellow when not
void fingerprint_led_sweep(void);  // diagnostic: cycle the 7 colors, 2s each

// Legacy shims (old bitmask call sites map to nearest state).
void fingerprint_led(uint8_t color, bool steady);
void fingerprint_led_breathe(uint8_t color);
