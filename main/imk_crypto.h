#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// immurok pairing/auth crypto. Matches app-macos/ImmurokSecurity exactly:
//   ECDH P-256 (compressed 33-byte keys)
//   shared_key = HKDF-SHA256(ecdh_secret, salt="immurok-pairing-salt",
//                            info="immurok-shared-key", 32 bytes)
//   auth       = HMAC-SHA256(shared_key, message)[0:8]

void imk_crypto_init(void);            // load a stored shared key from NVS
bool imk_crypto_is_paired(void);

// Pairing (device side). imk_pair_begin generates an ephemeral P-256 keypair and
// returns our compressed public key. imk_pair_complete takes the app's compressed
// public key, derives the shared key, persists it, and marks the device paired.
bool imk_pair_begin(uint8_t our_pubkey[33]);
bool imk_pair_complete(const uint8_t app_pubkey[33]);
void imk_pair_abort(void);
void imk_unpair(void);                 // clear the connected host's binding
void imk_unpair_slot(int slot);        // clear a specific host slot (0/1)

// Dual-host: pick the key slot for the connected peer (by bonded address).
void imk_crypto_select_host(const uint8_t bda[6]);
bool imk_crypto_any_paired(void);
uint8_t imk_crypto_slot_bitmap(void);      // bit0 = slot 1, bit1 = slot 2
int imk_crypto_free_slot(void);            // 0/1, or -1 when both bound
uint8_t imk_crypto_active_slot_1b(void);   // 1-based slot of the live host

// HMAC-SHA256(shared_key, msg)[0:8]. Returns false if not paired.
bool imk_hmac8(const uint8_t *msg, size_t len, uint8_t out[8]);
