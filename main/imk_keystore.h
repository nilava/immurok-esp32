#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// immurok keystore: SSH P-256 keys, TOTP secrets, API secrets in NVS.
// Entry layouts match app-macos (KeystoreViewModel / CLISocketServer):
//   ssh (cat 0): name[16] + pubkey_LE[64] + privkey_LE[32]  = 112 B, 32 max
//   otp (cat 1): name[30] + service[30] + secret[32]        =  92 B, 128 max
//   api (cat 2): name[32] + key[128]                        = 160 B, 50 max
// The device's uECC heritage means pubkey/privkey are little-endian per
// 32-byte coordinate; mbedTLS work reverses at the boundary.

#define KS_CAT_SSH 0
#define KS_CAT_OTP 1
#define KS_CAT_API 2

void imk_keystore_init(void);

int imk_ks_count(uint8_t cat);
uint32_t imk_ks_checksum(uint8_t cat);  // digest the app uses for cache sync

// Read `len` bytes at `off` of entry `idx`, clamped to the category's
// app-readable size (SSH privkey and OTP secret are masked). Returns bytes
// copied, 0 on bad idx/off. *readable_total gets the masked entry size.
size_t imk_ks_read(uint8_t cat, uint8_t idx, uint8_t off,
                   uint8_t *out, size_t len, uint8_t *readable_total);

// Staging: KEY_WRITE chunks accumulate here until KEY_COMMIT persists.
bool imk_ks_stage(uint8_t cat, uint8_t off, const uint8_t *data, size_t len);
bool imk_ks_commit(uint8_t cat, uint8_t idx);  // idx 0xFF = append
bool imk_ks_delete(uint8_t cat, uint8_t idx);

// ECDSA P-256 sign a 32-byte hash with SSH key `idx`; result (r||s, LE per
// half, 64 B) lands in the result buffer read back via KEY_RESULT.
bool imk_ks_sign(uint8_t idx, const uint8_t hash[32]);

// Copy SSH key `idx`'s stored public key (LE, 64 B) into the result buffer.
bool imk_ks_get_pub(uint8_t idx);

// Generate a P-256 keypair on-device into a new SSH entry named `name16`.
// Public key (LE) lands in the result buffer. *new_idx gets the entry index.
bool imk_ks_generate(const uint8_t name16[16], uint8_t *new_idx);

// TOTP (RFC 6238, HMAC-SHA1, 30 s, 6 digits) for OTP entry `idx` at unix
// time `ts`; writes 6 ASCII digits to out6.
bool imk_ks_totp(uint8_t idx, uint32_t ts, char out6[6]);

// Result buffer (read back with KEY_RESULT 0x68).
size_t imk_ks_result_read(uint8_t off, uint8_t *out, size_t len, uint8_t *total);
