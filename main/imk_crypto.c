#include "imk_crypto.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

static const char *TAG = "imk_crypto";

static const char HKDF_SALT[] = "immurok-pairing-salt";
static const char HKDF_INFO[] = "immurok-shared-key";

static uint8_t shared_key[32];
static bool paired;

// Ephemeral pairing state (device private scalar + group), held between
// imk_pair_begin and imk_pair_complete.
static bool pairing_active;
static mbedtls_ecp_group pair_grp;
static mbedtls_mpi pair_d;

static int rng_cb(void *ctx, unsigned char *out, size_t len) {
  (void)ctx;
  esp_fill_random(out, len);
  return 0;
}

static void load_shared_key(void) {
  paired = false;
  nvs_handle_t h;
  if (nvs_open("imk", NVS_READONLY, &h) != ESP_OK) return;
  size_t len = sizeof(shared_key);
  if (nvs_get_blob(h, "shared_key", shared_key, &len) == ESP_OK && len == sizeof(shared_key)) {
    paired = true;
  }
  nvs_close(h);
}

static bool store_shared_key(void) {
  nvs_handle_t h;
  if (nvs_open("imk", NVS_READWRITE, &h) != ESP_OK) return false;
  esp_err_t r = nvs_set_blob(h, "shared_key", shared_key, sizeof(shared_key));
  if (r == ESP_OK) r = nvs_commit(h);
  nvs_close(h);
  return r == ESP_OK;
}

void imk_crypto_init(void) {
  load_shared_key();
  ESP_LOGI(TAG, "crypto init: %s", paired ? "paired" : "unpaired");
}

bool imk_crypto_is_paired(void) { return paired; }

// Write point Q as a 33-byte compressed key: [0x02|Yparity][X:32].
static bool point_to_compressed(mbedtls_ecp_group *grp, const mbedtls_ecp_point *Q,
                                uint8_t out[33]) {
  out[0] = 0x02 | (uint8_t)(mbedtls_mpi_get_bit(&Q->MBEDTLS_PRIVATE(Y), 0));
  return mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(X), out + 1, 32) == 0;
}

// Decompress a 33-byte compressed key into point P on the curve.
// P-256: y^2 = x^3 - 3x + b (mod p); since p = 3 (mod 4), y = z^((p+1)/4) mod p.
static bool compressed_to_point(mbedtls_ecp_group *grp, const uint8_t in[33],
                                mbedtls_ecp_point *P) {
  if (in[0] != 0x02 && in[0] != 0x03) return false;
  bool ok = false;
  mbedtls_mpi x, y, rhs, t, exp;
  mbedtls_mpi_init(&x); mbedtls_mpi_init(&y); mbedtls_mpi_init(&rhs);
  mbedtls_mpi_init(&t); mbedtls_mpi_init(&exp);
  do {
    if (mbedtls_mpi_read_binary(&x, in + 1, 32) != 0) break;
    // rhs = x^3 - 3x + b (mod p)  == x*(x^2 - 3) + b
    if (mbedtls_mpi_mul_mpi(&t, &x, &x) != 0) break;                 // x^2
    if (mbedtls_mpi_sub_int(&t, &t, 3) != 0) break;                  // x^2 - 3
    if (mbedtls_mpi_mul_mpi(&rhs, &t, &x) != 0) break;               // x^3 - 3x
    if (mbedtls_mpi_add_mpi(&rhs, &rhs, &grp->B) != 0) break;        // + b
    if (mbedtls_mpi_mod_mpi(&rhs, &rhs, &grp->P) != 0) break;
    // y = rhs^((p+1)/4) mod p
    if (mbedtls_mpi_add_int(&exp, &grp->P, 1) != 0) break;
    if (mbedtls_mpi_shift_r(&exp, 2) != 0) break;
    if (mbedtls_mpi_exp_mod(&y, &rhs, &exp, &grp->P, NULL) != 0) break;
    // choose parity to match the compressed prefix
    if ((uint8_t)mbedtls_mpi_get_bit(&y, 0) != (in[0] & 1)) {
      if (mbedtls_mpi_sub_mpi(&y, &grp->P, &y) != 0) break;
    }
    if (mbedtls_mpi_copy(&P->MBEDTLS_PRIVATE(X), &x) != 0) break;
    if (mbedtls_mpi_copy(&P->MBEDTLS_PRIVATE(Y), &y) != 0) break;
    if (mbedtls_mpi_lset(&P->MBEDTLS_PRIVATE(Z), 1) != 0) break;
    ok = mbedtls_ecp_check_pubkey(grp, P) == 0;
  } while (0);
  mbedtls_mpi_free(&x); mbedtls_mpi_free(&y); mbedtls_mpi_free(&rhs);
  mbedtls_mpi_free(&t); mbedtls_mpi_free(&exp);
  return ok;
}

bool imk_pair_begin(uint8_t our_pubkey[33]) {
  imk_pair_abort();
  mbedtls_ecp_group_init(&pair_grp);
  mbedtls_mpi_init(&pair_d);
  if (mbedtls_ecp_group_load(&pair_grp, MBEDTLS_ECP_DP_SECP256R1) != 0) return false;

  mbedtls_ecp_point Q;
  mbedtls_ecp_point_init(&Q);
  bool ok = false;
  do {
    if (mbedtls_ecp_gen_keypair(&pair_grp, &pair_d, &Q, rng_cb, NULL) != 0) break;
    if (!point_to_compressed(&pair_grp, &Q, our_pubkey)) break;
    ok = true;
  } while (0);
  mbedtls_ecp_point_free(&Q);
  if (!ok) { imk_pair_abort(); return false; }
  pairing_active = true;
  return true;
}

bool imk_pair_complete(const uint8_t app_pubkey[33]) {
  if (!pairing_active) return false;
  mbedtls_ecp_point P, S;
  mbedtls_ecp_point_init(&P);
  mbedtls_ecp_point_init(&S);
  uint8_t secret[32];
  bool ok = false;
  do {
    if (!compressed_to_point(&pair_grp, app_pubkey, &P)) break;
    // S = d * P; the ECDH secret is S.X (32 bytes).
    if (mbedtls_ecp_mul(&pair_grp, &S, &pair_d, &P, rng_cb, NULL) != 0) break;
    if (mbedtls_mpi_write_binary(&S.MBEDTLS_PRIVATE(X), secret, sizeof(secret)) != 0) break;
    // shared_key = HKDF-SHA256(secret, salt, info, 32)
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mbedtls_hkdf(md, (const uint8_t *)HKDF_SALT, strlen(HKDF_SALT),
                     secret, sizeof(secret),
                     (const uint8_t *)HKDF_INFO, strlen(HKDF_INFO),
                     shared_key, sizeof(shared_key)) != 0) break;
    ok = store_shared_key();
  } while (0);
  memset(secret, 0, sizeof(secret));
  mbedtls_ecp_point_free(&P);
  mbedtls_ecp_point_free(&S);
  imk_pair_abort();
  if (ok) { paired = true; ESP_LOGI(TAG, "pairing complete"); }
  return ok;
}

void imk_pair_abort(void) {
  if (!pairing_active && pair_d.MBEDTLS_PRIVATE(p) == NULL) {
    // nothing to free (already clean)
  }
  mbedtls_mpi_free(&pair_d);
  mbedtls_ecp_group_free(&pair_grp);
  pairing_active = false;
}

void imk_unpair(void) {
  memset(shared_key, 0, sizeof(shared_key));
  paired = false;
  nvs_handle_t h;
  if (nvs_open("imk", NVS_READWRITE, &h) == ESP_OK) {
    nvs_erase_key(h, "shared_key");
    nvs_commit(h);
    nvs_close(h);
  }
}

bool imk_hmac8(const uint8_t *msg, size_t len, uint8_t out[8]) {
  if (!paired) return false;
  uint8_t full[32];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (mbedtls_md_hmac(md, shared_key, sizeof(shared_key), msg, len, full) != 0) return false;
  memcpy(out, full, 8);
  return true;
}
