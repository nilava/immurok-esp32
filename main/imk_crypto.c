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

// Dual-host: two independent shared keys, each bound to a host's BLE
// identity address. The active slot is selected per-connection.
static uint8_t shared_key[2][32];
static bool paired_slot[2];
static uint8_t host_addr[2][6];
static int active_slot = -1;        // -1: connected host not bound yet
static uint8_t current_bda[6];      // peer address of the live connection

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

static const char *KEY_NAMES[2] = {"key0", "key1"};
static const char *ADDR_NAMES[2] = {"addr0", "addr1"};

static void load_keys(void) {
  nvs_handle_t h;
  if (nvs_open("imk", NVS_READONLY, &h) != ESP_OK) return;
  for (int s = 0; s < 2; s++) {
    size_t len = 32;
    if (nvs_get_blob(h, KEY_NAMES[s], shared_key[s], &len) == ESP_OK && len == 32) {
      paired_slot[s] = true;
      len = 6;
      nvs_get_blob(h, ADDR_NAMES[s], host_addr[s], &len);
    }
  }
  // Legacy single-key layout ("shared_key") migrates into slot 0; its host
  // address is unknown (zeros) and gets adopted on the next bonded connect.
  if (!paired_slot[0]) {
    size_t len = 32;
    if (nvs_get_blob(h, "shared_key", shared_key[0], &len) == ESP_OK && len == 32) {
      paired_slot[0] = true;
      ESP_LOGI(TAG, "migrated legacy shared key into slot 0");
    }
  }
  nvs_close(h);
}

static bool store_slot(int s) {
  nvs_handle_t h;
  if (nvs_open("imk", NVS_READWRITE, &h) != ESP_OK) return false;
  esp_err_t r = nvs_set_blob(h, KEY_NAMES[s], shared_key[s], 32);
  if (r == ESP_OK) r = nvs_set_blob(h, ADDR_NAMES[s], host_addr[s], 6);
  if (r == ESP_OK) r = nvs_commit(h);
  nvs_close(h);
  return r == ESP_OK;
}

void imk_crypto_init(void) {
  load_keys();
  ESP_LOGI(TAG, "crypto init: slot0=%s slot1=%s",
           paired_slot[0] ? "paired" : "-", paired_slot[1] ? "paired" : "-");
}

static bool addr_zero(const uint8_t a[6]) {
  for (int i = 0; i < 6; i++) if (a[i]) return false;
  return true;
}

// Select which host slot the live connection belongs to, by peer address.
// `authenticated` means bda is the bonded IDENTITY address (auth-complete);
// only then may a legacy zero-address slot adopt the host — the address at
// connect time can be an unresolved RPA and must never be persisted.
void imk_crypto_select_host2(const uint8_t bda[6], bool authenticated) {
  memcpy(current_bda, bda, 6);
  active_slot = -1;
  for (int s = 0; s < 2; s++) {
    if (paired_slot[s] && memcmp(host_addr[s], bda, 6) == 0) { active_slot = s; break; }
  }
  if (active_slot < 0 && authenticated) {
    for (int s = 0; s < 2; s++) {
      if (paired_slot[s] && addr_zero(host_addr[s])) {
        memcpy(host_addr[s], bda, 6);
        store_slot(s);
        active_slot = s;
        ESP_LOGI(TAG, "slot %d adopted host %02x:%02x:%02x:%02x:%02x:%02x",
                 s, bda[0], bda[1], bda[2], bda[3], bda[4], bda[5]);
        break;
      }
    }
  }
  ESP_LOGI(TAG, "host selected: slot %d (%s addr)", active_slot,
           authenticated ? "identity" : "connect");
}

void imk_crypto_select_host(const uint8_t bda[6]) {
  imk_crypto_select_host2(bda, false);
}

void imk_crypto_dump_slots(void) {
  for (int s = 0; s < 2; s++) {
    const uint8_t *a = host_addr[s];
    ESP_LOGW(TAG, "slot %d: %s addr=%02x:%02x:%02x:%02x:%02x:%02x%s", s,
             paired_slot[s] ? "PAIRED" : "empty",
             a[0], a[1], a[2], a[3], a[4], a[5],
             (s == active_slot) ? "  <- active" : "");
  }
}

bool imk_crypto_is_paired(void) { return active_slot >= 0 && paired_slot[active_slot]; }
bool imk_crypto_any_paired(void) { return paired_slot[0] || paired_slot[1]; }
uint8_t imk_crypto_slot_bitmap(void) {
  return (paired_slot[0] ? 1 : 0) | (paired_slot[1] ? 2 : 0);
}
int imk_crypto_free_slot(void) {
  if (!paired_slot[0]) return 0;
  if (!paired_slot[1]) return 1;
  return -1;
}
// 1-based slot the connected host sits on (or would sit on, if unbound).
uint8_t imk_crypto_active_slot_1b(void) {
  if (active_slot >= 0) return (uint8_t)(active_slot + 1);
  int f = imk_crypto_free_slot();
  return (uint8_t)((f < 0 ? 0 : f) + 1);
}

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
    // shared_key = HKDF-SHA256(secret, salt, info, 32), into the free slot,
    // bound to the connected host's address.
    int slot = imk_crypto_free_slot();
    if (slot < 0) break;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mbedtls_hkdf(md, (const uint8_t *)HKDF_SALT, strlen(HKDF_SALT),
                     secret, sizeof(secret),
                     (const uint8_t *)HKDF_INFO, strlen(HKDF_INFO),
                     shared_key[slot], 32) != 0) break;
    memcpy(host_addr[slot], current_bda, 6);
    paired_slot[slot] = true;
    ok = store_slot(slot);
    if (ok) {
      active_slot = slot;
      ESP_LOGI(TAG, "pairing complete: slot %d", slot);
    } else {
      paired_slot[slot] = false;
    }
  } while (0);
  memset(secret, 0, sizeof(secret));
  mbedtls_ecp_point_free(&P);
  mbedtls_ecp_point_free(&S);
  imk_pair_abort();
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

void imk_unpair_slot(int slot) {
  if (slot < 0 || slot > 1) return;
  memset(shared_key[slot], 0, 32);
  memset(host_addr[slot], 0, 6);
  paired_slot[slot] = false;
  if (active_slot == slot) active_slot = -1;
  nvs_handle_t h;
  if (nvs_open("imk", NVS_READWRITE, &h) == ESP_OK) {
    nvs_erase_key(h, KEY_NAMES[slot]);
    nvs_erase_key(h, ADDR_NAMES[slot]);
    nvs_erase_key(h, "shared_key");  // legacy leftovers
    nvs_commit(h);
    nvs_close(h);
  }
  ESP_LOGI(TAG, "slot %d unpaired", slot);
}

void imk_unpair(void) {
  // Clear the connected host's binding (falls back to slot 0 pre-selection).
  imk_unpair_slot(active_slot >= 0 ? active_slot : 0);
}

bool imk_hmac8(const uint8_t *msg, size_t len, uint8_t out[8]) {
  if (active_slot < 0 || !paired_slot[active_slot]) return false;
  uint8_t full[32];
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (mbedtls_md_hmac(md, shared_key[active_slot], 32, msg, len, full) != 0) return false;
  memcpy(out, full, 8);
  return true;
}
