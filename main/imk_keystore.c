#include "imk_keystore.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

static const char *TAG = "imk_ks";

#define NVS_NS "imk_ks"

typedef struct {
  const char *nvs_key;   // one blob per category: [count:1][entries...]
  uint16_t entry_size;
  uint8_t max_entries;
  uint8_t readable;      // app-visible bytes per entry (secrets masked)
} cat_info_t;

static const cat_info_t CATS[3] = {
  [KS_CAT_SSH] = {"ssh", 112, 32, 80},   // name[16]+pubkey[64]; privkey masked
  [KS_CAT_OTP] = {"otp", 92, 128, 60},   // name[30]+service[30]; secret masked
  [KS_CAT_API] = {"api", 160, 50, 160},  // fully readable (CLI fetches secrets)
};

// In-RAM mirror of each category blob (persisted whole on every mutation).
static uint8_t s_ssh[32 * 112];
static uint8_t s_otp[128 * 92];
static uint8_t s_api[50 * 160];
static uint8_t s_count[3];

// KEY_WRITE staging area + KEY_SIGN/GET_PUB/GENERATE result buffer.
static uint8_t s_stage[160];
static size_t s_stage_len;
static uint8_t s_result[64];
static uint8_t s_result_len;

static uint8_t *cat_buf(uint8_t cat) {
  switch (cat) {
    case KS_CAT_SSH: return s_ssh;
    case KS_CAT_OTP: return s_otp;
    case KS_CAT_API: return s_api;
    default: return NULL;
  }
}

static bool persist(uint8_t cat) {
  nvs_handle_t h;
  if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return false;
  size_t body = (size_t)s_count[cat] * CATS[cat].entry_size;
  // Store count + used entries only (single blob, rewritten atomically by NVS).
  // Static: ~12KB is far too big for a task stack.
  static uint8_t tmp[1 + sizeof(s_otp)];
  uint8_t hdr[1] = {s_count[cat]};
  tmp[0] = hdr[0];
  memcpy(tmp + 1, cat_buf(cat), body);
  esp_err_t err = nvs_set_blob(h, CATS[cat].nvs_key, tmp, 1 + body);
  if (err == ESP_OK) err = nvs_commit(h);
  nvs_close(h);
  if (err != ESP_OK) ESP_LOGE(TAG, "persist cat %u failed: %d", cat, (int)err);
  return err == ESP_OK;
}

void imk_keystore_init(void) {
  nvs_handle_t h;
  if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
    ESP_LOGI(TAG, "keystore empty (no namespace yet)");
    return;
  }
  for (uint8_t cat = 0; cat < 3; cat++) {
    static uint8_t tmp[1 + sizeof(s_otp)];
    size_t len = sizeof(tmp);
    if (nvs_get_blob(h, CATS[cat].nvs_key, tmp, &len) == ESP_OK && len >= 1) {
      uint8_t n = tmp[0];
      if (n > CATS[cat].max_entries) n = 0;
      size_t body = (size_t)n * CATS[cat].entry_size;
      if (1 + body <= len) {
        s_count[cat] = n;
        memcpy(cat_buf(cat), tmp + 1, body);
      }
    }
  }
  nvs_close(h);
  ESP_LOGI(TAG, "keystore: ssh=%u otp=%u api=%u", s_count[0], s_count[1], s_count[2]);
}

int imk_ks_count(uint8_t cat) {
  return (cat < 3) ? s_count[cat] : 0;
}

// CRC32 over the category's live entries — an opaque digest the app compares
// against its cache; any content-sensitive value works.
uint32_t imk_ks_checksum(uint8_t cat) {
  if (cat >= 3) return 0;
  uint32_t crc = 0xFFFFFFFF ^ s_count[cat];
  const uint8_t *p = cat_buf(cat);
  size_t n = (size_t)s_count[cat] * CATS[cat].entry_size;
  for (size_t i = 0; i < n; i++) {
    crc ^= p[i];
    for (int b = 0; b < 8; b++) crc = (crc >> 1) ^ (0xEDB88320 & (-(int32_t)(crc & 1)));
  }
  return ~crc;
}

size_t imk_ks_read(uint8_t cat, uint8_t idx, uint8_t off,
                   uint8_t *out, size_t len, uint8_t *readable_total) {
  if (cat >= 3 || idx >= s_count[cat]) return 0;
  uint8_t readable = CATS[cat].readable;
  if (readable_total) *readable_total = readable;
  if (off >= readable) return 0;
  size_t n = readable - off;
  if (n > len) n = len;
  memcpy(out, cat_buf(cat) + (size_t)idx * CATS[cat].entry_size + off, n);
  return n;
}

bool imk_ks_stage(uint8_t cat, uint8_t off, const uint8_t *data, size_t len) {
  if (cat >= 3 || (size_t)off + len > CATS[cat].entry_size) return false;
  if (off == 0) memset(s_stage, 0, sizeof(s_stage));  // new entry begins
  memcpy(s_stage + off, data, len);
  if ((size_t)off + len > s_stage_len || off == 0) s_stage_len = off + len;
  return true;
}

bool imk_ks_commit(uint8_t cat, uint8_t idx) {
  if (cat >= 3) return false;
  if (idx == 0xFF) {  // append
    if (s_count[cat] >= CATS[cat].max_entries) return false;
    idx = s_count[cat];
    s_count[cat]++;
  } else if (idx >= s_count[cat]) {
    return false;
  }
  memcpy(cat_buf(cat) + (size_t)idx * CATS[cat].entry_size, s_stage, CATS[cat].entry_size);
  s_stage_len = 0;
  ESP_LOGI(TAG, "commit cat %u idx %u", cat, idx);
  return persist(cat);
}

bool imk_ks_delete(uint8_t cat, uint8_t idx) {
  if (cat >= 3 || idx >= s_count[cat]) return false;
  uint8_t *buf = cat_buf(cat);
  uint16_t es = CATS[cat].entry_size;
  // Compact: entries stay contiguous 0..count-1 (the app indexes by position).
  memmove(buf + (size_t)idx * es, buf + (size_t)(idx + 1) * es,
          (size_t)(s_count[cat] - idx - 1) * es);
  s_count[cat]--;
  memset(buf + (size_t)s_count[cat] * es, 0, es);
  ESP_LOGI(TAG, "delete cat %u idx %u", cat, idx);
  return persist(cat);
}

static int ks_rng(void *ctx, unsigned char *out, size_t len) {
  (void)ctx;
  esp_fill_random(out, len);
  return 0;
}

static void reverse32(uint8_t *dst, const uint8_t *src) {
  for (int i = 0; i < 32; i++) dst[i] = src[31 - i];
}

bool imk_ks_sign(uint8_t idx, const uint8_t hash[32]) {
  if (idx >= s_count[KS_CAT_SSH]) return false;
  const uint8_t *entry = s_ssh + (size_t)idx * 112;
  uint8_t priv_be[32];
  reverse32(priv_be, entry + 80);  // stored little-endian

  mbedtls_ecp_group grp;
  mbedtls_mpi d, r, s;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  bool ok = false;
  do {
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) break;
    if (mbedtls_mpi_read_binary(&d, priv_be, 32)) break;
    if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32, ks_rng, NULL)) break;
    uint8_t r_be[32], s_be[32];
    if (mbedtls_mpi_write_binary(&r, r_be, 32)) break;
    if (mbedtls_mpi_write_binary(&s, s_be, 32)) break;
    reverse32(s_result, r_be);       // result buffer is LE per 32-byte half
    reverse32(s_result + 32, s_be);
    s_result_len = 64;
    ok = true;
  } while (0);
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  ESP_LOGI(TAG, "sign idx %u: %s", idx, ok ? "ok" : "FAILED");
  return ok;
}

bool imk_ks_get_pub(uint8_t idx) {
  if (idx >= s_count[KS_CAT_SSH]) return false;
  memcpy(s_result, s_ssh + (size_t)idx * 112 + 16, 64);  // stored LE already
  s_result_len = 64;
  return true;
}

bool imk_ks_generate(const uint8_t name16[16], uint8_t *new_idx) {
  if (s_count[KS_CAT_SSH] >= CATS[KS_CAT_SSH].max_entries) return false;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  bool ok = false;
  do {
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) break;
    if (mbedtls_ecp_gen_keypair(&grp, &d, &Q, ks_rng, NULL)) break;
    uint8_t priv_be[32], x_be[32], y_be[32];
    if (mbedtls_mpi_write_binary(&d, priv_be, 32)) break;
    if (mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(X), x_be, 32)) break;
    if (mbedtls_mpi_write_binary(&Q.MBEDTLS_PRIVATE(Y), y_be, 32)) break;

    uint8_t idx = s_count[KS_CAT_SSH];
    uint8_t *entry = s_ssh + (size_t)idx * 112;
    memcpy(entry, name16, 16);
    reverse32(entry + 16, x_be);   // pubkey LE
    reverse32(entry + 48, y_be);
    reverse32(entry + 80, priv_be);  // privkey LE
    s_count[KS_CAT_SSH]++;
    if (!persist(KS_CAT_SSH)) { s_count[KS_CAT_SSH]--; break; }
    memcpy(s_result, entry + 16, 64);
    s_result_len = 64;
    if (new_idx) *new_idx = idx;
    ok = true;
    ESP_LOGI(TAG, "generated SSH key idx %u", idx);
  } while (0);
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&Q);
  return ok;
}

bool imk_ks_totp(uint8_t idx, uint32_t ts, char out6[6]) {
  if (idx >= s_count[KS_CAT_OTP]) return false;
  const uint8_t *secret = s_otp + (size_t)idx * 92 + 60;
  // RFC 6238: counter = floor(unix/30), big-endian 8 bytes, HMAC-SHA1.
  // The 32-byte zero-padded secret HMACs identically to the original key
  // (HMAC zero-pads keys shorter than the block size anyway).
  uint64_t counter = ts / 30;
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) { msg[i] = counter & 0xff; counter >>= 8; }
  uint8_t mac[20];
  const mbedtls_md_info_t *sha1 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (!sha1 || mbedtls_md_hmac(sha1, secret, 32, msg, 8, mac)) return false;
  uint8_t o = mac[19] & 0x0f;
  uint32_t code = (((uint32_t)(mac[o] & 0x7f) << 24) | ((uint32_t)mac[o + 1] << 16) |
                   ((uint32_t)mac[o + 2] << 8) | mac[o + 3]) % 1000000;
  for (int i = 5; i >= 0; i--) { out6[i] = '0' + (code % 10); code /= 10; }
  return true;
}

size_t imk_ks_result_read(uint8_t off, uint8_t *out, size_t len, uint8_t *total) {
  if (total) *total = s_result_len;
  if (off >= s_result_len) return 0;
  size_t n = (size_t)s_result_len - off;
  if (n > len) n = len;
  memcpy(out, s_result + off, n);
  return n;
}
