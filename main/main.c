#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "driver/usb_serial_jtag.h"
#include "soc/rtc_cntl_reg.h"

#include "fingerprint.h"
#include "imk_crypto.h"
#include "imk_keystore.h"
#include "imk_proto.h"
#include "imk_service.h"

static const char *TAG = "immurok";

static void prompt(const char *msg) { ESP_LOGI("enroll", "%s", msg); }

// Console input over USB-Serial-JTAG: type 'd' in the monitor to reboot straight
// into ROM download mode (no BOOT/RESET buttons), 'r' to just restart.
static void console_task(void *arg) {
  (void)arg;
  uint8_t c;
  while (true) {
    if (usb_serial_jtag_read_bytes(&c, 1, portMAX_DELAY) != 1) continue;
    if (c == 'd' || c == 'D') {
      ESP_LOGW(TAG, "rebooting into download mode…");
      vTaskDelay(pdMS_TO_TICKS(80));
      REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
      esp_restart();
    } else if (c == 'r' || c == 'R') {
      ESP_LOGW(TAG, "restarting…");
      vTaskDelay(pdMS_TO_TICKS(80));
      esp_restart();
    } else if (c == 'i' || c == 'I') {
      // Diagnostics: live count + index bitmap + which of slots 0..7 load.
      int n = fingerprint_count();
      uint8_t bm = fingerprint_index_bitmap();
      ESP_LOGW(TAG, "info: count=%d bitmap=0x%02x loadable=[%s]", n, bm,
               fingerprint_slot_probe());
    } else if (c == 'w' || c == 'W') {
      ESP_LOGW(TAG, "wiping all fingerprint templates…");
      bool ok = fingerprint_delete_all();
      fingerprint_count();  // refresh cache
      ESP_LOGW(TAG, "wipe %s; %d template(s) now", ok ? "ok" : "FAILED",
               fingerprint_cached_count());
    }
  }
}

void app_main(void) {
  esp_err_t nvs = nvs_flash_init();
  if (nvs == ESP_ERR_NVS_NO_FREE_PAGES || nvs == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
  }

  usb_serial_jtag_driver_config_t ucfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
  usb_serial_jtag_driver_install(&ucfg);
  xTaskCreate(console_task, "console", 3072, NULL, 5, NULL);

  fingerprint_init();
  imk_crypto_init();
  imk_keystore_init();
  imk_proto_init(imk_service_respond);
  imk_service_start();
  ESP_LOGI(TAG, "immurok-esp32 boot; console: d=download r=restart w=wipe fingerprints");
  (void)prompt;

  // On a fingerprint touch: during pairing it drives the ECDH pubkey exchange;
  // otherwise it sends an HMAC-signed match notification to the paired host.
  while (true) {
    if (imk_proto_enroll_requested()) {
      imk_proto_run_enrollment();
      vTaskDelay(pdMS_TO_TICKS(800));  // hold the green "enrolled" beat
      fingerprint_led_idle();
      continue;
    }
    imk_proto_gate_tick();  // expire a stale fingerprint gate (25s)
    if (fingerprint_present()) {
      if (imk_proto_pairing_pending()) {
        // Any live finger confirms physical presence for pairing.
        imk_proto_on_fingerprint(0);
      } else {
        uint16_t page = 0, score = 0;
        bool matched = false;
        // The first frame of a touch is often poor (cold sensor, light touch);
        // retry while the finger is still down before calling it a miss.
        for (int attempt = 0; attempt < 3 && !matched; attempt++) {
          matched = fingerprint_search(&page, &score);
          if (!matched && !fingerprint_present()) break;
        }
        if (matched) {
          ESP_LOGI(TAG, "MATCH slot=%u score=%u", page, score);
        } else {
          ESP_LOGW(TAG, "no match");
          fingerprint_led(0x04, true);  // steady red: final verdict
        }
        if (imk_proto_gate_active()) {
          // A gate is waiting on this verification — resolve it locally.
          imk_proto_gate_on_touch(matched, page);
        } else if (matched) {
          imk_proto_on_fingerprint(page);
        }
      }
      // Hold >=2s = lock request (reference behavior: fires regardless of the
      // match outcome; the app ignores it when the screen is already locked).
      TickType_t hold_start = xTaskGetTickCount();
      bool lock_sent = false;
      while (fingerprint_present()) {
        if (!lock_sent &&
            (xTaskGetTickCount() - hold_start) > pdMS_TO_TICKS(2000)) {
          imk_proto_send_lock_request();
          fingerprint_led(0x01, true);  // steady blue: lock request sent
          lock_sent = true;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
      }
      // Let the verdict linger a beat, then return to idle.
      vTaskDelay(pdMS_TO_TICKS(350));
      fingerprint_led_idle();
    }
    vTaskDelay(pdMS_TO_TICKS(80));
  }
}
