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
    } else if (c == 'c' || c == 'C') {
      ESP_LOGW(TAG, "LED color sweep: watch the ring, compare with the logged names");
      fingerprint_led_sweep();
    } else if (c == 'p' || c == 'P') {
      imk_crypto_dump_slots();
    } else if (c == 'u' || c == 'U') {
      ESP_LOGW(TAG, "clearing BOTH host bindings (fingerprints untouched)…");
      imk_unpair_slot(0);
      imk_unpair_slot(1);
      ESP_LOGW(TAG, "host bindings cleared; re-pair each computer");
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
  ESP_LOGI(TAG, "immurok-esp32 boot; console: d=download r=restart w=wipe-fp i=info p=slots u=unbind-hosts c=led-sweep");
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
        if (imk_proto_pairing_needs_match()) {
          // Second-host pairing: this touch must MATCH an enrolled finger.
          uint16_t page = 0, score = 0;
          fingerprint_led_state(FP_LED_READING);
          bool m = fingerprint_search(&page, &score);
          if (!m) fingerprint_led_hold(FP_LED_NOMATCH, 700);
          imk_proto_on_pairing_touch(m);
        } else {
          // Presence stages: any live finger confirms.
          imk_proto_on_pairing_touch(true);
        }
      } else {
        uint16_t page = 0, score = 0;
        bool matched = false;
        // Paint once for the whole touch, not per retry — search() itself no
        // longer paints, so this doesn't flicker between attempts. Skip it
        // when a gate is already breathing its own color (cyan "verify to
        // proceed") — forcing purple over that would clash mid-breath.
        bool showed_reading = !imk_proto_gate_active();
        if (showed_reading) fingerprint_led_state(FP_LED_READING);
        TickType_t reading_start = xTaskGetTickCount();
        // Single capture per touch — matches tinytouch's proven, complaint-
        // free behavior on this exact sensor. A 3x cold-start retry looked
        // good on paper but each capture attempt visibly blips the ring
        // (likely a hardware indicator baked into the sensor's own imaging
        // sequence, independent of our aura commands), so 3 attempts read
        // as an ugly triple-flicker on every ordinary wrong-finger touch.
        // Trade: rare cold-boot misses need a second tap, same as always.
        matched = fingerprint_search(&page, &score);
        if (showed_reading) {
          // A fast capture (well under a breathing cycle) painting straight
          // over "reading" reads as a flash, not a transition — give it a
          // minimum visible stretch before the verdict replaces it.
          TickType_t elapsed = xTaskGetTickCount() - reading_start;
          if (elapsed < pdMS_TO_TICKS(350)) {
            vTaskDelay(pdMS_TO_TICKS(350) - elapsed);
          }
        }
        if (matched) {
          ESP_LOGI(TAG, "MATCH slot=%u score=%u", page, score);
        } else {
          ESP_LOGW(TAG, "no match");
          // Hold red across the module's own red-blink indicator, which is
          // what made a single wrong touch read as a flicker.
          fingerprint_led_hold(FP_LED_NOMATCH, 700);
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
          fingerprint_led_state(FP_LED_SWITCHING);  // steady blue: lock sent
          lock_sent = true;
        }
        vTaskDelay(pdMS_TO_TICKS(50));
      }
      // Verdicts now hold themselves; just a short beat before idle.
      // (No-op while the LED is locked, e.g. mid host-switch.)
      vTaskDelay(pdMS_TO_TICKS(250));
      fingerprint_led_idle();
    }
    vTaskDelay(pdMS_TO_TICKS(80));
  }
}
