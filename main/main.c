#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "driver/usb_serial_jtag.h"
#include "soc/rtc_cntl_reg.h"

#include "fingerprint.h"
#include "imk_crypto.h"
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
  imk_proto_init(imk_service_respond);
  imk_service_start();
  ESP_LOGI(TAG, "immurok-esp32 boot; type 'd' to enter download mode");
  (void)prompt;

  // On a fingerprint touch: during pairing it drives the ECDH pubkey exchange;
  // otherwise it sends an HMAC-signed match notification to the paired host.
  while (true) {
    if (imk_proto_enroll_requested()) {
      imk_proto_run_enrollment();
      continue;
    }
    if (fingerprint_present()) {
      if (imk_proto_pairing_pending()) {
        // Any live finger confirms physical presence for pairing.
        imk_proto_on_fingerprint(0);
      } else {
        uint16_t page = 0, score = 0;
        if (fingerprint_search(&page, &score)) {
          ESP_LOGI(TAG, "MATCH slot=%u score=%u", page, score);
          imk_proto_on_fingerprint(page);
        } else {
          ESP_LOGW(TAG, "no match");
        }
      }
      while (fingerprint_present()) vTaskDelay(pdMS_TO_TICKS(50));
    }
    vTaskDelay(pdMS_TO_TICKS(80));
  }
}
