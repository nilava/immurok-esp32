#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "fingerprint.h"

static const char *TAG = "immurok";

static void prompt(const char *msg) { ESP_LOGI("enroll", "%s", msg); }

void app_main(void) {
  esp_err_t nvs = nvs_flash_init();
  if (nvs == ESP_ERR_NVS_NO_FREE_PAGES || nvs == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ESP_ERROR_CHECK(nvs_flash_init());
  }

  fingerprint_init();
  ESP_LOGI(TAG, "immurok-esp32 boot; fingerprint self-test running");

  // Phase 5.0 bring-up: if no prints enrolled, enroll one into slot 1, then loop
  // searching so you can confirm the ZW101 works before BLE goes in.
  if (fingerprint_count() == 0) {
    ESP_LOGW(TAG, "no templates enrolled; enrolling into slot 1");
    if (fingerprint_enroll(1, prompt)) ESP_LOGI(TAG, "enroll OK");
    else ESP_LOGE(TAG, "enroll failed");
  }

  while (true) {
    if (fingerprint_present()) {
      uint16_t page = 0, score = 0;
      if (fingerprint_search(&page, &score)) {
        ESP_LOGI(TAG, "MATCH slot=%u score=%u", page, score);
      } else {
        ESP_LOGW(TAG, "no match");
      }
      while (fingerprint_present()) vTaskDelay(pdMS_TO_TICKS(50));
    }
    vTaskDelay(pdMS_TO_TICKS(80));
  }
}
