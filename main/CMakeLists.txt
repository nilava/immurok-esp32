idf_component_register(
  SRCS
    "main.c"
    "fingerprint.c"
  INCLUDE_DIRS "."
  REQUIRES driver nvs_flash esp_timer
)
