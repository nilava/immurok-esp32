idf_component_register(
  SRCS
    "main.c"
    "fingerprint.c"
  INCLUDE_DIRS "."
  REQUIRES driver nvs_flash esp_timer esp_driver_usb_serial_jtag
)
