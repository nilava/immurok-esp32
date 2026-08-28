#include "imk_service.h"

#include <string.h>

#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_gatt_common_api.h"
#include "esp_log.h"

#include "imk_proto.h"

static const char *TAG = "imk_service";

#define DEVICE_NAME "immurok-tt"
#define APPEARANCE_KEYBOARD 0x03C1

// Custom immurok service/char UUIDs in Bluedroid little-endian order.
static const uint8_t UUID_SVC[16] = {
  0xd9, 0x95, 0x65, 0xbe, 0xea, 0xe4, 0xfe, 0xb9,
  0xf9, 0x48, 0x68, 0x76, 0x19, 0x99, 0x52, 0x45};
static const uint8_t UUID_CMD[16] = {
  0xe1, 0x86, 0x81, 0x77, 0x4e, 0x8d, 0x77, 0x8b,
  0x2c, 0x4b, 0x92, 0x39, 0x1f, 0x7e, 0x53, 0x8a};
static const uint8_t UUID_RESP[16] = {
  0x89, 0xe2, 0x28, 0x60, 0x48, 0x70, 0xfc, 0xb3,
  0xd1, 0x44, 0xf6, 0x8c, 0x0d, 0x66, 0xa1, 0x76};

// SIG UUIDs.
static const uint16_t primary_service_uuid = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t char_decl_uuid = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t cccd_uuid = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
static const uint16_t rpt_ref_uuid = ESP_GATT_UUID_RPT_REF_DESCR;   // 0x2908
static const uint16_t devinfo_svc_uuid = ESP_GATT_UUID_DEVICE_INFO_SVC;   // 0x180A
static const uint16_t pnp_uuid = ESP_GATT_UUID_PNP_ID;                    // 0x2A50
static const uint16_t bat_svc_uuid = ESP_GATT_UUID_BATTERY_SERVICE_SVC;   // 0x180F
static const uint16_t bat_level_uuid = ESP_GATT_UUID_BATTERY_LEVEL;       // 0x2A19
static const uint16_t hid_svc_uuid = ESP_GATT_UUID_HID_SVC;               // 0x1812
static const uint16_t hid_info_uuid = ESP_GATT_UUID_HID_INFORMATION;      // 0x2A4A
static const uint16_t hid_ctrl_uuid = ESP_GATT_UUID_HID_CONTROL_POINT;    // 0x2A4C
static const uint16_t hid_report_map_uuid = ESP_GATT_UUID_HID_REPORT_MAP; // 0x2A4B
static const uint16_t hid_report_uuid = ESP_GATT_UUID_HID_REPORT;         // 0x2A4D
static const uint16_t hid_proto_uuid = ESP_GATT_UUID_HID_PROTO_MODE;      // 0x2A4E

static const uint8_t prop_read = ESP_GATT_CHAR_PROP_BIT_READ;
static const uint8_t prop_write = ESP_GATT_CHAR_PROP_BIT_WRITE;
static const uint8_t prop_write_nr = ESP_GATT_CHAR_PROP_BIT_WRITE_NR;
static const uint8_t prop_read_write_nr = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE_NR;
static const uint8_t prop_read_notify = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_NOTIFY;

// Standard boot-keyboard report map, report ID 1.
static const uint8_t hid_report_map[] = {
  0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,
  0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
  0x95, 0x01, 0x75, 0x08, 0x81, 0x03,
  0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
  0xC0};
static const uint8_t hid_info_val[4] = {0x11, 0x01, 0x00, 0x02};  // bcdHID 1.11, country 0, flags normally-connectable
static uint8_t hid_ctrl_val[1] = {0};
static uint8_t hid_proto_val[1] = {0x01};  // report protocol
static uint8_t hid_report_val[8] = {0};
static uint8_t hid_report_cccd[2] = {0, 0};
static const uint8_t hid_report_ref[2] = {0x01, 0x01};  // report id 1, input
static const uint8_t pnp_val[7] = {0x02, 0x3a, 0x30, 0x01, 0x40, 0x00, 0x01};  // USB VID 0x303a, PID 0x4001
static uint8_t bat_level_val[1] = {100};
static uint8_t bat_cccd[2] = {0, 0};
static uint8_t cccd_val[2] = {0, 0};
static uint8_t resp_val[1] = {0};

enum {
  IDX_DEV_SVC, IDX_PNP_CHAR, IDX_PNP_VAL,
  IDX_BAT_SVC, IDX_BAT_CHAR, IDX_BAT_VAL, IDX_BAT_CCCD,
  IDX_HID_SVC, IDX_HID_INFO_CHAR, IDX_HID_INFO_VAL,
  IDX_HID_CTRL_CHAR, IDX_HID_CTRL_VAL,
  IDX_HID_PROTO_CHAR, IDX_HID_PROTO_VAL,
  IDX_HID_MAP_CHAR, IDX_HID_MAP_VAL,
  IDX_HID_RPT_CHAR, IDX_HID_RPT_VAL, IDX_HID_RPT_CCCD, IDX_HID_RPT_REF,
  IDX_SVC, IDX_CMD_CHAR, IDX_CMD_VAL, IDX_RESP_CHAR, IDX_RESP_VAL, IDX_RESP_CCCD,
  IDX_NB,
};
static uint16_t handle_table[IDX_NB];

static esp_gatt_if_t s_gatts_if = ESP_GATT_IF_NONE;
static uint16_t s_conn_id;
static bool s_connected;
static bool s_notify_enabled;

static esp_ble_adv_data_t adv_data = {
  .set_scan_rsp = false,
  .include_name = true,
  .include_txpower = false,
  .appearance = APPEARANCE_KEYBOARD,
  .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};
// Advertise the HID service UUID (16-bit) so macOS treats it as a keyboard.
static uint16_t hid_adv_uuid = ESP_GATT_UUID_HID_SVC;
static esp_ble_adv_data_t scan_rsp = {
  .set_scan_rsp = true,
  .service_uuid_len = 2,
  .p_service_uuid = (uint8_t *)&hid_adv_uuid,
};
static esp_ble_adv_params_t adv_params = {
  .adv_int_min = 0x20, .adv_int_max = 0x40, .adv_type = ADV_TYPE_IND,
  .own_addr_type = BLE_ADDR_TYPE_PUBLIC, .channel_map = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

#define ENC_R ESP_GATT_PERM_READ_ENCRYPTED
#define ENC_W ESP_GATT_PERM_WRITE_ENCRYPTED

static const esp_gatts_attr_db_t gatt_db[IDX_NB] = {
  // --- Device Information ---
  [IDX_DEV_SVC] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, 2, 2, (uint8_t *)&devinfo_svc_uuid}},
  [IDX_PNP_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read}},
  [IDX_PNP_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&pnp_uuid, ESP_GATT_PERM_READ, sizeof(pnp_val), sizeof(pnp_val), (uint8_t *)pnp_val}},

  // --- Battery ---
  [IDX_BAT_SVC] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, 2, 2, (uint8_t *)&bat_svc_uuid}},
  [IDX_BAT_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_notify}},
  [IDX_BAT_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&bat_level_uuid, ESP_GATT_PERM_READ, 1, 1, bat_level_val}},
  [IDX_BAT_CCCD] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&cccd_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, 2, 2, bat_cccd}},

  // --- HID ---
  [IDX_HID_SVC] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, 2, 2, (uint8_t *)&hid_svc_uuid}},
  [IDX_HID_INFO_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read}},
  [IDX_HID_INFO_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_info_uuid, ESP_GATT_PERM_READ, sizeof(hid_info_val), sizeof(hid_info_val), (uint8_t *)hid_info_val}},
  [IDX_HID_CTRL_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_write_nr}},
  [IDX_HID_CTRL_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_ctrl_uuid, ESP_GATT_PERM_WRITE, 1, 1, hid_ctrl_val}},
  [IDX_HID_PROTO_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_write_nr}},
  [IDX_HID_PROTO_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_proto_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, 1, 1, hid_proto_val}},
  [IDX_HID_MAP_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read}},
  [IDX_HID_MAP_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_report_map_uuid, ENC_R, sizeof(hid_report_map), sizeof(hid_report_map), (uint8_t *)hid_report_map}},
  [IDX_HID_RPT_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_notify}},
  [IDX_HID_RPT_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_report_uuid, ENC_R, sizeof(hid_report_val), sizeof(hid_report_val), hid_report_val}},
  [IDX_HID_RPT_CCCD] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&cccd_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, 2, 2, hid_report_cccd}},
  [IDX_HID_RPT_REF] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&rpt_ref_uuid, ESP_GATT_PERM_READ, sizeof(hid_report_ref), sizeof(hid_report_ref), (uint8_t *)hid_report_ref}},

  // --- Custom immurok service ---
  [IDX_SVC] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, sizeof(UUID_SVC), sizeof(UUID_SVC), (uint8_t *)UUID_SVC}},
  [IDX_CMD_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_write}},
  [IDX_CMD_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_128, (uint8_t *)UUID_CMD, ENC_W, 64, 0, NULL}},
  [IDX_RESP_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_notify}},
  [IDX_RESP_VAL] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_128, (uint8_t *)UUID_RESP, ENC_R, 64, sizeof(resp_val), resp_val}},
  [IDX_RESP_CCCD] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&cccd_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, 2, 2, cccd_val}},
};

void imk_service_respond(const uint8_t *data, size_t len) {
  if (!s_connected || !s_notify_enabled || s_gatts_if == ESP_GATT_IF_NONE) return;
  esp_ble_gatts_send_indicate(s_gatts_if, s_conn_id, handle_table[IDX_RESP_VAL],
                              len, (uint8_t *)data, false);
}

bool imk_service_connected(void) { return s_connected; }

static void gap_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  switch (event) {
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
      esp_ble_gap_config_adv_data(&scan_rsp);
      break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT:
      esp_ble_gap_start_advertising(&adv_params);
      break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
      ESP_LOGI(TAG, "advertising as %s (%s)", DEVICE_NAME,
               param->adv_start_cmpl.status == ESP_BT_STATUS_SUCCESS ? "ok" : "FAIL");
      break;
    case ESP_GAP_BLE_AUTH_CMPL_EVT:
      ESP_LOGI(TAG, "auth complete: %s",
               param->ble_security.auth_cmpl.success ? "success" : "FAIL");
      break;
    case ESP_GAP_BLE_SEC_REQ_EVT:
      esp_ble_gap_security_rsp(param->ble_security.ble_req.bd_addr, true);
      break;
    default:
      break;
  }
}

static void gatts_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if,
                          esp_ble_gatts_cb_param_t *param) {
  switch (event) {
    case ESP_GATTS_REG_EVT:
      s_gatts_if = gatts_if;
      esp_ble_gap_set_device_name(DEVICE_NAME);
      esp_ble_gap_config_adv_data(&adv_data);
      esp_ble_gatts_create_attr_tab(gatt_db, gatts_if, IDX_NB, 0);
      break;
    case ESP_GATTS_CREAT_ATTR_TAB_EVT:
      if (param->add_attr_tab.status == ESP_GATT_OK && param->add_attr_tab.num_handle == IDX_NB) {
        memcpy(handle_table, param->add_attr_tab.handles, sizeof(handle_table));
        esp_ble_gatts_start_service(handle_table[IDX_DEV_SVC]);
        esp_ble_gatts_start_service(handle_table[IDX_BAT_SVC]);
        esp_ble_gatts_start_service(handle_table[IDX_HID_SVC]);
        esp_ble_gatts_start_service(handle_table[IDX_SVC]);
        ESP_LOGI(TAG, "services started");
      } else {
        ESP_LOGE(TAG, "attr table failed: status=%d num=%d",
                 param->add_attr_tab.status, param->add_attr_tab.num_handle);
      }
      break;
    case ESP_GATTS_CONNECT_EVT: {
      s_conn_id = param->connect.conn_id;
      s_connected = true;
      esp_ble_conn_update_params_t cp = {.min_int = 24, .max_int = 40, .latency = 29, .timeout = 600};
      memcpy(cp.bda, param->connect.remote_bda, sizeof(cp.bda));
      esp_ble_gap_update_conn_params(&cp);
      ESP_LOGI(TAG, "host connected");
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT:
      s_connected = false;
      s_notify_enabled = false;
      imk_proto_on_disconnect();
      ESP_LOGI(TAG, "host disconnected; re-advertising");
      esp_ble_gap_start_advertising(&adv_params);
      break;
    case ESP_GATTS_WRITE_EVT:
      if (param->write.handle == handle_table[IDX_CMD_VAL]) {
        imk_proto_handle(param->write.value, param->write.len);
      } else if (param->write.handle == handle_table[IDX_RESP_CCCD] && param->write.len == 2) {
        s_notify_enabled = (param->write.value[0] & 0x01) != 0;
        ESP_LOGI(TAG, "immurok notifications %s", s_notify_enabled ? "on" : "off");
      }
      if (param->write.need_rsp) {
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
      }
      break;
    default:
      break;
  }
}

void imk_service_start(void) {
  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));
  ESP_ERROR_CHECK(esp_bt_controller_init(&bt_cfg));
  ESP_ERROR_CHECK(esp_bt_controller_enable(ESP_BT_MODE_BLE));
  ESP_ERROR_CHECK(esp_bluedroid_init());
  ESP_ERROR_CHECK(esp_bluedroid_enable());

  ESP_ERROR_CHECK(esp_ble_gap_register_callback(gap_handler));
  ESP_ERROR_CHECK(esp_ble_gatts_register_callback(gatts_handler));

  esp_ble_auth_req_t auth = ESP_LE_AUTH_REQ_SC_BOND;
  esp_ble_io_cap_t iocap = ESP_IO_CAP_NONE;
  uint8_t key_size = 16;
  uint8_t init_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  uint8_t rsp_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth, sizeof(auth));
  esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &iocap, sizeof(iocap));
  esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &key_size, sizeof(key_size));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &init_key, sizeof(init_key));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rsp_key, sizeof(rsp_key));

  esp_ble_gatt_set_local_mtu(200);
  ESP_ERROR_CHECK(esp_ble_gatts_app_register(0));
  ESP_LOGI(TAG, "BLE service starting");
}
