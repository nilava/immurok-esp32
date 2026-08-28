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

static const uint16_t primary_service_uuid = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t char_decl_uuid = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t cccd_uuid = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
static const uint16_t rpt_ref_uuid = ESP_GATT_UUID_RPT_REF_DESCR;
static const uint16_t devinfo_svc_uuid = ESP_GATT_UUID_DEVICE_INFO_SVC;
static const uint16_t pnp_uuid = ESP_GATT_UUID_PNP_ID;
static const uint16_t bat_svc_uuid = ESP_GATT_UUID_BATTERY_SERVICE_SVC;
static const uint16_t bat_level_uuid = ESP_GATT_UUID_BATTERY_LEVEL;
static const uint16_t hid_svc_uuid = ESP_GATT_UUID_HID_SVC;
static const uint16_t hid_info_uuid = ESP_GATT_UUID_HID_INFORMATION;
static const uint16_t hid_ctrl_uuid = ESP_GATT_UUID_HID_CONTROL_POINT;
static const uint16_t hid_report_map_uuid = ESP_GATT_UUID_HID_REPORT_MAP;
static const uint16_t hid_report_uuid = ESP_GATT_UUID_HID_REPORT;
static const uint16_t hid_proto_uuid = ESP_GATT_UUID_HID_PROTO_MODE;

static const uint8_t prop_read = ESP_GATT_CHAR_PROP_BIT_READ;
static const uint8_t prop_write = ESP_GATT_CHAR_PROP_BIT_WRITE;
static const uint8_t prop_write_nr = ESP_GATT_CHAR_PROP_BIT_WRITE_NR;
static const uint8_t prop_read_write_nr = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_WRITE_NR;
static const uint8_t prop_read_notify = ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_NOTIFY;

static const uint8_t hid_report_map[] = {
  0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x85, 0x01,
  0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
  0x95, 0x01, 0x75, 0x08, 0x81, 0x03,
  0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
  0xC0};
static const uint8_t hid_info_val[4] = {0x11, 0x01, 0x00, 0x02};
static uint8_t hid_ctrl_val[1] = {0};
static uint8_t hid_proto_val[1] = {0x01};
static uint8_t hid_report_val[8] = {0};
static uint8_t hid_report_cccd[2] = {0, 0};
static const uint8_t hid_report_ref[2] = {0x01, 0x01};
static const uint8_t pnp_val[7] = {0x02, 0x3a, 0x30, 0x01, 0x40, 0x00, 0x01};
static uint8_t bat_level_val[1] = {100};
static uint8_t bat_cccd[2] = {0, 0};
static uint8_t cccd_val[2] = {0, 0};
static uint8_t resp_val[1] = {0};

#define ENC_R ESP_GATT_PERM_READ_ENCRYPTED
#define ENC_W ESP_GATT_PERM_WRITE_ENCRYPTED
#define RW   (ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE)

// One service per attribute table (Bluedroid restriction), created in sequence.
enum { D_SVC, D_PNP_CHAR, D_PNP_VAL, D_NB };
static const esp_gatts_attr_db_t db_dev[D_NB] = {
  [D_SVC]      = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, 2, 2, (uint8_t *)&devinfo_svc_uuid}},
  [D_PNP_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read}},
  [D_PNP_VAL]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&pnp_uuid, ESP_GATT_PERM_READ, sizeof(pnp_val), sizeof(pnp_val), (uint8_t *)pnp_val}},
};

enum { B_SVC, B_CHAR, B_VAL, B_CCCD, B_NB };
static const esp_gatts_attr_db_t db_bat[B_NB] = {
  [B_SVC]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, 2, 2, (uint8_t *)&bat_svc_uuid}},
  [B_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_notify}},
  [B_VAL]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&bat_level_uuid, ESP_GATT_PERM_READ, 1, 1, bat_level_val}},
  [B_CCCD] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&cccd_uuid, RW, 2, 2, bat_cccd}},
};

enum { H_SVC, H_INFO_CHAR, H_INFO_VAL, H_CTRL_CHAR, H_CTRL_VAL, H_PROTO_CHAR, H_PROTO_VAL,
       H_MAP_CHAR, H_MAP_VAL, H_RPT_CHAR, H_RPT_VAL, H_RPT_CCCD, H_RPT_REF, H_NB };
static const esp_gatts_attr_db_t db_hid[H_NB] = {
  [H_SVC]        = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, 2, 2, (uint8_t *)&hid_svc_uuid}},
  [H_INFO_CHAR]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read}},
  [H_INFO_VAL]   = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_info_uuid, ESP_GATT_PERM_READ, sizeof(hid_info_val), sizeof(hid_info_val), (uint8_t *)hid_info_val}},
  [H_CTRL_CHAR]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_write_nr}},
  [H_CTRL_VAL]   = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_ctrl_uuid, ESP_GATT_PERM_WRITE, 1, 1, hid_ctrl_val}},
  [H_PROTO_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_write_nr}},
  [H_PROTO_VAL]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_proto_uuid, RW, 1, 1, hid_proto_val}},
  [H_MAP_CHAR]   = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read}},
  [H_MAP_VAL]    = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_report_map_uuid, ENC_R, sizeof(hid_report_map), sizeof(hid_report_map), (uint8_t *)hid_report_map}},
  [H_RPT_CHAR]   = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_notify}},
  [H_RPT_VAL]    = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&hid_report_uuid, ENC_R, sizeof(hid_report_val), sizeof(hid_report_val), hid_report_val}},
  [H_RPT_CCCD]   = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&cccd_uuid, RW, 2, 2, hid_report_cccd}},
  [H_RPT_REF]    = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&rpt_ref_uuid, ESP_GATT_PERM_READ, sizeof(hid_report_ref), sizeof(hid_report_ref), (uint8_t *)hid_report_ref}},
};

enum { C_SVC, C_CMD_CHAR, C_CMD_VAL, C_RESP_CHAR, C_RESP_VAL, C_RESP_CCCD, C_NB };
static const esp_gatts_attr_db_t db_cust[C_NB] = {
  [C_SVC]       = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ, sizeof(UUID_SVC), sizeof(UUID_SVC), (uint8_t *)UUID_SVC}},
  [C_CMD_CHAR]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_write}},
  [C_CMD_VAL]   = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_128, (uint8_t *)UUID_CMD, ENC_W, 64, 0, NULL}},
  [C_RESP_CHAR] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ, 1, 1, (uint8_t *)&prop_read_notify}},
  [C_RESP_VAL]  = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_128, (uint8_t *)UUID_RESP, ENC_R, 64, sizeof(resp_val), resp_val}},
  [C_RESP_CCCD] = {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&cccd_uuid, RW, 2, 2, cccd_val}},
};

// Handles we need after creation.
static uint16_t h_cmd_val, h_resp_val, h_resp_cccd;

static esp_gatt_if_t s_gatts_if = ESP_GATT_IF_NONE;
static uint16_t s_conn_id;
static bool s_connected;
static bool s_notify_enabled;
static int s_stage;  // which service table is being created

// Advertise flags + name + keyboard appearance + the HID service UUID so macOS
// lists it as a keyboard. Bluedroid requires service UUIDs in 128-bit form
// (service_uuid_len must be a multiple of 16) and compresses SIG-base UUIDs to
// 16-bit in the actual packet — a 2-byte UUID here makes config_adv_data fail
// with INVALID_ARG and advertising never starts.
static const uint8_t hid_adv_uuid128[16] = {
  0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
  0x00, 0x10, 0x00, 0x00, 0x12, 0x18, 0x00, 0x00};
static esp_ble_adv_data_t adv_data = {
  .set_scan_rsp = false, .include_name = true, .include_txpower = false,
  .appearance = APPEARANCE_KEYBOARD,
  .service_uuid_len = sizeof(hid_adv_uuid128),
  .p_service_uuid = (uint8_t *)hid_adv_uuid128,
  .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};
static esp_ble_adv_params_t adv_params = {
  .adv_int_min = 0x20, .adv_int_max = 0x40, .adv_type = ADV_TYPE_IND,
  .own_addr_type = BLE_ADDR_TYPE_PUBLIC, .channel_map = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

void imk_service_respond(const uint8_t *data, size_t len) {
  if (!s_connected || !s_notify_enabled || s_gatts_if == ESP_GATT_IF_NONE) return;
  esp_ble_gatts_send_indicate(s_gatts_if, s_conn_id, h_resp_val, len, (uint8_t *)data, false);
}

bool imk_service_connected(void) { return s_connected; }

static void create_next_table(esp_gatt_if_t gatts_if) {
  switch (s_stage) {
    case 0: esp_ble_gatts_create_attr_tab(db_dev, gatts_if, D_NB, 0); break;
    case 1: esp_ble_gatts_create_attr_tab(db_bat, gatts_if, B_NB, 1); break;
    case 2: esp_ble_gatts_create_attr_tab(db_hid, gatts_if, H_NB, 2); break;
    case 3: esp_ble_gatts_create_attr_tab(db_cust, gatts_if, C_NB, 3); break;
    default: break;
  }
}

static void gap_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  switch (event) {
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
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
      esp_err_t adv_rc = esp_ble_gap_config_adv_data(&adv_data);
      if (adv_rc != ESP_OK) ESP_LOGE(TAG, "config_adv_data failed: %s", esp_err_to_name(adv_rc));
      s_stage = 0;
      create_next_table(gatts_if);
      break;
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      if (param->add_attr_tab.status != ESP_GATT_OK) {
        ESP_LOGE(TAG, "attr table %d failed: status=%d", s_stage, param->add_attr_tab.status);
        break;
      }
      const uint16_t *h = param->add_attr_tab.handles;
      switch (s_stage) {
        case 0: esp_ble_gatts_start_service(h[D_SVC]); break;
        case 1: esp_ble_gatts_start_service(h[B_SVC]); break;
        case 2: esp_ble_gatts_start_service(h[H_SVC]); break;
        case 3:
          h_cmd_val = h[C_CMD_VAL]; h_resp_val = h[C_RESP_VAL]; h_resp_cccd = h[C_RESP_CCCD];
          esp_ble_gatts_start_service(h[C_SVC]);
          ESP_LOGI(TAG, "all services started");
          break;
      }
      if (s_stage < 3) { s_stage++; create_next_table(gatts_if); }
      break;
    }
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
      if (param->write.handle == h_cmd_val) {
        imk_proto_handle(param->write.value, param->write.len);
      } else if (param->write.handle == h_resp_cccd && param->write.len == 2) {
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
