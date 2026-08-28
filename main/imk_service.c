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

// 128-bit UUIDs in Bluedroid little-endian byte order (reverse of the written form).
// Service 45529919-7668-48f9-b9fe-e4eabe6595d9
static const uint8_t UUID_SVC[16] = {
  0xd9, 0x95, 0x65, 0xbe, 0xea, 0xe4, 0xfe, 0xb9,
  0xf9, 0x48, 0x68, 0x76, 0x19, 0x99, 0x52, 0x45};
// Command char 8a537e1f-3992-4b2c-8b77-8d4e778186e1
static const uint8_t UUID_CMD[16] = {
  0xe1, 0x86, 0x81, 0x77, 0x4e, 0x8d, 0x77, 0x8b,
  0x2c, 0x4b, 0x92, 0x39, 0x1f, 0x7e, 0x53, 0x8a};
// Response char 76a1660d-8cf6-44d1-b3fc-70486028e289
static const uint8_t UUID_RESP[16] = {
  0x89, 0xe2, 0x28, 0x60, 0x48, 0x70, 0xfc, 0xb3,
  0xd1, 0x44, 0xf6, 0x8c, 0x0d, 0x66, 0xa1, 0x76};

enum { IDX_SVC, IDX_CMD_CHAR, IDX_CMD_VAL, IDX_RESP_CHAR, IDX_RESP_VAL, IDX_RESP_CCCD, IDX_NB };
static uint16_t handle_table[IDX_NB];

static esp_gatt_if_t s_gatts_if = ESP_GATT_IF_NONE;
static uint16_t s_conn_id;
static bool s_connected;
static bool s_notify_enabled;

// Advertising: name + appearance in the advertisement (fits in 31 bytes).
static esp_ble_adv_data_t adv_data = {
  .set_scan_rsp = false,
  .include_name = true,
  .include_txpower = false,
  .appearance = APPEARANCE_KEYBOARD,
  .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};
static esp_ble_adv_params_t adv_params = {
  .adv_int_min = 0x20,
  .adv_int_max = 0x40,
  .adv_type = ADV_TYPE_IND,
  .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
  .channel_map = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

// GATT attribute table.
static const uint16_t primary_service_uuid = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t char_decl_uuid = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t cccd_uuid = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
static const uint8_t prop_write = ESP_GATT_CHAR_PROP_BIT_WRITE;
static const uint8_t prop_notify_read = ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_READ;
static uint8_t cccd_val[2] = {0x00, 0x00};
static uint8_t resp_val[1] = {0x00};

static const esp_gatts_attr_db_t gatt_db[IDX_NB] = {
  [IDX_SVC] = {{ESP_GATT_AUTO_RSP},
    {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ,
     sizeof(UUID_SVC), sizeof(UUID_SVC), (uint8_t *)UUID_SVC}},

  [IDX_CMD_CHAR] = {{ESP_GATT_AUTO_RSP},
    {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ,
     1, 1, (uint8_t *)&prop_write}},
  [IDX_CMD_VAL] = {{ESP_GATT_RSP_BY_APP},
    {ESP_UUID_LEN_128, (uint8_t *)UUID_CMD, ESP_GATT_PERM_WRITE_ENCRYPTED,
     64, 0, NULL}},

  [IDX_RESP_CHAR] = {{ESP_GATT_AUTO_RSP},
    {ESP_UUID_LEN_16, (uint8_t *)&char_decl_uuid, ESP_GATT_PERM_READ,
     1, 1, (uint8_t *)&prop_notify_read}},
  [IDX_RESP_VAL] = {{ESP_GATT_AUTO_RSP},
    {ESP_UUID_LEN_128, (uint8_t *)UUID_RESP, ESP_GATT_PERM_READ_ENCRYPTED,
     64, sizeof(resp_val), resp_val}},
  [IDX_RESP_CCCD] = {{ESP_GATT_AUTO_RSP},
    {ESP_UUID_LEN_16, (uint8_t *)&cccd_uuid,
     ESP_GATT_PERM_READ_ENCRYPTED | ESP_GATT_PERM_WRITE_ENCRYPTED,
     sizeof(cccd_val), sizeof(cccd_val), cccd_val}},
};

void imk_service_respond(const uint8_t *data, size_t len) {
  if (!s_connected || !s_notify_enabled || s_gatts_if == ESP_GATT_IF_NONE) return;
  esp_ble_gatts_send_indicate(s_gatts_if, s_conn_id, handle_table[IDX_RESP_VAL],
                              len, (uint8_t *)data, false);  // false = notify
}

bool imk_service_connected(void) { return s_connected; }

static void gap_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  switch (event) {
    case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
      esp_ble_gap_start_advertising(&adv_params);
      break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
      if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS)
        ESP_LOGE(TAG, "adv start failed");
      else
        ESP_LOGI(TAG, "advertising as %s", DEVICE_NAME);
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
      if (param->add_attr_tab.status == ESP_GATT_OK &&
          param->add_attr_tab.num_handle == IDX_NB) {
        memcpy(handle_table, param->add_attr_tab.handles, sizeof(handle_table));
        esp_ble_gatts_start_service(handle_table[IDX_SVC]);
      } else {
        ESP_LOGE(TAG, "attr table create failed");
      }
      break;
    case ESP_GATTS_CONNECT_EVT: {
      s_conn_id = param->connect.conn_id;
      s_connected = true;
      // immurok connection parameters (30ms/50ms, latency 29, 6s supervision).
      esp_ble_conn_update_params_t cp = {
        .min_int = 24, .max_int = 40, .latency = 29, .timeout = 600,
      };
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
        ESP_LOGI(TAG, "notifications %s", s_notify_enabled ? "on" : "off");
      }
      if (param->write.need_rsp) {
        esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id,
                                    ESP_GATT_OK, NULL);
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

  // Just Works bonding: Secure Connections + bond, no MITM, no IO.
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

  esp_ble_gatt_set_local_mtu(64 + 3);
  ESP_ERROR_CHECK(esp_ble_gatts_app_register(0));
  ESP_LOGI(TAG, "BLE service starting");
}
