#include "ble_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

std::vector<uint8_t> switchbot_service_data(const NimBLEAdvertisedDevice *adv) {
  static const NimBLEUUID U_FD3D(static_cast<uint16_t>(0xFD3D));
  static const NimBLEUUID U_0D00(static_cast<uint16_t>(0x0D00));
  std::string sd = adv->getServiceData(U_FD3D);
  if (sd.empty()) sd = adv->getServiceData(U_0D00);
  return std::vector<uint8_t>(sd.begin(), sd.end());
}

std::vector<uint8_t> switchbot_manufacturer_payload(const NimBLEAdvertisedDevice *adv) {
  if (!adv->haveManufacturerData()) {
    return {};
  }
  const std::string mfr = adv->getManufacturerData();
  if (mfr.size() < 2) {
    return {};
  }
  const auto *data = reinterpret_cast<const uint8_t *>(mfr.data());
  if (data[0] != 0x69 || data[1] != 0x09) {
    return {};
  }
  return std::vector<uint8_t>(data + 2, data + mfr.size());
}

std::array<uint8_t, 6> addr_bytes(const NimBLEAddress &addr) {
  std::array<uint8_t, 6> out{};
  const uint8_t *raw = addr.getBase()->val;  // little-endian
  for (size_t i = 0; i < 6; ++i) {
    out[i] = raw[5 - i];
  }
  return out;
}

void configure_switchbot_scan(NimBLEScan *scan) {
  scan->clearResults();
  scan->setActiveScan(true);
  scan->setInterval(45);
  scan->setWindow(30);
}

bool connect_switchbot_service(const NimBLEAddress &target, uint32_t timeout_ms,
                               const char *device_label,
                               SwitchbotGattConnection &conn,
                               std::string &error_out) {
  conn = SwitchbotGattConnection{};
  conn.client = NimBLEDevice::createClient();
  if (conn.client == nullptr) {
    error_out = "Could not allocate a BLE client for the ";
    error_out += device_label;
    error_out += ".";
    return false;
  }

  conn.client->setConnectTimeout(timeout_ms);
  if (!conn.client->connect(target)) {
    NimBLEDevice::deleteClient(conn.client);
    conn.client = nullptr;
    error_out = "Could not connect to the ";
    error_out += device_label;
    error_out += ".";
    return false;
  }

  NimBLERemoteService *svc =
      conn.client->getService(NimBLEUUID(SWITCHBOT_SERVICE_UUID));
  if (svc != nullptr) {
    conn.rx = svc->getCharacteristic(NimBLEUUID(SWITCHBOT_RX_CHAR_UUID));
    conn.tx = svc->getCharacteristic(NimBLEUUID(SWITCHBOT_TX_CHAR_UUID));
  }
  if (conn.rx == nullptr || conn.tx == nullptr) {
    conn.client->disconnect();
    NimBLEDevice::deleteClient(conn.client);
    conn = SwitchbotGattConnection{};
    error_out = "The ";
    error_out += device_label;
    error_out += " does not expose the SwitchBot GATT service.";
    return false;
  }
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
