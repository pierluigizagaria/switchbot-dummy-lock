#include "lock_advert.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

int valid_percent(uint8_t raw) {
  const int value = raw & 0x7F;
  return value <= 100 ? value : -1;
}

}  // namespace

int parse_lock_battery(PhysicalLockModel model,
                       const uint8_t *service_data, size_t service_len,
                       const uint8_t *manufacturer_payload,
                       size_t manufacturer_len) {
  switch (model) {
    case PhysicalLockModel::LOCK:
    case PhysicalLockModel::LOCK_LITE:
    case PhysicalLockModel::LOCK_VISION:
      if (service_data == nullptr || service_len < 3) return -1;
      return valid_percent(service_data[2]);

    case PhysicalLockModel::LOCK_PRO:
    case PhysicalLockModel::LOCK_PRO_WIFI:
    case PhysicalLockModel::LOCK_ULTRA:
    case PhysicalLockModel::LOCK_VISION_PRO:
      if (manufacturer_payload == nullptr || manufacturer_len < 10) return -1;
      return valid_percent(manufacturer_payload[9]);

    default:
      return -1;
  }
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
