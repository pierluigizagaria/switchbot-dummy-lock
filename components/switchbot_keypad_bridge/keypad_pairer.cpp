#include "keypad_pairer.h"

#include <host/ble_gap.h>

#include <cstring>
#include <utility>

#include "esphome/core/log.h"
#include "aes_ctr.h"
#include "ble_utils.h"
#include "keypad_advert.h"
#include "mac_utils.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.pairer";

// Per-family pairing dialect: the BLE handshake constants that differ
// between the Original and Vision keypad families.
struct FamilyPreset {
  uint8_t shared_slot;
  uint8_t slot_init_nonce;
  const uint8_t *enter_pairing;
  size_t enter_pairing_len;
  const uint8_t *capabilities_probe;  // may be nullptr
  size_t capabilities_probe_len;
  const uint8_t *finalize_tail;
  size_t finalize_tail_len;
  const uint8_t *enable_doorbell;     // may be nullptr (Vision-only feature)
  size_t enable_doorbell_len;
};

constexpr uint8_t ORIGINAL_ENTER_PAIRING[]   = {0x0f, 0x52, 0x01, 0x07, 0x00};
constexpr uint8_t ORIGINAL_FINALIZE_TAIL[]   = {0x00, 0x08, 0x09, 0x04, 0x05, 0x07};

constexpr uint8_t VISION_ENTER_PAIRING[]     = {0x0f, 0x53, 0x01, 0x07};
constexpr uint8_t VISION_CAPABILITIES_PROBE[]= {0x0f, 0x53, 0x07, 0x03};
constexpr uint8_t VISION_FINALIZE_TAIL[]     = {0x04, 0x04, 0x01, 0x05, 0x08, 0x09};

// Doorbell-enable setting toggle (byte[4] = 0x02 enable / 0x01 disable),
// captured from the official app. Vision-family only.
constexpr uint8_t VISION_ENABLE_DOORBELL[]   = {0x0f, 0x52, 0x01, 0x09, 0x02, 0x01, 0x01};

constexpr FamilyPreset ORIGINAL_PRESET = {
    0x88, 0x69,
    ORIGINAL_ENTER_PAIRING,    sizeof(ORIGINAL_ENTER_PAIRING),
    nullptr,                   0,
    ORIGINAL_FINALIZE_TAIL,    sizeof(ORIGINAL_FINALIZE_TAIL),
    nullptr,                   0,
};
constexpr FamilyPreset VISION_PRESET = {
    0xC6, 0x80,
    VISION_ENTER_PAIRING,      sizeof(VISION_ENTER_PAIRING),
    VISION_CAPABILITIES_PROBE, sizeof(VISION_CAPABILITIES_PROBE),
    VISION_FINALIZE_TAIL,      sizeof(VISION_FINALIZE_TAIL),
    VISION_ENABLE_DOORBELL,    sizeof(VISION_ENABLE_DOORBELL),
};

const FamilyPreset &preset_for(KeypadFamily f) {
  return f == KeypadFamily::VISION ? VISION_PRESET : ORIGINAL_PRESET;
}

constexpr const char *STEP_LABELS[] = {
    "Connecting to keypad",
    "Discovering services",
    "Negotiating session key",
    "Opening lock slot",
    "Writing shared key (1/2)",
    "Writing shared key (2/2)",
    "Updating lock target",
    "Finalising",
    "Force-enabling doorbell",
};
constexpr uint8_t BASE_STEP_COUNT   = 8;
constexpr uint8_t DOORBELL_STEP     = 8;
constexpr uint8_t VISION_STEP_COUNT = 9;

NimBLEAddress discover_target(const std::string &mac_pretty, uint32_t timeout_ms,
                             KeypadIdent &ident_out) {
  NimBLEScan *scan = NimBLEDevice::getScan();
  configure_switchbot_scan(scan);

  const std::string target = upper_mac(mac_pretty);

  NimBLEScanResults results = scan->getResults(timeout_ms, false);
  for (int i = 0; i < results.getCount(); ++i) {
    const NimBLEAdvertisedDevice *adv = results.getDevice(i);
    if (upper_mac(adv->getAddress().toString()) == target) {
      const std::vector<uint8_t> sd = switchbot_service_data(adv);
      ident_out = identify_keypad(sd.data(), sd.size());
      ESP_LOGI(TAG, "Found keypad %s (addr_type=%d, advert=%s)",
               mac_pretty.c_str(), adv->getAddressType(),
               ident_out.is_keypad ? keypad_family_str(ident_out.family) : "unrecognised");
      return adv->getAddress();
    }
  }
  return NimBLEAddress{};
}

}  // namespace

uint8_t KeypadPairer::step_count(KeypadFamily family) {
  return family == KeypadFamily::VISION ? VISION_STEP_COUNT : BASE_STEP_COUNT;
}

const char *KeypadPairer::step_label(KeypadFamily family, uint8_t step) {
  return step < step_count(family) ? STEP_LABELS[step] : "";
}

std::string KeypadPairer::start(Request req) {
  const uint8_t total = step_count(req.family);
  return this->start_job_(
      this, std::move(req), 'p', "kp-pair", total, STEP_LABELS[0],
      "Could not start keypad-link task", TAG, "Keypad link", &this->task_handle_,
      [this](Request &prepared) {
        this->key_ = prepared.key;
        this->key_id_ = static_cast<uint8_t>(prepared.key_id);
        this->iv_received_ = false;

        if (this->ack_sem_ == nullptr) {
          this->ack_sem_ = xSemaphoreCreateBinary();
        }
        while (xSemaphoreTake(this->ack_sem_, 0) == pdTRUE) { /* drain */ }

        this->status_keypad_mac_.clear();
        this->status_family_ = KeypadFamily::ORIGINAL;
      });
}

KeypadPairer::Status KeypadPairer::status() const {
  std::lock_guard<std::mutex> lk(this->mu_);
  Status out;
  this->copy_status_base_(out);
  out.keypad_mac = this->status_keypad_mac_;
  out.family = this->status_family_;
  return out;
}

void KeypadPairer::set_step_(uint8_t step, const char *msg) {
  this->mark_step_(step, msg, TAG);
}

void KeypadPairer::set_success_(const std::string &keypad_mac,
                                KeypadFamily family) {
  ESP_LOGI(TAG, "Keypad link successful");
  std::lock_guard<std::mutex> lk(this->mu_);
  this->status_.state = State::SUCCESS;
  this->status_.step = this->status_.total;
  this->status_.message = "Keypad linked";
  this->status_.error.clear();
  this->status_keypad_mac_ = keypad_mac;
  this->status_family_ = family;
}

void KeypadPairer::set_failed_(const std::string &err) {
  this->mark_failed_(err, TAG, "Keypad link");
}

void KeypadPairer::on_notify_(const uint8_t *data, size_t length) {
  if (length == 20 && data[0] == 0x01 && data[1] == 0x00) {
    std::memcpy(this->iv_.data(), data + 4, 16);
    this->iv_received_.store(true);
  }
  if (this->ack_sem_ != nullptr) {
    xSemaphoreGive(this->ack_sem_);
  }
}

bool KeypadPairer::send_command_(NimBLERemoteCharacteristic *rx,
                                 const uint8_t *plaintext, size_t plaintext_len) {
  std::vector<uint8_t> frame(4 + plaintext_len);
  frame[0] = 0x57;
  frame[1] = this->key_id_;
  frame[2] = this->iv_[0];
  frame[3] = this->iv_[1];
  if (!aes_ctr_xcrypt_raw_key(this->key_.data(), this->iv_.data(),
                              plaintext, frame.data() + 4, plaintext_len)) {
    return false;
  }

  while (xSemaphoreTake(this->ack_sem_, 0) == pdTRUE) { /* drain */ }
  if (!rx->writeValue(frame.data(), frame.size(), /*response=*/true)) {
    return false;
  }
  xSemaphoreTake(this->ack_sem_, pdMS_TO_TICKS(800));
  return true;
}

void KeypadPairer::execute_(Request &req) {
  this->set_step_(0, STEP_LABELS[0]);
  KeypadIdent ident;
  NimBLEAddress target = discover_target(req.keypad_mac, 6000, ident);
  if (target.isNull()) {
    this->set_failed_("Could not see the keypad over BLE. Keep it within 2 m and retry.");
    return;
  }

  const KeypadFamily family = req.family;
  ESP_LOGI(TAG, "Linking keypad as %s family", keypad_family_str(family));
  const FamilyPreset &preset = preset_for(family);

  {
    struct ble_gap_conn_desc desc{};
    if (ble_gap_conn_find_by_addr(target.getBase(), &desc) == 0) {
      ESP_LOGI(TAG, "Keypad still connected as peripheral (h=%u), terminating before pair",
               desc.conn_handle);
      ble_gap_terminate(desc.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
      vTaskDelay(pdMS_TO_TICKS(600));
    }
  }

  SwitchbotGattConnection gatt;
  std::string error;
  if (!connect_switchbot_service(target, 10000, "keypad", gatt, error)) {
    this->set_failed_(error);
    return;
  }
  NimBLEClient *client = gatt.client;
  NimBLERemoteCharacteristic *rx = gatt.rx;
  NimBLERemoteCharacteristic *tx = gatt.tx;

  this->set_step_(1, STEP_LABELS[1]);
  tx->subscribe(true,
                [this](NimBLERemoteCharacteristic *, uint8_t *data,
                       size_t length, bool /*is_notify*/) {
                  this->on_notify_(data, length);
                });

  this->set_step_(2, STEP_LABELS[2]);
  while (xSemaphoreTake(this->ack_sem_, 0) == pdTRUE) { /* drain */ }
  uint8_t iv_req[8] = {0x57, 0x00, 0x00, 0x00, 0x0F, 0x21, 0x03,
                       this->key_id_};
  if (!rx->writeValue(iv_req, sizeof(iv_req), /*response=*/true)) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("Could not request session IV from keypad.");
    return;
  }
  for (int i = 0; i < 6 && !this->iv_received_.load(); ++i) {
    xSemaphoreTake(this->ack_sem_, pdMS_TO_TICKS(500));
  }
  if (!this->iv_received_.load()) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("Keypad did not open a session. Reset it into pairing mode and retry.");
    return;
  }

  auto run_step = [&](uint8_t step, const uint8_t *pt, size_t pt_len,
                      const char *err_msg) -> bool {
    this->set_step_(step, STEP_LABELS[step]);
    if (!this->send_command_(rx, pt, pt_len)) {
      client->disconnect();
      NimBLEDevice::deleteClient(client);
      this->set_failed_(err_msg);
      return false;
    }
    return true;
  };

  this->set_step_(3, STEP_LABELS[3]);
  if (!this->send_command_(rx, preset.enter_pairing, preset.enter_pairing_len)) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("enter_pairing rejected.");
    return;
  }
  if (preset.capabilities_probe != nullptr) {
    this->send_command_(rx, preset.capabilities_probe, preset.capabilities_probe_len);
  }
  uint8_t prep[] = {0x06, 0x03};
  this->send_command_(rx, prep, sizeof(prep));
  uint8_t slot_init[] = {0x0F, 0x20, 0x03, preset.shared_slot, preset.slot_init_nonce};
  if (!this->send_command_(rx, slot_init, sizeof(slot_init))) {
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    this->set_failed_("Could not open the keypad's key slot.");
    return;
  }

  uint8_t tok1[5 + 8];
  tok1[0] = 0x0F; tok1[1] = 0x20; tok1[2] = 0x04;
  tok1[3] = preset.shared_slot; tok1[4] = 0x00;
  std::memcpy(tok1 + 5, req.shared_token.data(), 8);
  if (!run_step(4, tok1, sizeof(tok1), "Could not write shared_key (1/2).")) return;

  uint8_t tok2[5 + 8];
  tok2[0] = 0x0F; tok2[1] = 0x20; tok2[2] = 0x04;
  tok2[3] = preset.shared_slot; tok2[4] = 0x01;
  std::memcpy(tok2 + 5, req.shared_token.data() + 8, 8);
  if (!run_step(5, tok2, sizeof(tok2), "Could not write shared_key (2/2).")) return;

  uint8_t mac_payload[3 + 6];
  mac_payload[0] = 0x06; mac_payload[1] = 0x01; mac_payload[2] = preset.shared_slot;
  std::memcpy(mac_payload + 3, req.esp_mac.data(), 6);
  if (!run_step(6, mac_payload, sizeof(mac_payload), "Could not update target lock MAC.")) return;

  this->set_step_(7, STEP_LABELS[7]);
  {
    std::vector<uint8_t> fin = {0x0f, 0x52, 0x02, 0x02, 0x10, 0xFF, 0x05, 0x06};
    fin.insert(fin.end(), preset.finalize_tail,
               preset.finalize_tail + preset.finalize_tail_len);
    this->send_command_(rx, fin.data(), fin.size());
  }
  uint8_t finalize2[] = {0x0f, 0x53, 0x01, 0x06};
  this->send_command_(rx, finalize2, sizeof(finalize2));

  if (preset.enable_doorbell != nullptr) {
    this->set_step_(DOORBELL_STEP, STEP_LABELS[DOORBELL_STEP]);
    this->send_command_(rx, preset.enable_doorbell, preset.enable_doorbell_len);
  }

  client->disconnect();
  NimBLEDevice::deleteClient(client);

  this->set_success_(req.keypad_mac, family);
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
