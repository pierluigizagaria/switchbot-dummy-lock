#include "lock_linker.h"

#include <utility>
#include <vector>

#include "esphome/core/log.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.linker";

// Friendly step labels — kept short so the UI's progress card stays tidy.
enum LockLinkStep : uint8_t {
  STEP_CONNECT = 0,
  STEP_DISCOVER,
  STEP_SESSION,
  STEP_OPEN_SLOT,
  STEP_WRITE_KEY_1,
  STEP_WRITE_KEY_2,
  STEP_VERIFY_SHARED_KEY,
};

constexpr const char *STEP_LABELS[] = {
    "Connecting to lock",
    "Discovering services",
    "Negotiating provisioning session",
    "Opening lock slot",
    "Writing shared key (1/2)",
    "Writing shared key (2/2)",
    "Verifying shared key",
};
constexpr uint8_t STEP_COUNT = sizeof(STEP_LABELS) / sizeof(STEP_LABELS[0]);

constexpr uint8_t SHARED_SLOT_ORIGINAL = 0x88;
constexpr uint8_t SHARED_SLOT_VISION   = 0xC6;

uint8_t slot_nonce(uint8_t slot_id) {
  return slot_id == SHARED_SLOT_VISION ? 0x80 : 0x69;
}

std::vector<std::vector<uint8_t>> make_provision_commands(
    uint8_t slot_id, const std::array<uint8_t, 16> &shared_key) {
  return {
      {0x0F, 0x20, 0x09, slot_id},
      {0x0F, 0x20, 0x03, slot_id, slot_nonce(slot_id)},
      {0x0F, 0x20, 0x04, slot_id, 0x00,
       shared_key[0], shared_key[1], shared_key[2], shared_key[3],
       shared_key[4], shared_key[5], shared_key[6], shared_key[7]},
      {0x0F, 0x20, 0x04, slot_id, 0x01,
       shared_key[8], shared_key[9], shared_key[10], shared_key[11],
       shared_key[12], shared_key[13], shared_key[14], shared_key[15]},
  };
}

bool provision_responses_plausible(
    uint8_t slot_id, const std::vector<std::vector<uint8_t>> &responses) {
  if (responses.size() != 4) {
    return false;
  }
  if (!responses[0].empty() &&
      !(responses[0].size() == 1 && responses[0][0] == slot_id)) {
    return false;
  }
  if (responses[1].size() != 2 || responses[1][0] != slot_id ||
      responses[1][1] != slot_nonce(slot_id)) {
    return false;
  }
  return responses[2].size() == 1 && responses[2][0] == slot_id &&
         responses[3].size() == 1 && responses[3][0] == slot_id;
}

}  // namespace

uint8_t LockLinker::step_count() { return STEP_COUNT; }

const char *LockLinker::step_label(uint8_t step) {
  return step < STEP_COUNT ? STEP_LABELS[step] : "";
}

std::string LockLinker::start(Request req) {
  return this->start_job_(this, std::move(req), 'l', "lock-link", STEP_COUNT,
                          STEP_LABELS[0], "Could not start lock-link task",
                          TAG, "Lock link", nullptr, [this](Request &) {
                            this->status_name_.clear();
                            this->status_mac_.clear();
                            this->status_model_ = PhysicalLockModel::UNKNOWN;
                            this->status_slot_id_ = 0;
                          });
}

LockLinker::Status LockLinker::status() const {
  std::lock_guard<std::mutex> lk(this->mu_);
  Status out;
  this->copy_status_base_(out);
  out.name = this->status_name_;
  out.mac = this->status_mac_;
  out.model = this->status_model_;
  out.slot_id = this->status_slot_id_;
  return out;
}

// ── Status helpers ────────────────────────────────────────────────────────

void LockLinker::set_step_(uint8_t step) {
  if (step >= STEP_COUNT) return;
  this->mark_step_(step, STEP_LABELS[step], TAG);
}

void LockLinker::set_success_(const Request &req) {
  ESP_LOGI(TAG, "Shared key verified for '%s' (%s, slot=0x%02X)",
           req.name.c_str(), req.mac.c_str(), this->status_slot_id_);
  std::lock_guard<std::mutex> lk(this->mu_);
  this->status_.state   = State::SUCCESS;
  this->status_.step    = this->status_.total;
  this->status_.message = "Lock linked";
  this->status_.error.clear();
  this->status_name_ = req.name;
  this->status_mac_ = req.mac;
  this->status_model_ = req.model;
}

void LockLinker::set_failed_(const std::string &err) {
  this->mark_failed_(err, TAG, "Lock link");
}

// ── Task body ─────────────────────────────────────────────────────────────

void LockLinker::execute_(Request &req) {
  std::string err;
  const uint8_t slot = req.shared_slot_id != 0 ? req.shared_slot_id : SHARED_SLOT_ORIGINAL;

  PhysicalLockClient::Config provisioning_cfg;
  provisioning_cfg.mac    = req.mac;
  provisioning_cfg.model  = req.model;
  provisioning_cfg.key_id = req.lock_key_id;
  provisioning_cfg.key    = req.lock_key;

  PhysicalLockClient::Config shared_cfg;
  shared_cfg.mac    = req.mac;
  shared_cfg.model  = req.model;
  shared_cfg.key_id = slot;
  shared_cfg.key    = req.shared_key;

  auto provision_phase = [this](PhysicalLockClient::Phase phase) {
    switch (phase) {
      case PhysicalLockClient::Phase::CONNECT:
        this->set_step_(STEP_CONNECT);
        break;
      case PhysicalLockClient::Phase::DISCOVER:
        this->set_step_(STEP_DISCOVER);
        break;
      case PhysicalLockClient::Phase::SESSION:
        this->set_step_(STEP_SESSION);
        break;
      case PhysicalLockClient::Phase::SCAN:
      case PhysicalLockClient::Phase::COMMAND:
        break;
    }
  };
  auto provision_command = [this](size_t command_index) {
    if (command_index < 2) {
      this->set_step_(STEP_OPEN_SLOT);
    } else if (command_index == 2) {
      this->set_step_(STEP_WRITE_KEY_1);
    } else if (command_index == 3) {
      this->set_step_(STEP_WRITE_KEY_2);
    }
  };
  auto verify_phase = [this](PhysicalLockClient::Phase phase) {
    switch (phase) {
      case PhysicalLockClient::Phase::COMMAND:
        this->set_step_(STEP_VERIFY_SHARED_KEY);
        break;
      case PhysicalLockClient::Phase::SCAN:
      case PhysicalLockClient::Phase::CONNECT:
      case PhysicalLockClient::Phase::DISCOVER:
      case PhysicalLockClient::Phase::SESSION:
        break;
    }
  };

  std::vector<std::vector<uint8_t>> provision_responses;
  const std::vector<std::vector<uint8_t>> provision_commands =
      make_provision_commands(slot, req.shared_key);
  if (!this->client_.provision_and_verify_shared_key(
          provisioning_cfg, provision_commands, provision_responses,
          shared_cfg, err, provision_phase, provision_command, verify_phase)) {
    this->set_failed_("Could not link the lock shared key: " + err);
    return;
  }
  if (!provision_responses_plausible(slot, provision_responses)) {
    this->set_failed_("The lock returned an unexpected shared-key provisioning response.");
    return;
  }

  {
    std::lock_guard<std::mutex> lk(this->mu_);
    this->status_slot_id_ = slot;
  }
  this->set_success_(req);
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
