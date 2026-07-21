#pragma once

// Background task that provisions the bridge's shared keypad/lock key into a
// physical SwitchBot Lock, then verifies that the shared slot answers.
//
// User-facing progress mirrors the keypad pairer style: transport setup first,
// then grouped pairing operations:
//   1. Connect to the lock
//   2. Discover the SwitchBot GATT service
//   3. Negotiate the provisioning session
//   4. Create/open the shared slot
//   5. Write the first shared-key half
//   6. Write the second shared-key half
//   7. Verify the shared slot with a lock-info command
//
// Spawned once per link attempt; the HTTP handler polls `status()` from the
// UI's `/api/lock/link/status`, and the bridge's loop() fires the linked
// callback from the SUCCESS snapshot (browser-independent).

#include <array>
#include <cstdint>
#include <mutex>
#include <string>

#include "background_job.h"
#include "physical_lock.h"

namespace esphome {
namespace switchbot_keypad_bridge {

class LockLinker : private BackgroundBleJob {
 public:
  using State = BackgroundBleJob::State;

  // Snapshot of the linker's progress, safe to copy across threads.
  struct Status : BackgroundBleJob::Status {
    // Identity of the lock just verified, valid only when state == SUCCESS.
    // Carries everything the bridge persists, so the linked callback can be
    // fired from this snapshot alone.
    std::string name;
    std::string mac;           // pretty form, e.g. "B0:E9:FE:..."
    PhysicalLockModel model{PhysicalLockModel::UNKNOWN};
    uint8_t slot_id{0};
  };

  // Arguments for a single link attempt. The lock cloud credential is used
  // only as a bootstrap channel to write the bridge's shared key into the
  // lock. Runtime relay persists and uses only shared_key/shared_slot_id.
  struct Request {
    std::string name;
    std::string mac;           // pretty form, e.g. "B0:E9:FE:..."
    PhysicalLockModel model{PhysicalLockModel::UNKNOWN};
    std::array<uint8_t, 16> shared_key{};
    uint8_t shared_slot_id{0};
    uint8_t lock_key_id{0};
    std::array<uint8_t, 16> lock_key{};
  };

  // Spawns the link task and returns a job id. If a job is already running
  // this returns an empty string and leaves the current job untouched — only
  // one link attempt can be in flight at a time.
  std::string start(Request req);

  // The user-facing label of each step, in order. The wizard builds its
  // progress stepper from these (returned by /api/lock/link), so the linker
  // is the single source of truth for step count, order and wording.
  static uint8_t step_count();
  static const char *step_label(uint8_t step);

  // Atomic snapshot of progress. Suitable for polling from any thread.
  Status status() const;

  // Cheap state-only read (no string copies) — for per-loop polling.
  State state() const { return BackgroundBleJob::state(); }

 private:
  friend class BackgroundBleJob;

  void execute_(Request &req);

  void set_step_(uint8_t step);
  void set_success_(const Request &req);
  void set_failed_(const std::string &err);

  std::string status_name_;
  std::string status_mac_;
  PhysicalLockModel status_model_{PhysicalLockModel::UNKNOWN};
  uint8_t status_slot_id_{0};

  PhysicalLockClient client_{};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
