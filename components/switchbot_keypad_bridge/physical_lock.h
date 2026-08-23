#pragma once

#include "nimble_compat.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace esphome {
namespace switchbot_keypad_bridge {

enum class PhysicalLockModel : uint8_t {
  UNKNOWN = 0,
  LOCK,
  LOCK_LITE,
  LOCK_PRO,
  LOCK_ULTRA,
  LOCK_VISION,
  LOCK_VISION_PRO,
  LOCK_PRO_WIFI,
};

const char *physical_lock_model_str(PhysicalLockModel model);
PhysicalLockModel physical_lock_model_from_api_type(const std::string &device_type);
bool is_supported_physical_lock_type(const std::string &device_type);

class PhysicalLockClient {
 public:
  struct Config {
    std::string mac;
    PhysicalLockModel model{PhysicalLockModel::UNKNOWN};
    uint8_t key_id{0};
    std::array<uint8_t, 16> key{};
    // Keep the disconnected NimBLE client and its discovered GATT database
    // between relay calls. This avoids repeating service discovery without
    // keeping the physical lock connected (and therefore awake) while idle.
    bool reuse_gatt_cache{false};
    // Runtime relay only: request a shorter connection interval and use GATT
    // writes without response, matching pySwitchbot's command path. Pairing
    // and key provisioning keep their conservative acknowledged writes.
    bool low_latency_io{false};
  };

  // Coarse progress of one encrypted exchange, reported through the optional
  // callback below. Callers map these phases to their own user-facing steps.
  enum class Phase : uint8_t {
    SCAN = 0,
    CONNECT,
    DISCOVER,
    SESSION,
    COMMAND,
  };
  using ProgressCallback = std::function<void(Phase)>;
  using CommandProgressCallback = std::function<void(size_t command_index)>;
  using ResponseCallback = std::function<void(const std::vector<uint8_t> &response)>;

  // Verify that the configured key/slot can open an encrypted BLE session and
  // return a plausible lock-info payload.
  bool verify(const Config &config, std::string &error_out,
              const ProgressCallback &progress = nullptr);

  // Send one SwitchBot plaintext command body (the bytes after the leading
  // 0x57 command marker) to the physical lock and return the decrypted notify
  // payload from the lock. The caller provides the key/slot for this session.
  bool send_plaintext(const Config &config, const uint8_t *plaintext,
                      size_t plaintext_len, std::vector<uint8_t> &response_plaintext,
                      std::string &error_out,
                      const ProgressCallback &progress = nullptr,
                      const ResponseCallback &response_callback = nullptr);

  // Send a short provisioning sequence over one encrypted session. This
  // mirrors the official keypad/lock binding flow where several 0F 20 ...
  // writes share the same IV.
  bool send_plaintext_sequence(const Config &config,
                               const std::vector<std::vector<uint8_t>> &commands,
                               std::vector<std::vector<uint8_t>> &responses,
                               std::string &error_out,
                               const ProgressCallback &progress = nullptr,
                               const ResponseCallback &response_callback = nullptr);

  // Open the BLE/GATT path without starting an encryption session. The bridge
  // calls this only after a keypad wakes up, so lock connection latency can
  // overlap keypad authentication without holding the lock awake while idle.
  bool preconnect(const Config &config, std::string &error_out,
                  const ProgressCallback &progress = nullptr);

  // Close a connection left open by preconnect(). The disconnected client and
  // discovered GATT database remain cached when reuse_gatt_cache is enabled.
  void disconnect_preconnected();

  // Provision the keypad/lock shared key with the lock's cloud credential,
  // then verify the freshly-written shared slot on the same BLE connection.
  bool provision_and_verify_shared_key(
      const Config &provisioning_config,
      const std::vector<std::vector<uint8_t>> &provision_commands,
      std::vector<std::vector<uint8_t>> &provision_responses,
      const Config &shared_config,
      std::string &error_out,
      const ProgressCallback &provision_progress = nullptr,
      const CommandProgressCallback &provision_command_progress = nullptr,
      const ProgressCallback &verify_progress = nullptr);

  // Drop any retained disconnected client/GATT database. Call this when the
  // linked lock changes or pairing is reset so stale handles are never reused
  // for another device.
  void clear_connection_cache();

 private:
  enum class CryptoMode : uint8_t { CTR, GCM };

  struct Session {
    CryptoMode mode{CryptoMode::CTR};
    std::array<uint8_t, 16> ctr_iv{};
    std::array<uint8_t, 12> gcm_iv{};
  };

  bool connect_(const Config &config, NimBLEClient *&client,
                NimBLERemoteCharacteristic *&rx,
                NimBLERemoteCharacteristic *&tx,
                std::string &error_out,
                const ProgressCallback &progress);
  void release_connection_(const Config &config, NimBLEClient *client);
  bool parse_session_response_(const std::string &wire, Session &session,
                               std::string &error_out);
  bool send_encrypted_(const Config &config, const Session &session,
                       NimBLERemoteCharacteristic *rx, const uint8_t *plaintext,
                       size_t plaintext_len, std::string &error_out);
  bool decrypt_notify_(const Config &config, const Session &session,
                       const std::string &wire, std::vector<uint8_t> &out,
                       std::string &error_out);

  // Last advertisement address seen for cached_mac_, including its BLE
  // address type. Lets follow-up connects skip the ~2.5 s discovery scan —
  // the dominant cost of a relay round-trip. Invalidated when a connect
  // through it fails (the next attempt re-scans).
  NimBLEAddress cached_addr_{};
  std::string   cached_mac_;

  // A disconnected NimBLE client retains the peer's discovered services and
  // characteristic handles. Reconnecting it with deleteAttributes=false is
  // substantially faster than creating and discovering a fresh client, while
  // drawing no connection-event power between commands.
  NimBLEClient *cached_client_{nullptr};
  std::string   cached_client_mac_;
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
