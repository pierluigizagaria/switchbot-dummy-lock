#pragma once

// SwitchBot cloud client.
//
// Makes four HTTPS calls:
//
//   POST  account.api.switchbot.net /account/api/v1/user/login
//   POST  account.api.switchbot.net /account/api/v1/user/userinfo
//   POST  wonderlabs.<region>.api.switchbot.net /wonder/device/v3/getdevice
//   POST  wonderlabs.<region>.api.switchbot.net /wonder/keys/v1/communicate
//
// The four endpoints together give us:
//   - an account-wide bearer token
//   - the user's home region ("us" / "eu" / ...)
//   - the account device list (keypad detection happens later, over BLE)
//   - the keypad's current `communicationKey` (the cloud-issued key the
//     keypad uses to talk to its currently linked lock)
//
// The last one is what we re-encrypt the BLE pairing commands with —
// the cloud client is the entry point of the on-device setup wizard.

#include <cstdint>
#include <string>
#include <vector>

namespace esphome {
namespace switchbot_keypad_bridge {

class CloudClient {
 public:
  // Plain-data view of one account device as returned by
  // /wonder/device/v3/getdevice. Whether a device is a keypad — and which
  // family it speaks — is decided by the setup UI / pairer from its live
  // BLE advertisement (keypad_advert.h); the cloud only supplies identity
  // (MAC, name) and, later, the communication key.
  struct AccountDevice {
    std::string mac;          // hex, no separators: "B0E9FE612E75"
    std::string mac_pretty;   // "B0:E9:FE:61:2E:75"
    std::string name;         // user-set, e.g. "Keypad Vision 75"
    std::string device_type;  // cloud SKU, e.g. "WoLock" / "WoLockPro"
  };

  // Authenticate against the SwitchBot account API. Captures the bearer
  // token and the user's home region. Returns true on success; on
  // failure writes a human-readable error into `error_out`.
  bool login(const std::string &email, const std::string &password,
             std::string &error_out);

  // Returns the user's SwitchBot account devices that carry a MAC (keypad
  // candidates). The caller decides which are really keypads by checking each
  // one's live BLE advertisement (keypad_advert.h). Successive calls are
  // cached — pass `force_refresh = true` to bypass.
  bool list_devices(std::vector<AccountDevice> &out_devices,
                    std::string &error_out, bool force_refresh = false);

  // Look up a device communication key. `mac` may be in pretty
  // (`B0:E9:FE:...`) or compact (`B0E9FE...`) form.
  // `key_id_hex` receives the hex string (e.g. "88" or "C6"),
  // `key_bytes` receives the 16-byte AES key.
  bool fetch_device_key(const std::string &mac, std::string &key_id_hex,
                        std::vector<uint8_t> &key_bytes,
                        std::string &error_out);

  bool is_logged_in() const { return !this->auth_token_.empty(); }
  const std::string &region() const { return this->region_; }
  void clear() {
    this->auth_token_.clear();
    this->region_.clear();
    this->devices_cache_.clear();
  }

 private:
  // Build the per-region wonderlabs base URL.
  std::string wonderlabs_base_() const;

  // POST `body` to `url`. If `bearer` is non-empty, sends the SwitchBot
  // `authorization` header. On HTTP-level success (2xx with parseable
  // body) returns true and writes the raw response body into `out`.
  bool post_json_(const std::string &url, const std::string &body,
                  const std::string &bearer, std::string &out,
                  std::string &error_out);

  std::string auth_token_;
  std::string region_;
  std::vector<AccountDevice> devices_cache_;
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
