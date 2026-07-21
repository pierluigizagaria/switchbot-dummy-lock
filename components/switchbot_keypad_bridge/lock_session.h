#pragma once

// Encrypted-session state machine for the emulated SwitchBot Lock: token-slot
// learning, IV negotiation, frame validation, AES-CTR transport crypto and
// anti-replay. Bytes in, decoded commands out — no NimBLE and no ESPHome
// entities, so the entire validation pipeline lives in one reviewable place.
// The bridge owns the transport (BLE notify) and the business logic (lock
// state, entity publishing) on top of it.

#include <psa/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "lock_protocol.h"

namespace esphome {
namespace switchbot_keypad_bridge {

// 4-byte transport header echoed back on every encrypted exchange.
struct FrameHeader {
  uint8_t key_id;
  uint8_t seq_a;
  uint8_t seq_b;
};

class LockSession {
 public:
  static constexpr size_t HEADER_LEN = 4;   // [0x57|0x01, key_id, seq_a, seq_b]
  static constexpr size_t MAX_PAYLOAD = 32;
  static constexpr size_t MAX_PACKET = HEADER_LEN + MAX_PAYLOAD;

  // Outcome of feeding one received frame into the session.
  enum class Action : uint8_t {
    NONE,     // frame dropped — the reason has been logged
    SEND_IV,  // IV request handled: notify iv_response()
    COMMAND,  // decrypted and decoded: header() / command() are valid
  };

  // (Re-)point the session at an imported PSA AES-CTR key. The bridge owns
  // key generation, NVS persistence and PSA import (including reset-pairing
  // rotation); the session only uses the handle.
  void set_aes_key(psa_key_id_t key) { this->aes_key_ = key; }

  // Drop the crypto session state. Used when the shared key changes or the
  // pairing is reset; ordinary BLE reconnects may continue the same SwitchBot
  // session and must keep the IV alive.
  void reset();

  // Clear transient decoded-frame state while preserving the negotiated IV and
  // replay window. Called on BLE connect/disconnect events because some
  // keypads continue the same logical session after a transport reconnect.
  void reset_transport();

  // Forget the learned token slot as well (pairing reset only).
  void forget_slot() { this->slot_id_ = 0x00; }

  // Validate, decrypt and decode one received frame. On COMMAND the decoded
  // result is available via header()/command() until the next call.
  Action process_frame(const std::string &frame);

  // Valid after process_frame() returned COMMAND.
  const FrameHeader &header() const { return this->header_; }
  const DecodedCommand &command() const { return this->command_; }
  const uint8_t *plaintext() const { return this->plaintext_.data(); }
  size_t plaintext_size() const { return this->plaintext_size_; }

  // The 20-byte session-IV response to notify after SEND_IV:
  // [0x01, 0x00, 0x00, 0x00, IV(16)]. The trailing 16 bytes are the pending
  // AES-CTR IV; it becomes active when the first frame using it arrives.
  const uint8_t *iv_response() const { return this->iv_response_.data(); }
  size_t iv_response_size() const { return this->iv_response_.size(); }

  // Encrypt `plaintext` into a notify-ready packet
  // [0x01, key_id, seq_a, seq_b, ciphertext…] written to `out` (which must
  // hold MAX_PACKET bytes). Returns the packet length, 0 on failure (logged).
  size_t encrypt_response(const FrameHeader &header, const uint8_t *plaintext,
                          size_t length, uint8_t out[MAX_PACKET]);

 private:
  static constexpr size_t AES_IV_SIZE = 16;
  static constexpr size_t REPLAY_HISTORY_SIZE = 8;

  bool is_iv_request_(const std::string &frame) const;
  void rotate_pending_iv_();

  // AES-CTR is symmetric, so a single primitive covers both directions.
  bool xcrypt_(const std::array<uint8_t, AES_IV_SIZE> &iv, const uint8_t *input,
               size_t length, uint8_t *output);

  psa_key_id_t aes_key_{PSA_KEY_ID_NULL};

  // Token-slot key_id the keypad uses post-pairing. Auto-learned from the
  // IV-request frame the keypad sends when it starts a logical session
  // (Original/Touch=0x88, Vision/Vision Pro=0xC6, ...). 0x00 = not yet seen;
  // no encrypted frame is accepted until an IV handshake has set it.
  uint8_t slot_id_{0x00};

  struct ReplayEntry {
    std::array<uint8_t, MAX_PAYLOAD> data{};
    size_t length{0};
  };

  // An IV and its replay window form one logical crypto generation. A new IV
  // remains pending until the keypad proves it switched by sending a frame
  // whose seq bytes match it. Keeping the previous generation alive during
  // that hand-off lets us answer an already-in-flight state poll without
  // reopening old lock/unlock actions.
  struct CryptoContext {
    std::array<uint8_t, AES_IV_SIZE> iv{};
    std::array<ReplayEntry, REPLAY_HISTORY_SIZE> replay_history{};
    size_t replay_head{0};
    bool valid{false};
  };

  bool is_replayed_ciphertext_(const CryptoContext &context,
                               const uint8_t *ciphertext, size_t length) const;
  void record_ciphertext_(CryptoContext &context, const uint8_t *ciphertext,
                          size_t length);
  bool seq_matches_(const CryptoContext &context, const FrameHeader &header) const;

  CryptoContext active_{};
  CryptoContext pending_{};

  std::array<uint8_t, 20> iv_response_{0x01, 0x00, 0x00, 0x00};

  // Exact IV used to decrypt the most recent COMMAND. Responses must use the
  // same generation, especially for a late state poll under active_ while a
  // newer pending_ IV has already been advertised.
  std::array<uint8_t, AES_IV_SIZE> response_iv_{};
  bool response_iv_valid_{false};

  FrameHeader header_{};
  DecodedCommand command_{};
  std::array<uint8_t, MAX_PAYLOAD> plaintext_{};
  size_t plaintext_size_{0};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
