#include "lock_session.h"

#include <cstring>

#include <esp_random.h>

#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "aes_ctr.h"

namespace esphome {
namespace switchbot_keypad_bridge {

namespace {

const char *const TAG = "switchbot_keypad_bridge.session";

// Encrypted protocol framing.
constexpr uint8_t PROTOCOL_MAGIC = 0x57;

// Session IV negotiation. Most keypads send this after connect; some reconnect
// and continue with the IV they already have.
// Shape: 57 00 00 00 0F 21 03 <key_id>
constexpr size_t SESSION_IV_REQ_MIN = 8;

constexpr size_t IV_RESPONSE_HEADER = 4;  // iv_response_ prefix before the IV bytes

}  // namespace

void LockSession::reset() {
  this->active_ = CryptoContext{};
  this->pending_ = CryptoContext{};
  this->reset_transport();
}

void LockSession::reset_transport() {
  this->plaintext_size_ = 0;
  this->header_ = FrameHeader{};
  this->command_ = DecodedCommand{};
  this->response_iv_valid_ = false;
}

LockSession::Action LockSession::process_frame(const std::string &frame) {
  // Never expose stale decoded bytes or a stale response IV after a dropped
  // frame. The bridge may relay plaintext asynchronously after COMMAND.
  this->reset_transport();

  ESP_LOGV(TAG, "RX WIRE %zu bytes: %s", frame.size(),
           format_hex_pretty(reinterpret_cast<const uint8_t *>(frame.data()), frame.size()).c_str());

  if (this->is_iv_request_(frame)) {
    // The IV request advertises which key_id the keypad will use for the
    // rest of the session (`57 00 00 00 0F 21 03 <key_id>`). Adapt to it —
    // Original/Touch uses 0x88, Vision/Vision Pro uses 0xC6.
    const uint8_t requested_slot = static_cast<uint8_t>(frame[7]);
    if (requested_slot != this->slot_id_) {
      ESP_LOGI(TAG, "Token slot: 0x%02X", requested_slot);
      this->slot_id_ = requested_slot;
    }
    ESP_LOGD(TAG, "IV request");
    // Do not overwrite active_ yet. Vision-family keypads can send a delayed
    // state poll from the previous generation after requesting the next IV.
    this->rotate_pending_iv_();
    return Action::SEND_IV;
  }

  if (frame.size() <= HEADER_LEN ||
      static_cast<uint8_t>(frame[0]) != PROTOCOL_MAGIC) {
    ESP_LOGD(TAG, "Ignoring non-protocol frame (size=%zu)", frame.size());
    return Action::NONE;
  }

  this->header_ = FrameHeader{static_cast<uint8_t>(frame[1]), static_cast<uint8_t>(frame[2]),
                              static_cast<uint8_t>(frame[3])};

  if (this->header_.key_id != this->slot_id_) {
    ESP_LOGD(TAG, "Ignoring frame with unexpected key_id=0x%02X", this->header_.key_id);
    return Action::NONE;
  }

  // Refuse encrypted frames before any IV has been negotiated for this key.
  // BLE reconnects may preserve active_, but a fresh boot/reset must not
  // decrypt against a zero or unrelated IV.
  if (!this->active_.valid && !this->pending_.valid) {
    ESP_LOGW(TAG, "Dropping encrypted frame: no IV negotiated");
    return Action::NONE;
  }

  // The protocol echoes IV[0..1] as seq_a/seq_b. Prefer pending_ when the
  // keypad has switched; otherwise retain active_ just long enough to finish
  // an in-flight poll. rotate_pending_iv_() guarantees their seq pairs differ.
  const bool uses_pending = this->seq_matches_(this->pending_, this->header_);
  const bool uses_active = this->seq_matches_(this->active_, this->header_);
  if (!uses_pending && !uses_active) {
    ESP_LOGW(TAG, "Dropping frame: seq_a/seq_b mismatch (cross-session replay?)");
    return Action::NONE;
  }
  CryptoContext &context = uses_pending ? this->pending_ : this->active_;

  const size_t ct_len = frame.size() - HEADER_LEN;
  if (ct_len > MAX_PAYLOAD) {
    ESP_LOGW(TAG, "Dropping frame with invalid payload length: %zu", ct_len);
    return Action::NONE;
  }

  const uint8_t *ciphertext = reinterpret_cast<const uint8_t *>(frame.data() + HEADER_LEN);

  // Intra-session replay protection for state-changing actions: under a
  // fixed session IV, identical plaintexts produce identical ciphertexts.
  // We only flag duplicates that decode to a side-effecting command — state
  // polls are idempotent and a legitimate keypad emits them repeatedly.
  const bool ciphertext_seen =
      this->is_replayed_ciphertext_(context, ciphertext, ct_len);

  uint8_t plaintext[MAX_PAYLOAD];
  if (!this->xcrypt_(context.iv, ciphertext, ct_len, plaintext)) {
    return Action::NONE;  // error already logged
  }

  ESP_LOGD(TAG, "RX %s", format_hex_pretty(plaintext, ct_len).c_str());

  this->command_ = decode_lock_command(plaintext, ct_len);

  // Once a new IV has been advertised, the superseded generation is accepted
  // only for an idempotent state poll that was already in flight. In
  // particular, never let a delayed/captured lock or unlock cross the IV
  // boundary even if its ciphertext was not present in the small replay ring.
  if (!uses_pending && this->pending_.valid &&
      this->command_.type != CommandType::STATE_POLL) {
    ESP_LOGW(TAG, "Dropping non-poll frame under superseded IV");
    this->command_ = DecodedCommand{};
    return Action::NONE;
  }

  if (this->command_.type == CommandType::UNKNOWN) {
    ESP_LOGI(TAG, "Unhandled command: %s", format_hex_pretty(plaintext, ct_len).c_str());
  }

  // DOORBELL is deliberately left out of the replay filter: under a fixed
  // session IV a second legitimate press in the same connection produces the
  // exact same ciphertext, and dropping it would swallow real rings. Worst
  // case for a replayed doorbell frame is a spurious chime; a replayed
  // lock/unlock changes security state, so only those are filtered.
  if (this->command_.type == CommandType::LOCK || this->command_.type == CommandType::UNLOCK) {
    if (ciphertext_seen) {
      ESP_LOGW(TAG, "Dropping action: ciphertext replay within session");
      return Action::NONE;
    }
    this->record_ciphertext_(context, ciphertext, ct_len);
  }

  std::memcpy(this->plaintext_.data(), plaintext, ct_len);
  this->plaintext_size_ = ct_len;
  this->response_iv_ = context.iv;
  this->response_iv_valid_ = true;

  if (uses_pending) {
    this->active_ = this->pending_;
    this->pending_ = CryptoContext{};
    ESP_LOGV(TAG, "Pending IV promoted");
  } else if (this->pending_.valid) {
    ESP_LOGD(TAG, "Accepted delayed state poll under previous IV");
  }

  return Action::COMMAND;
}

bool LockSession::is_iv_request_(const std::string &frame) const {
  return frame.size() >= SESSION_IV_REQ_MIN &&
         static_cast<uint8_t>(frame[0]) == PROTOCOL_MAGIC &&
         static_cast<uint8_t>(frame[1]) == 0x00 &&
         static_cast<uint8_t>(frame[5]) == 0x21 &&
         static_cast<uint8_t>(frame[6]) == 0x03;
}

size_t LockSession::encrypt_response(const FrameHeader &header, const uint8_t *plaintext,
                                     size_t length, uint8_t out[MAX_PACKET]) {
  if (length > MAX_PAYLOAD) {
    ESP_LOGE(TAG, "Response payload too large (%zu > %zu)", length, MAX_PAYLOAD);
    return 0;
  }
  out[0] = 0x01;
  out[1] = header.key_id;
  out[2] = header.seq_a;
  out[3] = header.seq_b;
  if (!this->response_iv_valid_ ||
      header.seq_a != this->response_iv_[0] ||
      header.seq_b != this->response_iv_[1]) {
    ESP_LOGE(TAG, "Cannot encrypt response: no matching RX IV context");
    return 0;
  }
  if (!this->xcrypt_(this->response_iv_, plaintext, length, out + HEADER_LEN)) {
    return 0;
  }
  return HEADER_LEN + length;
}

bool LockSession::xcrypt_(const std::array<uint8_t, AES_IV_SIZE> &iv,
                          const uint8_t *input, size_t length, uint8_t *output) {
  return aes_ctr_xcrypt(this->aes_key_, iv.data(), input, output, length);
}

void LockSession::rotate_pending_iv_() {
  this->pending_ = CryptoContext{};
  auto fill_iv = [this]() {
    for (size_t i = 0; i < AES_IV_SIZE; i += 4) {
      const uint32_t value = esp_random();
      std::memcpy(this->pending_.iv.data() + i, &value, 4);
    }
  };
  fill_iv();

  // seq_a/seq_b are the only generation selector carried on the wire. Avoid
  // an ambiguous active/pending pair. Bound the retries so a broken RNG
  // cannot stall the BLE task; the final bit flip still makes the pair unique.
  size_t retries = 0;
  while (this->active_.valid && this->pending_.iv[0] == this->active_.iv[0] &&
         this->pending_.iv[1] == this->active_.iv[1] && retries++ < 4) {
    fill_iv();
  }
  if (this->active_.valid && this->pending_.iv[0] == this->active_.iv[0] &&
      this->pending_.iv[1] == this->active_.iv[1]) {
    this->pending_.iv[1] ^= 0x01;
  }
  this->pending_.valid = true;
  std::memcpy(this->iv_response_.data() + IV_RESPONSE_HEADER,
              this->pending_.iv.data(), AES_IV_SIZE);
  ESP_LOGV(TAG, "Pending IV: %s",
           format_hex_pretty(this->pending_.iv.data(), AES_IV_SIZE).c_str());
}

bool LockSession::is_replayed_ciphertext_(const CryptoContext &context,
                                          const uint8_t *ciphertext,
                                          size_t length) const {
  if (length == 0 || length > MAX_PAYLOAD) {
    return false;
  }
  for (const auto &entry : context.replay_history) {
    if (entry.length == length && std::memcmp(entry.data.data(), ciphertext, length) == 0) {
      return true;
    }
  }
  return false;
}

void LockSession::record_ciphertext_(CryptoContext &context,
                                     const uint8_t *ciphertext, size_t length) {
  if (length == 0 || length > MAX_PAYLOAD) {
    return;
  }
  ReplayEntry &slot = context.replay_history[context.replay_head];
  std::memcpy(slot.data.data(), ciphertext, length);
  slot.length = length;
  context.replay_head = (context.replay_head + 1) % REPLAY_HISTORY_SIZE;
}

bool LockSession::seq_matches_(const CryptoContext &context,
                               const FrameHeader &header) const {
  return context.valid && header.seq_a == context.iv[0] &&
         header.seq_b == context.iv[1];
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
