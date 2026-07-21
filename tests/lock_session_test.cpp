#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

#include "components/switchbot_keypad_bridge/aes_ctr.h"
#include "components/switchbot_keypad_bridge/lock_session.h"

namespace {

using esphome::switchbot_keypad_bridge::CommandType;
using esphome::switchbot_keypad_bridge::LockSession;

constexpr psa_key_id_t TEST_KEY = 0x42;
constexpr uint8_t SLOT = 0xC6;
constexpr std::array<uint8_t, 4> STATE_POLL = {0x0F, 0x4F, 0x81, 0x00};
constexpr std::array<uint8_t, 8> LOCK = {0x0F, 0x4E, 0x01, 0x03,
                                         0x00, 0x00, 0x00, 0x00};
constexpr std::array<uint8_t, 2> DOORBELL = {0x01, 0x03};

std::deque<uint32_t> random_values;

std::array<uint8_t, 16> make_iv(uint8_t first) {
  std::array<uint8_t, 16> iv{};
  for (size_t i = 0; i < iv.size(); ++i) {
    iv[i] = static_cast<uint8_t>(first + i);
  }
  return iv;
}

void queue_iv(const std::array<uint8_t, 16> &iv) {
  for (size_t i = 0; i < iv.size(); i += sizeof(uint32_t)) {
    uint32_t word;
    std::memcpy(&word, iv.data() + i, sizeof(word));
    random_values.push_back(word);
  }
}

std::string iv_request() {
  const uint8_t bytes[8] = {0x57, 0x00, 0x00, 0x00, 0x0F, 0x21, 0x03, SLOT};
  return {reinterpret_cast<const char *>(bytes), sizeof(bytes)};
}

std::array<uint8_t, 16> response_iv(const LockSession &session) {
  std::array<uint8_t, 16> iv{};
  std::memcpy(iv.data(), session.iv_response() + 4, iv.size());
  return iv;
}

template<size_t N>
std::string encrypted_frame(const std::array<uint8_t, 16> &iv,
                            const std::array<uint8_t, N> &plaintext) {
  std::vector<uint8_t> wire(LockSession::HEADER_LEN + plaintext.size());
  wire[0] = 0x57;
  wire[1] = SLOT;
  wire[2] = iv[0];
  wire[3] = iv[1];
  const bool ok = esphome::switchbot_keypad_bridge::aes_ctr_xcrypt(
      TEST_KEY, iv.data(), plaintext.data(), wire.data() + LockSession::HEADER_LEN,
      plaintext.size());
  assert(ok);
  return {reinterpret_cast<const char *>(wire.data()), wire.size()};
}

void assert_response_uses_iv(LockSession &session,
                             const std::array<uint8_t, 16> &iv) {
  const uint8_t plaintext[3] = {0x81, 0x08, 0x08};
  uint8_t packet[LockSession::MAX_PACKET]{};
  const size_t size = session.encrypt_response(session.header(), plaintext,
                                                sizeof(plaintext), packet);
  assert(size == LockSession::HEADER_LEN + sizeof(plaintext));

  uint8_t decoded[sizeof(plaintext)]{};
  const bool ok = esphome::switchbot_keypad_bridge::aes_ctr_xcrypt(
      TEST_KEY, iv.data(), packet + LockSession::HEADER_LEN, decoded,
      sizeof(decoded));
  assert(ok);
  assert(std::memcmp(decoded, plaintext, sizeof(plaintext)) == 0);
}

void test_iv_handoff_and_replay() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto active_iv = make_iv(0x10);
  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == active_iv);

  const std::string active_poll = encrypted_frame(active_iv, STATE_POLL);
  assert(session.process_frame(active_poll) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::STATE_POLL);

  // A BLE reconnect clears only transient transport state. The logical crypto
  // generation and its replay history stay alive.
  session.reset_transport();
  assert(session.process_frame(active_poll) == LockSession::Action::COMMAND);

  const auto abandoned_pending_iv = make_iv(0x30);
  queue_iv(abandoned_pending_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == abandoned_pending_iv);

  // A second IV request replaces only pending_, never the still-active IV.
  const auto pending_iv = make_iv(0x50);
  queue_iv(pending_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(response_iv(session) == pending_iv);

  // The reported Vision Pro race: finish an old state poll after advertising
  // the next IV, and encrypt the reply with the old generation.
  assert(session.process_frame(active_poll) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::STATE_POLL);
  assert_response_uses_iv(session, active_iv);

  // Only state polls may cross the hand-off boundary. Side effects remain
  // rejected even if their ciphertext has not appeared in the replay ring.
  assert(session.process_frame(encrypted_frame(active_iv, LOCK)) ==
         LockSession::Action::NONE);

  // A frame for an abandoned pending generation is neither active nor pending.
  assert(session.process_frame(encrypted_frame(abandoned_pending_iv, STATE_POLL)) ==
         LockSession::Action::NONE);

  // The first frame under pending_ promotes it. Its replay entry moves with
  // the context, so repeating the same state-changing ciphertext is rejected.
  const std::string pending_lock = encrypted_frame(pending_iv, LOCK);
  assert(session.process_frame(pending_lock) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::LOCK);
  assert(session.process_frame(pending_lock) == LockSession::Action::NONE);

  // The previous generation is gone once pending_ has been proven active.
  assert(session.process_frame(active_poll) == LockSession::Action::NONE);

  // Doorbell remains intentionally outside the side-effect replay filter.
  const std::string doorbell = encrypted_frame(pending_iv, DOORBELL);
  assert(session.process_frame(doorbell) == LockSession::Action::COMMAND);
  assert(session.command().type == CommandType::DOORBELL);
  assert(session.process_frame(doorbell) == LockSession::Action::COMMAND);

  // A full crypto reset (unpair/re-key) rejects the formerly active IV.
  session.reset();
  assert(session.process_frame(encrypted_frame(pending_iv, STATE_POLL)) ==
         LockSession::Action::NONE);
}

void test_seq_collision_is_resolved() {
  LockSession session;
  session.set_aes_key(TEST_KEY);

  const auto active_iv = make_iv(0x70);
  queue_iv(active_iv);
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  assert(session.process_frame(encrypted_frame(active_iv, STATE_POLL)) ==
         LockSession::Action::COMMAND);

  // Simulate a broken RNG returning the same IV for every bounded retry.
  for (size_t i = 0; i < 5; ++i) {
    queue_iv(active_iv);
  }
  assert(session.process_frame(iv_request()) == LockSession::Action::SEND_IV);
  const auto pending_iv = response_iv(session);
  assert(pending_iv[0] != active_iv[0] || pending_iv[1] != active_iv[1]);
}

}  // namespace

uint32_t esp_random() {
  assert(!random_values.empty());
  const uint32_t value = random_values.front();
  random_values.pop_front();
  return value;
}

namespace esphome {
namespace switchbot_keypad_bridge {

bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    output[i] = input[i] ^ iv[i % 16] ^ static_cast<uint8_t>(key);
  }
  return true;
}

}  // namespace switchbot_keypad_bridge
}  // namespace esphome

int main() {
  test_iv_handoff_and_replay();
  test_seq_collision_is_resolved();
  assert(random_values.empty());
  return 0;
}
