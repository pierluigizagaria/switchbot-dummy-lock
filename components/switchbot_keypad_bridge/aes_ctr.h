#pragma once

// AES-128-CTR on top of PSA Crypto — the one cipher the SwitchBot keypad
// protocol uses. CTR is symmetric, so a single primitive covers both
// encryption (responses) and decryption (incoming commands).

#include <psa/crypto.h>

#include <cstddef>
#include <cstdint>

namespace esphome {
namespace switchbot_keypad_bridge {

// Run AES-128-CTR over `input` with an already-imported PSA key. `output`
// must hold `length` bytes (in-place operation is not supported by PSA).
// Logs and returns false on failure.
bool aes_ctr_xcrypt(psa_key_id_t key, const uint8_t iv[16],
                    const uint8_t *input, uint8_t *output, size_t length);

// One-shot variant for a raw 16-byte key, imported and destroyed around the
// call — the pairing path, where the keypad's cloud key only lives for the
// duration of a single job.
bool aes_ctr_xcrypt_raw_key(const uint8_t key[16], const uint8_t iv[16],
                            const uint8_t *input, uint8_t *output, size_t length);

// AES-128-GCM helpers for newer SwitchBot locks. SwitchBot only carries the
// first two bytes of the authentication tag in the command header, but the full
// tag is still computed here so the caller can copy that prefix.
bool aes_gcm_encrypt_raw_key(const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t *input, uint8_t *output,
                             size_t length, uint8_t tag[16]);

// Decrypt without authenticating a received short-tag SwitchBot packet. This
// mirrors the official clients: firmware handles acceptance and only exposes a
// partial tag to BLE clients, so there is no complete tag to verify locally.
bool aes_gcm_decrypt_raw_key(const uint8_t key[16], const uint8_t iv[12],
                             const uint8_t *input, uint8_t *output,
                             size_t length);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
