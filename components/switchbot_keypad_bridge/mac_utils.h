#pragma once

// MAC-address string/byte conversions shared by the cloud client, the
// pairer, the setup UI and the bridge. Pure string handling — no NimBLE
// or ESP-IDF dependency.

#include <cstdint>
#include <string>

namespace esphome {
namespace switchbot_keypad_bridge {

// Convert "B0E9FE612E75" → "B0:E9:FE:61:2E:75". Idempotent on already-
// pretty input. Defensive on malformed input (returned as-is).
std::string pretty_mac(const std::string &raw);

// Any separators / case → "B0E9FE612E75".
std::string compact_mac(const std::string &any);

// Upper-cased copy of a MAC string, for case-insensitive comparisons
// ("b0:e9:fe:…" → "B0:E9:FE:…").
std::string upper_mac(std::string mac);

// Parse "B0:E9:FE:11:22:33" (any case) into 6 big-endian bytes.
bool parse_mac_pretty(const std::string &mac, uint8_t out[6]);

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
