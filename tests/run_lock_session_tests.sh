#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="${TMPDIR:-/tmp}/switchbot-lock-session-test"
CXX=${CXX:-c++}

"$CXX" -std=c++17 -Wall -Wextra -Werror \
  -I"$ROOT/tests/stubs" -I"$ROOT" \
  "$ROOT/components/switchbot_keypad_bridge/lock_session.cpp" \
  "$ROOT/components/switchbot_keypad_bridge/lock_protocol.cpp" \
  "$ROOT/tests/lock_session_test.cpp" \
  -o "$BIN"

"$BIN"
