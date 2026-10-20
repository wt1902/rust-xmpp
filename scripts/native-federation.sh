#!/usr/bin/env bash
# Native transport interop: built Prosody cafd74b9c5ea + Lua 5.4/TLS dependencies.
set -euo pipefail
: "${PROSODY_SOURCE:?Set PROSODY_SOURCE to the built Prosody cafd74b9c5ea source tree}"
export PROSODY_SOURCE
export PROSODY_LUA="${PROSODY_LUA:-lua5.4}"
# Optional Debian multiarch dependency bundle, e.g. /tmp/xmpp-native/usr.
if [[ -n "${PROSODY_NATIVE_PREFIX:-}" ]]; then
    export LD_LIBRARY_PATH="$PROSODY_NATIVE_PREFIX/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export LUA_PATH="$PROSODY_NATIVE_PREFIX/share/lua/5.4/?.lua;$PROSODY_NATIVE_PREFIX/share/lua/5.4/?/init.lua;${LUA_PATH:-;}"
    export LUA_CPATH="$PROSODY_NATIVE_PREFIX/lib/x86_64-linux-gnu/lua/5.4/?.so;${LUA_CPATH:-;}"
fi
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec "${CARGO:-cargo}" test --locked --test federation_tls native_prosody_tls_external_bidirectional -- --ignored --nocapture
