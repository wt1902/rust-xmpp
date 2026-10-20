#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo 'Usage: verify.sh /absolute/path/to/built/prosody-cafd74b9c5ea [lua5.4]' >&2
  exit 2
fi
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
reference_dir=$(cd -- "$1" && pwd)
if ! grep -q '^node: cafd74b9c5ea' "$reference_dir/.hg_archival.txt"; then
  echo 'Expected the supplied Prosody cafd74b9c5ea source revision.' >&2
  exit 2
fi
for required in util/encodings.so util/hashes.so util/pposix.so plugins/mod_storage_internal.lua; do
  test -f "$reference_dir/$required" || { echo "Missing $required; build Prosody first." >&2; exit 2; }
done
export PROSODY_REFERENCE_SOURCE="$reference_dir"
export PROSODY_REFERENCE_LUA="${2:-lua5.4}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-1.99.1}"
cd -- "$project_dir"
"${CARGO:-cargo}" test --locked --test reference_prosody --test pubsub_native --test pep_item_order --test muc_native --test muc_state_native --test csi_native --test push --test preauth_native -- --ignored --nocapture
