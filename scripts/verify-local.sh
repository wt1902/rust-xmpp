#!/usr/bin/env bash
# All runtime checks below create isolated data and use loopback listeners.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$project_dir"
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
python3 scripts/integration_xmpp.py
python3 tests/sasl_network.py --spawn --hash sha1
python3 tests/sasl_network.py --spawn --hash sha256
python3 tests/android_sasl_network.py target/release/rust-xmpp
python3 tests/logging_network.py target/release/rust-xmpp
python3 tests/sasl_retry_network.py target/release/rust-xmpp
python3 tests/sasl_web_network.py --binary target/release/rust-xmpp
python3 tests/wss_interop.py --binary target/release/rust-xmpp
python3 tests/http_proxy_paths_network.py --binary target/release/rust-xmpp
python3 tests/http_altconnect_network.py --binary target/release/rust-xmpp
python3 tests/sasl2_bind.py target/release/rust-xmpp
python3 tests/sasl2_cached_inline.py target/release/rust-xmpp
python3 tests/gajim_discovery_network.py target/release/rust-xmpp
python3 tests/sasl2_resume.py target/release/rust-xmpp
python3 tests/push_discovery.py target/release/rust-xmpp
python3 tests/pep_client_network.py target/release/rust-xmpp
python3 tests/pep_order_network.py target/release/rust-xmpp
python3 tests/pep_notifications_network.py target/release/rust-xmpp
python3 tests/preauth_network.py target/release/rust-xmpp
python3 tests/muc_restart_network.py target/release/rust-xmpp
python3 tests/resource_rebind.py target/release/rust-xmpp
python3 scripts/integration_http.py
python3 scripts/integration_http.py --custom-upload-path
python3 tests/upload_multi_network.py --binary target/release/rust-xmpp
python3 tests/upload_s3_network.py target/release/rust-xmpp
python3 tests/upload_migration_network.py target/release/rust-xmpp
# Opt-in real object-store run: default payload is 10 GiB, not a fixture.
if [[ -n ${MINIO_BINARY:-} ]]; then
  python3 tests/upload_minio_network.py --binary target/release/rust-xmpp --minio "$MINIO_BINARY"
fi
if [[ ${XMPP_LOAD_CHECK:-0} == 1 ]]; then
  python3 scripts/load_smoke.py --clients 500 --accounts 100 --rounds 10 --message-rounds 10 --archive
fi
if [[ -n ${PROSODY_REFERENCE_SOURCE:-} ]]; then
  RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.99.1} scripts/prosody_compat/verify.sh \
    "$PROSODY_REFERENCE_SOURCE" "${PROSODY_REFERENCE_LUA:-lua5.4}"
  PROSODY_SOURCE="$PROSODY_REFERENCE_SOURCE" PROSODY_LUA="${PROSODY_REFERENCE_LUA:-lua5.4}" scripts/native-federation.sh
fi
