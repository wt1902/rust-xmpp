#!/usr/bin/env bash
set -euo pipefail
: "${PROSODY_REFERENCE_SOURCE:?Build the bundled reference first}"
: "${MINIO_BINARY:?Build genuine MinIO first}"
export XMPP_LOAD_CHECK=1
mkdir -p ci-results
bash scripts/verify-local.sh
# These two tests are deliberately ignored by the ordinary test command.
cargo test --locked --test admin_socket --test archive_mam -- --ignored --nocapture
python3 tests/upload_large_network.py --binary target/release/rust-xmpp --report ci-results/upload-local-10gib.json
