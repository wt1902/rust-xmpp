#!/usr/bin/env bash
# Unmodified upstream source; never apply the sandbox adapter in hosted CI.
set -euo pipefail
output=${1:?Usage: prepare-minio.sh ABSOLUTE_OUTPUT_BINARY}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --fail --location --retry 3 --connect-timeout 20 --max-time 300 \
  https://github.com/minio/minio/archive/refs/tags/RELEASE.2025-04-22T22-12-26Z.tar.gz \
  --output "$work/minio.tar.gz"
printf '%s  %s\n' 1a63209927b9d1fb239b2a776b7b01d1902eff19379a108f4bc7005edcc0968c "$work/minio.tar.gz" | sha256sum --check --strict
tar --no-same-owner -xzf "$work/minio.tar.gz" -C "$work"
cd "$work/minio-RELEASE.2025-04-22T22-12-26Z"
mkdir -p "$(dirname "$output")"
GOTOOLCHAIN=local go build -mod=readonly -p 2 -o "$output" .
"$output" --version
