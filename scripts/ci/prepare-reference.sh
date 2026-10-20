#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
reference_parent=${1:?Usage: prepare-reference.sh OUTPUT_DIRECTORY}
mkdir -p "$reference_parent"
reference_parent=$(cd -- "$reference_parent" && pwd)
cd "$project_dir/scripts/ci/vendor"
printf '%s\n' '1e558d3d2211ea0228596aced2b71306503190c454ec4cb44f172045b3513c34  prosody-cafd74b9c5ea.tar.gz' | sha256sum --check --strict
tar --no-same-owner -xzf prosody-cafd74b9c5ea.tar.gz -C "$reference_parent"
cd "$reference_parent/prosody-cafd74b9c5ea"
./configure --ostype=debian --lua-version=5.4 --lua-suffix=5.4
make -j2
