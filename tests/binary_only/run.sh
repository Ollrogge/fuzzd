#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <cores>" >&2
    exit 1
fi

CORES="$1"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIGGY="${ZIGGY:-$DIR/../../target/debug/cargo-ziggy}"

exec "$ZIGGY" ziggy fuzz \
    --binary "$DIR/target_normal" \
    --cmplog-binary "$DIR/target_cmplog" \
    --asan-binary "$DIR/target_asan" \
    --ubsan-binary "$DIR/target_ubsan" \
    --laf-binary "$DIR/target_laf" \
    --cfisan-binary "$DIR/target_cfisan" \
    --ziggy-output "$DIR/output" \
    --jobs "$CORES"
