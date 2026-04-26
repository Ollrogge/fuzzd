#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <cores>" >&2
    exit 1
fi

CORES="$1"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZD="${FUZZD:-$DIR/../../target/debug/fuzzd}"

exec "$FUZZD" fuzz \
    --binary "$DIR/target_normal" \
    --cmplog-binary "$DIR/target_cmplog" \
    --sanitizer-binary "$DIR/target_asan_ubsan" \
    --laf-binary "$DIR/target_laf" \
    --cfisan-binary "$DIR/target_cfisan" \
    --output-root "$DIR/output" \
    --jobs "$CORES" \
    -m none
