#!/usr/bin/env bash
set -euo pipefail
KEY="$1"
IN="$2"
OUT="$3"
RAW="${OUT%.ts}_raw.ts"
STATS="results/$(basename "${OUT%.ts}")_stats.json"

./target/release/pqav-sign --key "$KEY" --in "$IN" --out "$RAW" --stats "$STATS"

tsp -I file "$RAW" \
    -P pmt --add-pid 0x1FF0/0x06 --add-pid-registration 0x1FF0/0x50514156 \
    -O file "$OUT"

rm -f "$RAW"
echo "firmado: $OUT  estadísticas: $STATS"
