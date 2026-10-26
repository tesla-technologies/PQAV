#!/usr/bin/env bash
# Uso: scripts/make_input.sh [segundos] [salida]
set -euo pipefail
DUR="${1:-60}"
OUT="${2:-testdata/entrada.ts}"
mkdir -p "$(dirname "$OUT")"
ffmpeg -hide_banner -y \
-f lavfi -i "testsrc2=size=1920x1080:rate=25" \
-f lavfi -i "sine=frequency=1000:sample_rate=48000" \
-t "$DUR" -map 0:v -map 1:a \
-c:v libx264 -profile:v high -preset veryfast -pix_fmt yuv420p \
-g 50 -bf 2 -b:v 4M -maxrate 4M -bufsize 4M \
-c:a aac -b:a 128k -ar 48000 -ac 2 \
-metadata:s:a:0 language=spa \
-f mpegts -muxrate 8000000 \
"$OUT"
